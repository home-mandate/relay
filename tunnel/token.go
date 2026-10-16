// SPDX-License-Identifier: AGPL-3.0-or-later

package tunnel

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"
)

// Stream token parameters (specification section 6).
const (
	// TokenSize is the size of a stream token: 256 random bits.
	TokenSize = 32
	// TokenValidity is how long a token can be redeemed after it was issued.
	TokenValidity = 10 * time.Second
	// TokenValidityMillis is TokenValidity as carried in a StreamOpen signal.
	TokenValidityMillis uint16 = 10000
	// MaxPendingTokens is the number of issued, not yet redeemed tokens per installation.
	MaxPendingTokens = 16
	// MaxTotalTokens bounds the store as a whole.
	MaxTotalTokens = 1 << 16
)

var (
	// ErrTokenUnknown covers a token that was never issued, was already redeemed or cancelled.
	ErrTokenUnknown = errors.New("tunnel: unknown stream token")
	// ErrTokenExpired is returned when a token is redeemed after its validity.
	ErrTokenExpired = errors.New("tunnel: stream token expired")
	// ErrTokenWrongInstallation is returned when another installation presents the token.
	ErrTokenWrongInstallation = errors.New("tunnel: stream token belongs to another installation")
	// ErrTooManyPending is returned when an installation has MaxPendingTokens open tokens.
	ErrTooManyPending = errors.New("tunnel: too many pending stream tokens")
	// ErrStoreFull is returned when the store holds MaxTotalTokens unexpired tokens.
	ErrStoreFull = errors.New("tunnel: stream token store is full")
	// ErrEmptyInstallation is returned when no installation is given.
	ErrEmptyInstallation = errors.New("tunnel: empty installation")
)

// Token is a one-time stream token: 256 random bits. It is a bearer secret, so it never prints.
type Token [TokenSize]byte

const redacted = "token(redacted)"

// String returns a fixed redacted value; formatting a Token cannot leak it into a log.
func (Token) String() string { return redacted }

// GoString implements fmt.GoStringer with the same redaction.
func (Token) GoString() string { return redacted }

// MarshalText redacts the token for encoding/json (as a value or map key) and other encoders.
func (Token) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// MarshalJSON redacts the token in JSON.
func (Token) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// LogValue redacts the token for log/slog.
func (Token) LogValue() slog.Value { return slog.StringValue(redacted) }

// NewToken returns a token from crypto/rand.
func NewToken() (Token, error) { return newTokenFrom(rand.Reader) }

func newTokenFrom(r io.Reader) (Token, error) {
	var t Token
	if _, err := io.ReadFull(r, t[:]); err != nil {
		return Token{}, fmt.Errorf("tunnel: reading entropy: %w", err)
	}
	return t, nil
}

type tokenEntry struct {
	installation string
	expires      time.Time
}

type tokenKey = [sha256.Size]byte

// TokenStore is the relay's table of issued tokens. It stores only SHA-256 hashes of tokens, so
// a memory disclosure of the table does not yield redeemable tokens, and map lookups do not
// depend on token bytes. Expiry is handled per installation: each installation has a FIFO of its
// tokens in issue order (the validity is constant, so this is expiry order), which makes
// reclaiming expired tokens cost only what it frees. The zero value is ready to use. It is safe
// for concurrent use; time is passed in by the caller.
type TokenStore struct {
	mu       sync.Mutex
	entries  map[tokenKey]tokenEntry
	queues   map[string][]tokenKey // may hold hashes of tokens already redeemed or cancelled
	pending  map[string]int
	maxTotal int // 0 means MaxTotalTokens
}

// NewTokenStore returns an empty store.
func NewTokenStore() *TokenStore { return &TokenStore{} }

func hashToken(t Token) tokenKey { return sha256.Sum256(t[:]) }

func (s *TokenStore) limit() int {
	if s.maxTotal > 0 {
		return s.maxTotal
	}
	return MaxTotalTokens
}

// Issue creates a token bound to installation (the home ID taken from the gateway's certificate)
// that is valid for TokenValidity from now. It fails closed if entropy is unavailable, with
// ErrTooManyPending if the installation already has MaxPendingTokens open tokens and with
// ErrStoreFull if the store as a whole is full.
func (s *TokenStore) Issue(installation string, now time.Time) (Token, time.Duration, error) {
	if installation == "" {
		return Token{}, 0, ErrEmptyInstallation
	}
	tok, err := NewToken()
	if err != nil {
		return Token{}, 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.entries == nil {
		s.entries, s.queues, s.pending = map[tokenKey]tokenEntry{}, map[string][]tokenKey{}, map[string]int{}
	}
	if s.pending[installation] >= MaxPendingTokens {
		s.sweepInstallationLocked(installation, now)
		if s.pending[installation] >= MaxPendingTokens {
			return Token{}, 0, ErrTooManyPending
		}
	}
	if len(s.entries) >= s.limit() {
		s.sweepLocked(now)
		if len(s.entries) >= s.limit() {
			return Token{}, 0, ErrStoreFull
		}
	}
	key := hashToken(tok)
	s.entries[key] = tokenEntry{installation: installation, expires: now.Add(TokenValidity)}
	s.queues[installation] = append(s.queues[installation], key)
	s.pending[installation]++
	s.compactLocked(installation)
	return tok, TokenValidity, nil
}

// Redeem consumes tok for installation. A token is consumed by the first presentation whatever
// the outcome: a wrong installation or an expired token burns it. The installation is compared
// in constant time. The caller checks its stream and pool limits BEFORE calling Redeem, so that
// a refusal for a full installation does not consume a token the gateway could still use.
func (s *TokenStore) Redeem(tok Token, installation string, now time.Time) error {
	key := hashToken(tok)
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[key]
	if !ok {
		return ErrTokenUnknown
	}
	s.removeLocked(key, e)
	if subtle.ConstantTimeCompare([]byte(e.installation), []byte(installation)) != 1 {
		return ErrTokenWrongInstallation
	}
	if now.After(e.expires) {
		return ErrTokenExpired
	}
	return nil
}

// Cancel removes tok if it was issued for installation, for example when the agent connection
// ended before the gateway dialed. A token of another installation is left alone.
func (s *TokenStore) Cancel(tok Token, installation string) {
	key := hashToken(tok)
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[key]
	if ok && subtle.ConstantTimeCompare([]byte(e.installation), []byte(installation)) == 1 {
		s.removeLocked(key, e)
	}
}

// Pending returns the number of open tokens of installation.
func (s *TokenStore) Pending(installation string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pending[installation]
}

// Sweep removes expired tokens from the front of every installation's queue. The relay calls it
// periodically.
func (s *TokenStore) Sweep(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
}

func (s *TokenStore) sweepLocked(now time.Time) {
	for inst := range s.queues {
		s.sweepInstallationLocked(inst, now)
	}
}

// sweepInstallationLocked pops the front of the queue while it is gone or expired.
func (s *TokenStore) sweepInstallationLocked(installation string, now time.Time) {
	q := s.queues[installation]
	for len(q) > 0 {
		e, live := s.entries[q[0]]
		if live && !now.After(e.expires) {
			break
		}
		if live {
			s.removeLocked(q[0], e)
		}
		q = q[1:]
	}
	if len(q) == 0 {
		delete(s.queues, installation)
		return
	}
	s.queues[installation] = q
}

// compactLocked drops dead hashes from the middle of a queue that grew because of redemptions.
func (s *TokenStore) compactLocked(installation string) {
	q := s.queues[installation]
	if len(q) <= 4*MaxPendingTokens {
		return
	}
	live := make([]tokenKey, 0, MaxPendingTokens)
	for _, k := range q {
		if _, ok := s.entries[k]; ok {
			live = append(live, k)
		}
	}
	s.queues[installation] = live
}

func (s *TokenStore) removeLocked(key tokenKey, e tokenEntry) {
	delete(s.entries, key)
	if s.pending[e.installation]--; s.pending[e.installation] <= 0 {
		delete(s.pending, e.installation)
	}
}
