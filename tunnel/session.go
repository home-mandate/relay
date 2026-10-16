// SPDX-License-Identifier: AGPL-3.0-or-later

package tunnel

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

var (
	// ErrHeartbeatTimeout is returned when no matching pong arrived within one interval.
	ErrHeartbeatTimeout = errors.New("tunnel: heartbeat timeout")
	// ErrUnexpectedPong is returned for a pong that answers no outstanding ping (protocol error).
	ErrUnexpectedPong = errors.New("tunnel: unexpected pong")
	// ErrPingOutstanding is returned when a ping is sent while one still awaits its pong.
	ErrPingOutstanding = errors.New("tunnel: ping already outstanding")
)

// WriteTimeout is the deadline for every write on a tunnel connection, error frames included.
const WriteTimeout = 5 * time.Second

var writeTimeout = WriteTimeout // variable for tests

// ShouldSupersede decides whether a new control connection of an installation replaces an
// existing one: only if the existing one missed its heartbeat or the new certificate was issued
// later (NotBefore). Otherwise the new connection is refused with ErrCodeSessionExists.
func ShouldSupersede(existingMissedHeartbeat bool, existingNotBefore, newNotBefore time.Time) bool {
	return existingMissedHeartbeat || newNotBefore.After(existingNotBefore)
}

// Liveness tracks the heartbeat of one control connection. Only a pong that carries the nonce of
// the outstanding ping, within one interval, counts as a sign of life: other frames do not.
type Liveness struct {
	mu          sync.Mutex
	interval    time.Duration
	outstanding bool
	nonce       uint64
	sentAt      time.Time
}

// NewLiveness returns a tracker for the given heartbeat interval.
func NewLiveness(interval time.Duration) *Liveness { return &Liveness{interval: interval} }

// Ping creates the next ping, with a random nonce, and starts the clock.
func (l *Liveness) Ping(now time.Time) (Ping, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.outstanding {
		return Ping{}, ErrPingOutstanding
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return Ping{}, err
	}
	l.outstanding, l.nonce, l.sentAt = true, binary.BigEndian.Uint64(b[:]), now
	return Ping{Nonce: l.nonce}, nil
}

// OnPong processes a received pong. A pong that matches no outstanding ping is a protocol error
// (ErrUnexpectedPong); a matching one that came too late is ErrHeartbeatTimeout.
func (l *Liveness) OnPong(p Pong, now time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.outstanding || p.Nonce != l.nonce {
		return ErrUnexpectedPong
	}
	l.outstanding = false
	if now.After(l.sentAt.Add(l.interval)) {
		return ErrHeartbeatTimeout
	}
	return nil
}

// Missed reports whether a ping has been outstanding for more than one interval.
func (l *Liveness) Missed(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.outstanding && now.After(l.sentAt.Add(l.interval))
}

// Check returns ErrHeartbeatTimeout if Missed.
func (l *Liveness) Check(now time.Time) error {
	if l.Missed(now) {
		return ErrHeartbeatTimeout
	}
	return nil
}

// WriteMessageTimeout encodes m and writes it with a write deadline of WriteTimeout.
func WriteMessageTimeout(c net.Conn, m Message) error {
	wire, err := EncodeMessage(m)
	if err != nil {
		return err
	}
	if err := c.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}
	_, err = c.Write(wire)
	return err
}

// SendFatalError writes an error message with the write deadline and then closes the
// connection, whether or not the write succeeded. It returns the first error.
func SendFatalError(c net.Conn, code ErrorCode, text string) error {
	err := WriteMessageTimeout(c, ErrorMessage{Code: code, Text: text})
	if cerr := c.Close(); err == nil {
		err = cerr
	}
	return err
}

// Limiter is a sliding-window rate limiter per key with bounded memory. It serves the limits of
// specification section 7: control connects per certificate serial and source, and connections
// per source address before the TLS handshake.
type Limiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	onLimit func(key string)
	maxKeys int
	keys    map[string]*limiterEntry
}

type limiterEntry struct {
	times   []time.Time
	alarmed bool
}

// DefaultLimiterKeys bounds the number of distinct keys a Limiter remembers.
const DefaultLimiterKeys = 1 << 17

// NewLimiter allows limit events per key within window. onLimit, if set, is called once for each
// window in which a key first exceeds the limit; the relay turns it into an alarm.
func NewLimiter(limit int, window time.Duration, onLimit func(key string)) *Limiter {
	return &Limiter{limit: limit, window: window, onLimit: onLimit, maxKeys: DefaultLimiterKeys, keys: map[string]*limiterEntry{}}
}

// Allow records an event for key at now and reports whether it is within the limit.
func (l *Limiter) Allow(key string, now time.Time) bool {
	l.mu.Lock()
	e, ok := l.keys[key]
	if !ok {
		if len(l.keys) >= l.maxKeys {
			l.reclaimLocked(now)
			if len(l.keys) >= l.maxKeys {
				l.mu.Unlock()
				return false
			}
		}
		e = &limiterEntry{}
		l.keys[key] = e
	}
	cutoff := now.Add(-l.window)
	kept := e.times[:0]
	for _, t := range e.times {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	e.times = kept
	if len(e.times) >= l.limit {
		fire := !e.alarmed && l.onLimit != nil
		e.alarmed = true
		l.mu.Unlock()
		if fire {
			l.onLimit(key)
		}
		return false
	}
	e.alarmed = false
	e.times = append(e.times, now)
	l.mu.Unlock()
	return true
}

func (l *Limiter) reclaimLocked(now time.Time) {
	cutoff := now.Add(-l.window)
	for k, e := range l.keys {
		if len(e.times) == 0 || !e.times[len(e.times)-1].After(cutoff) {
			delete(l.keys, k)
		}
	}
}

// RateKey builds the limiter key of a control connect: certificate serial (hex) and source
// address. An IPv6 source is reduced to its /64, as a single subscriber owns that much.
func RateKey(serialHex string, src netip.Addr) string {
	src = src.Unmap()
	if src.Is6() {
		src = netip.PrefixFrom(src, 64).Masked().Addr()
	}
	return serialHex + "|" + src.String()
}
