// SPDX-License-Identifier: AGPL-3.0-or-later

package tunnel

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// DataCertGrace is how long a data connection may outlive its certificate's NotAfter (so a
// stream that is in the middle of a response can finish). Control connections get no grace.
const DataCertGrace = 60 * time.Second

var (
	// ErrCertRevoked is returned for a certificate serial on the denylist.
	ErrCertRevoked = errors.New("tunnel: certificate revoked")
	// ErrCertExpired is returned for a certificate past its NotAfter (plus grace).
	ErrCertExpired = errors.New("tunnel: certificate expired")
)

type stopper func() bool

// Guard enforces certificate lifetime and revocation on open connections: the relay MUST close a
// control connection when its certificate expires and a data connection at most DataCertGrace
// later, MUST refuse a revoked serial at the handshake and MUST drop the open connections of a
// serial that is revoked while they are open. The zero value is ready to use.
type Guard struct {
	mu        sync.Mutex
	revoked   map[string]struct{}
	tracked   map[string]map[uint64]func()
	next      uint64
	now       func() time.Time
	afterFunc func(time.Duration, func()) stopper
}

// NewGuard returns an empty guard using the system clock.
func NewGuard() *Guard { return &Guard{} }

func (g *Guard) clock() time.Time {
	if g.now != nil {
		return g.now()
	}
	return time.Now()
}

func (g *Guard) schedule(d time.Duration, f func()) stopper {
	if g.afterFunc != nil {
		return g.afterFunc(d, f)
	}
	return time.AfterFunc(d, f).Stop
}

func serialKey(n *big.Int) string {
	if n == nil {
		return ""
	}
	return n.Text(16)
}

// Revoke puts the serial on the denylist and closes every tracked connection of it. It returns
// the number of connections it closed. Entries need to be kept only until the certificate's
// NotAfter.
func (g *Guard) Revoke(serial *big.Int) int {
	key := serialKey(serial)
	g.mu.Lock()
	if g.revoked == nil {
		g.revoked = map[string]struct{}{}
	}
	g.revoked[key] = struct{}{}
	closers := g.tracked[key]
	delete(g.tracked, key)
	g.mu.Unlock()
	for _, c := range closers {
		c()
	}
	return len(closers)
}

// IsRevoked reports whether the serial is on the denylist.
func (g *Guard) IsRevoked(serial *big.Int) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	_, ok := g.revoked[serialKey(serial)]
	return ok
}

// Tracked returns the number of open connections tracked for the serial.
func (g *Guard) Tracked(serial *big.Int) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.tracked[serialKey(serial)])
}

// VerifyConnection is meant for tls.Config.VerifyConnection on both control and data listeners:
// it refuses a connection whose certificate is revoked or past NotAfter.
func (g *Guard) VerifyConnection(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return fmt.Errorf("%w: no peer certificate", ErrIdentity)
	}
	cert := cs.PeerCertificates[0]
	if g.IsRevoked(cert.SerialNumber) {
		return ErrCertRevoked
	}
	if g.clock().After(cert.NotAfter) {
		return ErrCertExpired
	}
	return nil
}

// Track registers an open connection of cert. closeFn is called, at most once, when the
// certificate's NotAfter plus grace passes or when its serial is revoked. The returned release
// function must be called when the connection ends; it is idempotent.
func (g *Guard) Track(cert *x509.Certificate, grace time.Duration, closeFn func()) (release func(), err error) {
	if cert == nil || cert.SerialNumber == nil {
		return nil, fmt.Errorf("%w: certificate without serial", ErrIdentity)
	}
	key := serialKey(cert.SerialNumber)
	deadline := cert.NotAfter.Add(grace)
	g.mu.Lock()
	if _, bad := g.revoked[key]; bad {
		g.mu.Unlock()
		return nil, ErrCertRevoked
	}
	wait := deadline.Sub(g.clock())
	if wait < 0 {
		g.mu.Unlock()
		return nil, ErrCertExpired
	}
	var once sync.Once
	closeOnce := func() { once.Do(closeFn) }
	g.next++
	id := g.next
	if g.tracked == nil {
		g.tracked = map[string]map[uint64]func(){}
	}
	if g.tracked[key] == nil {
		g.tracked[key] = map[uint64]func(){}
	}
	g.tracked[key][id] = closeOnce
	g.mu.Unlock()

	stop := g.schedule(wait, func() { g.untrack(key, id); closeOnce() })
	return func() { stop(); g.untrack(key, id) }, nil
}

func (g *Guard) untrack(key string, id uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.tracked[key], id)
	if len(g.tracked[key]) == 0 {
		delete(g.tracked, key)
	}
}
