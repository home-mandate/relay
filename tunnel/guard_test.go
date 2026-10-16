// SPDX-License-Identifier: AGPL-3.0-or-later

package tunnel

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClock struct {
	now    time.Time
	timers []*fakeTimer
}

type fakeTimer struct {
	at      time.Time
	f       func()
	stopped bool
}

func (c *fakeClock) afterFunc(d time.Duration, f func()) stopper {
	tm := &fakeTimer{at: c.now.Add(d), f: f}
	c.timers = append(c.timers, tm)
	return func() bool { was := !tm.stopped; tm.stopped = true; return was }
}

func (c *fakeClock) advance(d time.Duration) {
	c.now = c.now.Add(d)
	for _, tm := range c.timers {
		if !tm.stopped && !tm.at.After(c.now) {
			tm.stopped = true
			tm.f()
		}
	}
}

func newTestGuard() (*Guard, *fakeClock) {
	c := &fakeClock{now: t0}
	g := NewGuard()
	g.now, g.afterFunc = func() time.Time { return c.now }, c.afterFunc
	return g, c
}

func certWith(serial int64, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: t0.Add(-time.Hour), NotAfter: notAfter}
}

func TestTrackClosesAtNotAfterPlusGrace(t *testing.T) {
	tests := []struct {
		name   string
		grace  time.Duration
		before time.Duration
		closed bool
	}{
		{"control closes at NotAfter", 0, time.Hour - time.Second, false},
		{"data closes after the grace", DataCertGrace, time.Hour + DataCertGrace - time.Second, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, clock := newTestGuard()
			var closed atomic.Int32
			if _, err := g.Track(certWith(1, t0.Add(time.Hour)), tt.grace, func() { closed.Add(1) }); err != nil {
				t.Fatal(err)
			}

			clock.advance(tt.before)
			early := closed.Load()
			clock.advance(2 * time.Second)

			if early != 0 || closed.Load() != 1 {
				t.Fatalf("closed early=%d later=%d", early, closed.Load())
			}
		})
	}
}

func TestTrackReleaseCancelsTheTimer(t *testing.T) {
	g, clock := newTestGuard()
	var closed atomic.Int32
	release, _ := g.Track(certWith(1, t0.Add(time.Minute)), 0, func() { closed.Add(1) })

	release()
	release() // idempotent
	clock.advance(time.Hour)

	if closed.Load() != 0 || g.Tracked(big.NewInt(1)) != 0 {
		t.Fatalf("closed %d, tracked %d", closed.Load(), g.Tracked(big.NewInt(1)))
	}
}

func TestTrackRefusesExpiredAndRevokedCertificates(t *testing.T) {
	g, _ := newTestGuard()
	if _, err := g.Track(certWith(1, t0.Add(-time.Second)), 0, func() {}); !errors.Is(err, ErrCertExpired) {
		t.Fatalf("expired: %v", err)
	}
	if _, err := g.Track(certWith(2, t0.Add(-time.Second)), DataCertGrace, func() {}); err != nil {
		t.Fatalf("within the data grace: %v", err)
	}
	g.Revoke(big.NewInt(3))
	if _, err := g.Track(certWith(3, t0.Add(time.Hour)), 0, func() {}); !errors.Is(err, ErrCertRevoked) {
		t.Fatalf("revoked: %v", err)
	}
	if _, err := g.Track(nil, 0, func() {}); err == nil {
		t.Fatal("nil certificate accepted")
	}
	if _, err := g.Track(&x509.Certificate{}, 0, func() {}); err == nil {
		t.Fatal("certificate without serial accepted")
	}
}

func TestRevokeClosesOpenConnectionsOfThatSerialOnly(t *testing.T) {
	g, _ := newTestGuard()
	var a, b, other atomic.Int32
	g.Track(certWith(7, t0.Add(time.Hour)), 0, func() { a.Add(1) })
	g.Track(certWith(7, t0.Add(time.Hour)), DataCertGrace, func() { b.Add(1) })
	g.Track(certWith(8, t0.Add(time.Hour)), 0, func() { other.Add(1) })

	n := g.Revoke(big.NewInt(7))

	if n != 2 || a.Load() != 1 || b.Load() != 1 || other.Load() != 0 {
		t.Fatalf("closed %d: a=%d b=%d other=%d", n, a.Load(), b.Load(), other.Load())
	}
	if !g.IsRevoked(big.NewInt(7)) || g.IsRevoked(big.NewInt(8)) {
		t.Fatal("denylist wrong")
	}
	if g.Revoke(big.NewInt(7)) != 0 {
		t.Fatal("second revoke closed something")
	}
}

func TestCloseFuncRunsAtMostOnce(t *testing.T) {
	g, clock := newTestGuard()
	var closed atomic.Int32
	g.Track(certWith(7, t0.Add(time.Minute)), 0, func() { closed.Add(1) })

	g.Revoke(big.NewInt(7))
	clock.advance(time.Hour)

	if closed.Load() != 1 {
		t.Fatalf("closed %d times", closed.Load())
	}
}

func TestVerifyConnectionChecksDenylistAndExpiry(t *testing.T) {
	g, _ := newTestGuard()
	g.Revoke(big.NewInt(5))
	state := func(c *x509.Certificate) tls.ConnectionState {
		return tls.ConnectionState{PeerCertificates: []*x509.Certificate{c}}
	}
	tests := []struct {
		name string
		cs   tls.ConnectionState
		want error
	}{
		{"fine", state(certWith(1, t0.Add(time.Hour))), nil},
		{"revoked serial", state(certWith(5, t0.Add(time.Hour))), ErrCertRevoked},
		{"expired", state(certWith(1, t0.Add(-time.Second))), ErrCertExpired},
		{"no certificate", tls.ConnectionState{}, ErrIdentity},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := g.VerifyConnection(tt.cs)
			if tt.want == nil && err != nil || tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestZeroValueGuardWorks(t *testing.T) {
	var g Guard
	if _, err := g.Track(certWith(1, time.Now().Add(time.Hour)), 0, func() {}); err != nil {
		t.Fatalf("zero value should work with real clocks: %v", err)
	}
}
