// SPDX-License-Identifier: AGPL-3.0-or-later

package tunnel

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestShouldSupersede(t *testing.T) {
	old := t0
	tests := []struct {
		name      string
		missed    bool
		newBefore time.Time
		want      bool
	}{
		{"existing missed its heartbeat", true, old, true},
		{"existing missed its heartbeat, new is older", true, old.Add(-time.Hour), true},
		{"healthy existing, newer certificate", false, old.Add(time.Second), true},
		{"healthy existing, same certificate time", false, old, false},
		{"healthy existing, older certificate", false, old.Add(-time.Second), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ShouldSupersede(tt.missed, old, tt.newBefore); got != tt.want {
				t.Fatalf("got %v", got)
			}
		})
	}
}

func TestLivenessAcceptsOnlyTheExpectedPongInTime(t *testing.T) {
	const interval = 15 * time.Second
	t.Run("matching pong in time", func(t *testing.T) {
		l := NewLiveness(interval)
		p, err := l.Ping(t0)
		if err != nil {
			t.Fatal(err)
		}

		if err := l.OnPong(Pong{Nonce: p.Nonce}, t0.Add(interval)); err != nil {
			t.Fatal(err)
		}
		if l.Missed(t0.Add(time.Hour)) {
			t.Fatal("nothing outstanding after the pong")
		}
	})
	t.Run("pong too late", func(t *testing.T) {
		l := NewLiveness(interval)
		p, _ := l.Ping(t0)
		if err := l.OnPong(Pong{Nonce: p.Nonce}, t0.Add(interval+time.Nanosecond)); !errors.Is(err, ErrHeartbeatTimeout) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("missing pong is a timeout", func(t *testing.T) {
		l := NewLiveness(interval)
		l.Ping(t0)
		if l.Missed(t0.Add(interval)) {
			t.Fatal("missed at the deadline itself")
		}
		if !l.Missed(t0.Add(interval + time.Second)) {
			t.Fatal("not missed after the interval")
		}
		if err := l.Check(t0.Add(interval + time.Second)); !errors.Is(err, ErrHeartbeatTimeout) {
			t.Fatalf("err = %v", err)
		}
		if err := l.Check(t0.Add(time.Second)); err != nil {
			t.Fatalf("early check: %v", err)
		}
	})
	t.Run("pong with a wrong nonce is a protocol error", func(t *testing.T) {
		l := NewLiveness(interval)
		p, _ := l.Ping(t0)
		if err := l.OnPong(Pong{Nonce: p.Nonce + 1}, t0); !errors.Is(err, ErrUnexpectedPong) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("pong without a ping is a protocol error", func(t *testing.T) {
		if err := NewLiveness(interval).OnPong(Pong{Nonce: 1}, t0); !errors.Is(err, ErrUnexpectedPong) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a second pong for the same ping is a protocol error", func(t *testing.T) {
		l := NewLiveness(interval)
		p, _ := l.Ping(t0)
		l.OnPong(Pong{Nonce: p.Nonce}, t0)
		if err := l.OnPong(Pong{Nonce: p.Nonce}, t0); !errors.Is(err, ErrUnexpectedPong) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("only one ping outstanding", func(t *testing.T) {
		l := NewLiveness(interval)
		l.Ping(t0)
		if _, err := l.Ping(t0); !errors.Is(err, ErrPingOutstanding) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("nonces differ", func(t *testing.T) {
		l := NewLiveness(interval)
		a, _ := l.Ping(t0)
		l.OnPong(Pong{Nonce: a.Nonce}, t0)
		b, _ := l.Ping(t0)
		if a.Nonce == b.Nonce {
			t.Fatal("nonce repeated")
		}
	})
}

func TestWriteMessageTimeoutWritesAFrame(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() { _ = WriteMessageTimeout(a, Ping{Nonce: 9}) }()

	f, err := ReadFrame(b, MaxPayload)

	if err != nil || f.Type != TypePing {
		t.Fatalf("%+v %v", f, err)
	}
}

func TestWriteMessageTimeoutGivesUpOnAStalledPeer(t *testing.T) {
	a, b := net.Pipe() // nobody reads b
	defer a.Close()
	defer b.Close()
	old := writeTimeout
	writeTimeout = 50 * time.Millisecond
	defer func() { writeTimeout = old }()

	err := WriteMessageTimeout(a, Ping{Nonce: 1})

	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("err = %v", err)
	}
}

func TestWriteMessageTimeoutRejectsInvalidMessages(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if err := WriteMessageTimeout(a, Hello{}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v", err)
	}
}

func TestWriteMessageTimeoutHasADefaultOfFiveSeconds(t *testing.T) {
	if WriteTimeout != 5*time.Second || writeTimeout != WriteTimeout {
		t.Fatalf("%v %v", WriteTimeout, writeTimeout)
	}
}

func TestSendFatalErrorWritesThenCloses(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	done := make(chan error, 1)
	go func() { done <- SendFatalError(a, ErrCodeLimitExceeded, "too many") }()

	f, err := ReadFrame(b, MaxPayload)
	if err != nil {
		t.Fatal(err)
	}
	m, err := DecodeControl(FromRelay, f)
	if err != nil || m.(ErrorMessage).Code != ErrCodeLimitExceeded {
		t.Fatalf("%v %v", m, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(b); err != nil {
		t.Fatalf("connection not closed cleanly: %v", err)
	}
}

func TestSendFatalErrorClosesEvenIfTheWriteStalls(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	old := writeTimeout
	writeTimeout = 50 * time.Millisecond
	defer func() { writeTimeout = old }()

	err := SendFatalError(a, ErrCodeTimeout, "slow")

	if err == nil {
		t.Fatal("expected the write error")
	}
	if _, werr := a.Write([]byte{1}); werr == nil {
		t.Fatal("connection still open")
	}
}

func TestLimiterAllowsUpToTheLimitPerKeyAndWindow(t *testing.T) {
	var alarms []string
	l := NewLimiter(3, time.Minute, func(key string) { alarms = append(alarms, key) })
	for i := 0; i < 3; i++ {
		if !l.Allow("k", t0) {
			t.Fatalf("attempt %d refused", i)
		}
	}

	if l.Allow("k", t0.Add(time.Second)) {
		t.Fatal("fourth attempt allowed")
	}
	if !l.Allow("other", t0) {
		t.Fatal("limit leaked to another key")
	}
	if !l.Allow("k", t0.Add(time.Minute+time.Second)) {
		t.Fatal("window did not reopen")
	}
	if len(alarms) != 1 || alarms[0] != "k" {
		t.Fatalf("alarms = %v", alarms)
	}
}

func TestLimiterBoundsItsMemory(t *testing.T) {
	l := NewLimiter(1, time.Minute, nil)
	l.maxKeys = 2
	l.Allow("a", t0)
	l.Allow("b", t0)

	if l.Allow("c", t0) {
		t.Fatal("new key accepted while full of live keys")
	}
	if !l.Allow("c", t0.Add(2*time.Minute)) {
		t.Fatal("expired keys not reclaimed")
	}
}

func TestRateKeyBindsSerialAndSourceAddress(t *testing.T) {
	a := RateKey("1f", netipAddr("203.0.113.7"))
	b := RateKey("1f", netipAddr("203.0.113.8"))
	c := RateKey("20", netipAddr("203.0.113.7"))
	d := RateKey("1f", netipAddr("2001:db8::1:2:3:4:5"))
	if a == b || a == c || a == d || RateKey("1f", netipAddr("203.0.113.7")) != a {
		t.Fatalf("%q %q %q %q", a, b, c, d)
	}
	if RateKey("1f", netipAddr("2001:db8:0:1::5")) != RateKey("1f", netipAddr("2001:db8:0:1::99")) {
		t.Fatal("IPv6 sources of one /64 must share a key")
	}
}

func netipAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
