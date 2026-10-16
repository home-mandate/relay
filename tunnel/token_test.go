// SPDX-License-Identifier: AGPL-3.0-or-later

package tunnel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

const (
	homeA = "aaaaaaaaaaaaaaaaaaaaaaaaaa"
	homeB = "bbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestNewTokenIsRandomAndFullLength(t *testing.T) {
	a, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewToken()
	if a == b || a == (Token{}) {
		t.Fatal("tokens repeat or are zero")
	}
}

func TestNewTokenFromReaderFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		r    func() *bytes.Reader
	}{
		{"short entropy", func() *bytes.Reader { return bytes.NewReader(make([]byte, TokenSize-1)) }},
		{"no entropy", func() *bytes.Reader { return bytes.NewReader(nil) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newTokenFrom(tt.r())
			if err == nil || got != (Token{}) {
				t.Fatalf("got %v, %v", got, err)
			}
		})
	}
}

func TestTokenNeverPrintsItsValue(t *testing.T) {
	tk := tok(0xAB)
	for _, s := range []string{tk.String(), fmtV(tk), fmtV(&tk)} {
		if strings.Contains(strings.ToLower(s), "abab") {
			t.Fatalf("token leaked: %q", s)
		}
	}
}

func TestTokenStoreRedeem(t *testing.T) {
	type step struct {
		advance time.Duration
		home    string
		want    error
	}
	tests := []struct {
		name  string
		issue string
		step  step
	}{
		{"valid", homeA, step{time.Second, homeA, nil}},
		{"valid at the last instant", homeA, step{TokenValidity, homeA, nil}},
		{"expired", homeA, step{TokenValidity + time.Nanosecond, homeA, ErrTokenExpired}},
		{"bound to another installation", homeA, step{time.Second, homeB, ErrTokenWrongInstallation}},
		{"empty installation", homeA, step{time.Second, "", ErrTokenWrongInstallation}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewTokenStore()
			tk, valid, err := s.Issue(tt.issue, t0)
			if err != nil || valid != TokenValidity {
				t.Fatalf("issue: %v %v", valid, err)
			}

			err = s.Redeem(tk, tt.step.home, t0.Add(tt.step.advance))

			if !errors.Is(err, tt.step.want) {
				t.Fatalf("err = %v, want %v", err, tt.step.want)
			}
		})
	}
}

func TestTokenIsSingleUse(t *testing.T) {
	s := NewTokenStore()
	tk, _, _ := s.Issue(homeA, t0)
	if err := s.Redeem(tk, homeA, t0); err != nil {
		t.Fatal(err)
	}

	err := s.Redeem(tk, homeA, t0)

	if !errors.Is(err, ErrTokenUnknown) {
		t.Fatalf("second use: %v", err)
	}
}

func TestWrongInstallationBurnsTheToken(t *testing.T) {
	s := NewTokenStore()
	tk, _, _ := s.Issue(homeA, t0)
	if err := s.Redeem(tk, homeB, t0); !errors.Is(err, ErrTokenWrongInstallation) {
		t.Fatal(err)
	}

	err := s.Redeem(tk, homeA, t0)

	if !errors.Is(err, ErrTokenUnknown) {
		t.Fatalf("token survived a foreign redemption: %v", err)
	}
}

func TestUnknownTokenIsRejected(t *testing.T) {
	s := NewTokenStore()
	if err := s.Redeem(tok(1), homeA, t0); !errors.Is(err, ErrTokenUnknown) {
		t.Fatal(err)
	}
}

func TestCancelRemovesTheToken(t *testing.T) {
	s := NewTokenStore()
	tk, _, _ := s.Issue(homeA, t0)

	s.Cancel(tk, homeA)

	if err := s.Redeem(tk, homeA, t0); !errors.Is(err, ErrTokenUnknown) {
		t.Fatal(err)
	}
	if s.Pending(homeA) != 0 {
		t.Fatal("pending count not reduced")
	}
	s.Cancel(tk, homeA) // idempotent
}

func TestIssueLimitsPendingTokensPerInstallation(t *testing.T) {
	s := NewTokenStore()
	for i := 0; i < MaxPendingTokens; i++ {
		if _, _, err := s.Issue(homeA, t0); err != nil {
			t.Fatalf("issue %d: %v", i, err)
		}
	}

	_, _, err := s.Issue(homeA, t0)
	_, _, errOther := s.Issue(homeB, t0)

	if !errors.Is(err, ErrTooManyPending) {
		t.Fatalf("err = %v", err)
	}
	if errOther != nil {
		t.Fatalf("limit leaked to another installation: %v", errOther)
	}
}

func TestIssueReclaimsExpiredTokens(t *testing.T) {
	s := NewTokenStore()
	for i := 0; i < MaxPendingTokens; i++ {
		s.Issue(homeA, t0)
	}

	_, _, err := s.Issue(homeA, t0.Add(TokenValidity+time.Second))

	if err != nil {
		t.Fatalf("expired tokens still count: %v", err)
	}
}

func TestSweepDropsOnlyExpiredTokens(t *testing.T) {
	s := NewTokenStore()
	old, _, _ := s.Issue(homeA, t0)
	fresh, _, _ := s.Issue(homeB, t0.Add(8*time.Second))

	s.Sweep(t0.Add(TokenValidity + time.Second))

	if s.Pending(homeA) != 0 || s.Pending(homeB) != 1 {
		t.Fatalf("pending A=%d B=%d", s.Pending(homeA), s.Pending(homeB))
	}
	if err := s.Redeem(old, homeA, t0); !errors.Is(err, ErrTokenUnknown) {
		t.Fatal(err)
	}
	if err := s.Redeem(fresh, homeB, t0.Add(9*time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestIssueRejectsEmptyInstallation(t *testing.T) {
	if _, _, err := NewTokenStore().Issue("", t0); !errors.Is(err, ErrEmptyInstallation) {
		t.Fatalf("err = %v", err)
	}
}

func TestCancelIsScopedToTheInstallation(t *testing.T) {
	s := NewTokenStore()
	tk, _, _ := s.Issue(homeA, t0)

	s.Cancel(tk, homeB)

	if s.Pending(homeA) != 1 {
		t.Fatal("another installation cancelled the token")
	}
	if err := s.Redeem(tk, homeA, t0); err != nil {
		t.Fatalf("token no longer redeemable: %v", err)
	}
}

func TestZeroValueTokenStoreIsUsable(t *testing.T) {
	var s TokenStore

	if err := s.Redeem(tok(1), homeA, t0); !errors.Is(err, ErrTokenUnknown) {
		t.Fatal(err)
	}
	s.Cancel(tok(1), homeA)
	s.Sweep(t0)
	tk, _, err := s.Issue(homeA, t0)
	if err != nil {
		t.Fatalf("issue on zero value: %v", err)
	}
	if err := s.Redeem(tk, homeA, t0); err != nil {
		t.Fatal(err)
	}
}

func TestStoreHasAGlobalLimit(t *testing.T) {
	s := NewTokenStore()
	s.maxTotal = 3
	for _, h := range []string{homeA, homeB, "c"} {
		if _, _, err := s.Issue(h, t0); err != nil {
			t.Fatal(err)
		}
	}

	_, _, err := s.Issue("d", t0)
	_, _, later := s.Issue("d", t0.Add(TokenValidity+time.Second))

	if !errors.Is(err, ErrStoreFull) {
		t.Fatalf("err = %v", err)
	}
	if later != nil {
		t.Fatalf("expired tokens still fill the store: %v", later)
	}
}

func TestQueueStaysBoundedUnderIssueAndRedeemChurn(t *testing.T) {
	s := NewTokenStore()
	for i := 0; i < 1000; i++ {
		tk, _, err := s.Issue(homeA, t0)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Redeem(tk, homeA, t0); err != nil {
			t.Fatal(err)
		}
	}

	if n := len(s.queues[homeA]); n > 4*MaxPendingTokens+1 {
		t.Fatalf("queue length %d", n)
	}
}

func TestSweepHandlesNonMonotonicClocks(t *testing.T) {
	s := NewTokenStore()
	late, _, _ := s.Issue(homeA, t0.Add(5*time.Second))
	early, _, _ := s.Issue(homeA, t0)

	s.Sweep(t0.Add(11 * time.Second)) // early expired, late not

	if err := s.Redeem(late, homeA, t0.Add(11*time.Second)); err != nil {
		t.Fatalf("late token swept: %v", err)
	}
	if err := s.Redeem(early, homeA, t0.Add(11*time.Second)); !errors.Is(err, ErrTokenUnknown) && !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("early token: %v", err)
	}
}

type tokenHolder struct {
	Name  string `json:"name"`
	Token Token  `json:"token"`
}

func TestTokenIsRedactedInJSONAndSlog(t *testing.T) {
	tk := tok(0xAB)
	values := map[string]any{
		"token":        tk,
		"pointer":      &tk,
		"holder":       tokenHolder{"x", tk},
		"stream-open":  StreamOpen{Token: tk, ValidMillis: 1},
		"stream-close": StreamClose{Token: tk, Reason: CloseRefused},
		"data-bind":    DataBind{Token: tk},
	}
	for name, v := range values {
		t.Run(name, func(t *testing.T) {
			asJSON, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			var logs bytes.Buffer
			slog.New(slog.NewJSONHandler(&logs, nil)).Info("m", "v", v, slog.Any("a", v))
			var text bytes.Buffer
			slog.New(slog.NewTextHandler(&text, nil)).Info("m", "v", v)

			for _, out := range []string{string(asJSON), logs.String(), text.String()} {
				if strings.Contains(out, "171") || strings.Contains(out, "q6ur") || strings.Contains(strings.ToLower(out), "abab") {
					t.Fatalf("token leaked: %s", out)
				}
				if !strings.Contains(out, "redacted") {
					t.Fatalf("no redaction marker in %s", out)
				}
			}
		})
	}
}

func TestStoreKeepsOnlyHashes(t *testing.T) {
	s := NewTokenStore()
	tk, _, _ := s.Issue(homeA, t0)

	for key := range s.entries {
		if bytes.Equal(key[:], tk[:]) {
			t.Fatal("raw token used as map key")
		}
	}
}

func fmtV(v any) string { return fmt.Sprintf("%v %+v %#v %s", v, v, v, v) }
