// SPDX-License-Identifier: AGPL-3.0-or-later

package tunnel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

const validID = "abcdefghijklmnopqrstuvwxyz"

func TestGatewaySPIFFEIDRoundTrip(t *testing.T) {
	uri, err := GatewaySPIFFEID(validID)
	if err != nil || uri != "spiffe://home-mandate.com/home/"+validID+"/gateway" {
		t.Fatalf("%q %v", uri, err)
	}

	id, err := ParseGatewaySPIFFEID(uri)

	if err != nil || id != validID {
		t.Fatalf("%q %v", id, err)
	}
}

func TestParseGatewaySPIFFEIDRejects(t *testing.T) {
	p := "spiffe://home-mandate.com/home/"
	tests := []struct{ name, in string }{
		{"empty", ""},
		{"wrong scheme", "https://home-mandate.com/home/" + validID + "/gateway"},
		{"wrong trust domain", "spiffe://home-mandate.org/home/" + validID + "/gateway"},
		{"trust domain with suffix", "spiffe://home-mandate.com.evil/home/" + validID + "/gateway"},
		{"wrong workload", p + validID + "/agent"},
		{"extra path", p + validID + "/gateway/x"},
		{"trailing slash", p + validID + "/gateway/"},
		{"query", p + validID + "/gateway?x=1"},
		{"fragment", p + validID + "/gateway#x"},
		{"port", "spiffe://home-mandate.com:443/home/" + validID + "/gateway"},
		{"userinfo", "spiffe://u@home-mandate.com/home/" + validID + "/gateway"},
		{"empty id", p + "/gateway"},
		{"id too short for 128 bits", p + strings.Repeat("a", HomeIDLen-1) + "/gateway"},
		{"id too long", p + strings.Repeat("a", HomeIDLen+1) + "/gateway"},
		{"digit outside base32", p + strings.Repeat("a", HomeIDLen-1) + "0" + "/gateway"},
		{"digit 8 outside base32", p + strings.Repeat("a", HomeIDLen-1) + "8" + "/gateway"},
		{"upper case id", p + strings.ToUpper(validID) + "/gateway"},
		{"dot in id", p + "abcdefghijklmnopqrstuvwxy.z/gateway"},
		{"dash in id", p + "abcdefghijklmnopqrstuvwxy-z/gateway"},
		{"percent in id", p + "abcdefghijklmnopqrstuvwxy%61/gateway"},
		{"non-ASCII id", p + "abcdefghijklmnopqrstuvwxyä/gateway"},
		{"NUL byte", p + validID + "\x00/gateway"},
		{"path traversal", p + "../" + validID + "/gateway"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if id, err := ParseGatewaySPIFFEID(tt.in); !errors.Is(err, ErrIdentity) {
				t.Fatalf("accepted as %q (err %v)", id, err)
			}
		})
	}
}

func TestGatewaySPIFFEIDRejectsInvalidID(t *testing.T) {
	if _, err := GatewaySPIFFEID("short"); !errors.Is(err, ErrIdentity) {
		t.Fatal(err)
	}
}

func TestHomeIDFromServerName(t *testing.T) {
	tests := []struct {
		name, in string
		want     string
		wantErr  bool
	}{
		{"valid", validID + ".home-mandate.net", validID, false},
		{"upper-case host is normalized", strings.ToUpper(validID) + ".HOME-MANDATE.NET", validID, false},
		{"trailing dot", validID + ".home-mandate.net.", validID, false},
		{"other domain", validID + ".home-mandate.com", "", true},
		{"nested label", "x." + validID + ".home-mandate.net", "", true},
		{"apex", "home-mandate.net", "", true},
		{"short id", "abc.home-mandate.net", "", true},
		{"empty", "", "", true},
		{"suffix trick", validID + "home-mandate.net", "", true},
		{"IP literal", "192.0.2.1", "", true},
		{"Kelvin sign would lower-case to k", strings.Replace(validID, "k", "\u212a", 1) + ".home-mandate.net", "", true},
		{"non-ASCII byte elsewhere", validID + ".home-mandate.net\xff", "", true},
		{"IDN look-alike label", "\u00e4" + validID[1:] + ".home-mandate.net", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HomeIDFromServerName(tt.in)
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Fatalf("got %q, %v", got, err)
			}
			if err != nil && !errors.Is(err, ErrIdentity) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestHomeIDFromURIs(t *testing.T) {
	mk := func(ss ...string) []*url.URL {
		var out []*url.URL
		for _, s := range ss {
			u, _ := url.Parse(s)
			out = append(out, u)
		}
		return out
	}
	good := "spiffe://home-mandate.com/home/" + validID + "/gateway"
	tests := []struct {
		name string
		in   []*url.URL
		ok   bool
	}{
		{"exactly one", mk(good), true},
		{"none", nil, false},
		{"two", mk(good, good), false},
		{"one wrong", mk("spiffe://home-mandate.com/home/" + validID + "/other"), false},
		{"nil entry", []*url.URL{nil}, false},
		{"upper-case scheme", []*url.URL{{Scheme: "SPIFFE", Host: "home-mandate.com", Path: "/home/" + validID + "/gateway"}}, false},
		{"user info", []*url.URL{{Scheme: "spiffe", User: url.User("u"), Host: "home-mandate.com", Path: "/home/" + validID + "/gateway"}}, false},
		{"opaque", []*url.URL{{Scheme: "spiffe", Opaque: "//home-mandate.com/home/" + validID + "/gateway"}}, false},
		{"query", []*url.URL{{Scheme: "spiffe", Host: "home-mandate.com", Path: "/home/" + validID + "/gateway", RawQuery: "a=1"}}, false},
		{"force query", []*url.URL{{Scheme: "spiffe", Host: "home-mandate.com", Path: "/home/" + validID + "/gateway", ForceQuery: true}}, false},
		{"fragment", []*url.URL{{Scheme: "spiffe", Host: "home-mandate.com", Path: "/home/" + validID + "/gateway", Fragment: "x"}}, false},
		{"raw fragment", []*url.URL{{Scheme: "spiffe", Host: "home-mandate.com", Path: "/home/" + validID + "/gateway", RawFragment: "x"}}, false},
		{"hand-built valid URL", []*url.URL{{Scheme: "spiffe", Host: "home-mandate.com", Path: "/home/" + validID + "/gateway"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := HomeIDFromURIs(tt.in)
			if (err == nil) != tt.ok || (tt.ok && id != validID) {
				t.Fatalf("%q %v", id, err)
			}
		})
	}
}

func TestTLSConfigPinsProtocolSecurity(t *testing.T) {
	cfg := NewTLSConfig()
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %#x", cfg.MinVersion)
	}
	if len(cfg.CurvePreferences) != 1 || cfg.CurvePreferences[0] != tls.X25519MLKEM768 {
		t.Fatalf("curves = %v", cfg.CurvePreferences)
	}
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "hm-tunnel/1" || !cfg.SessionTicketsDisabled {
		t.Fatalf("ALPN %v, tickets disabled %v", cfg.NextProtos, cfg.SessionTicketsDisabled)
	}
	if NewTLSConfig() == cfg {
		t.Fatal("config is shared")
	}
}

type testPKI struct {
	pool *x509.CertPool
	ca   *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newPKI(t *testing.T) testPKI {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return testPKI{pool: pool, ca: ca, key: key}
}

func (p testPKI) leaf(t *testing.T, tpl *x509.Certificate) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl.SerialNumber = big.NewInt(time.Now().UnixNano())
	tpl.NotBefore, tpl.NotAfter = time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.ca, &key.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// handshake runs a real mutual TLS handshake over an in-memory pipe and returns the server's view.
func handshake(t *testing.T, srv, cli *tls.Config) (tls.ConnectionState, error, error) {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_ = a.SetDeadline(time.Now().Add(5 * time.Second))
	_ = b.SetDeadline(time.Now().Add(5 * time.Second))
	s, c := tls.Server(a, srv), tls.Client(b, cli)
	cerr := make(chan error, 1)
	go func() { cerr <- c.Handshake() }()
	serr := s.Handshake()
	if serr != nil {
		_ = a.Close() // unblock the client
	}
	return s.ConnectionState(), serr, <-cerr
}

func TestMutualTLSAuthenticatesTheGatewayBySPIFFEID(t *testing.T) {
	pki := newPKI(t)
	uri, _ := url.Parse("spiffe://home-mandate.com/home/" + validID + "/gateway")
	gw := pki.leaf(t, &x509.Certificate{URIs: []*url.URL{uri}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	relay := pki.leaf(t, &x509.Certificate{DNSNames: []string{"relay.home-mandate.com"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})

	srv := NewTLSConfig()
	srv.Certificates = []tls.Certificate{relay}
	srv.ClientAuth = tls.RequireAndVerifyClientCert
	srv.ClientCAs = pki.pool
	cli := NewTLSConfig()
	cli.Certificates = []tls.Certificate{gw}
	cli.RootCAs = pki.pool
	cli.ServerName = "relay.home-mandate.com"

	state, serr, cerr := handshake(t, srv, cli)

	if serr != nil || cerr != nil {
		t.Fatalf("handshake: %v / %v", serr, cerr)
	}
	if state.NegotiatedProtocol != ALPN {
		t.Fatalf("alpn = %q", state.NegotiatedProtocol)
	}
	if state.Version != tls.VersionTLS13 {
		t.Fatalf("version = %#x", state.Version)
	}
	id, err := HomeIDFromURIs(state.PeerCertificates[0].URIs)
	if err != nil || id != validID {
		t.Fatalf("id %q err %v", id, err)
	}
}

func TestHandshakeRefusesOldTLSAndMissingClientCertificate(t *testing.T) {
	pki := newPKI(t)
	relay := pki.leaf(t, &x509.Certificate{DNSNames: []string{"relay.home-mandate.com"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	srv := NewTLSConfig()
	srv.Certificates = []tls.Certificate{relay}
	srv.ClientAuth = tls.RequireAndVerifyClientCert
	srv.ClientCAs = pki.pool

	t.Run("TLS 1.2 client", func(t *testing.T) {
		cli := &tls.Config{MaxVersion: tls.VersionTLS12, RootCAs: pki.pool, ServerName: "relay.home-mandate.com"}
		_, serr, _ := handshake(t, srv, cli)
		if serr == nil {
			t.Fatal("TLS 1.2 accepted")
		}
	})
	t.Run("client without certificate", func(t *testing.T) {
		cli := NewTLSConfig()
		cli.RootCAs = pki.pool
		cli.ServerName = "relay.home-mandate.com"
		_, serr, _ := handshake(t, srv, cli)
		if serr == nil {
			t.Fatal("anonymous client accepted")
		}
	})
}

func FuzzParseGatewaySPIFFEID(f *testing.F) {
	f.Add("spiffe://home-mandate.com/home/" + validID + "/gateway")
	f.Add("spiffe://home-mandate.com/home//gateway")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		id, err := ParseGatewaySPIFFEID(s)
		if err != nil {
			return
		}
		back, err := GatewaySPIFFEID(id)
		if err != nil || back != s {
			t.Fatalf("not canonical: %q -> %q (%v)", s, back, err)
		}
	})
}

func FuzzHomeIDFromServerName(f *testing.F) {
	f.Add(validID + ".home-mandate.net")
	f.Add("A.B.home-mandate.net.")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		id, err := HomeIDFromServerName(s)
		if err != nil {
			return
		}
		for i := 0; i < len(id); i++ {
			if id[i] >= 0x80 {
				t.Fatalf("non-ASCII result %q", id)
			}
		}
		if _, err := GatewaySPIFFEID(id); err != nil {
			t.Fatalf("accepted ID %q does not build a SPIFFE ID: %v", id, err)
		}
	})
}

func sanExtension(t *testing.T, names ...asn1.RawValue) pkix.Extension {
	t.Helper()
	der, err := asn1.Marshal(names)
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: der}
}

func uriName(s string) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(s)}
}

func dnsName(s string) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte(s)}
}

func parseCert(t *testing.T, c tls.Certificate) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestHomeIDFromCertificateChecksTheRawSAN(t *testing.T) {
	pki := newPKI(t)
	good := "spiffe://home-mandate.com/home/" + validID + "/gateway"
	tests := []struct {
		name  string
		names []asn1.RawValue
		ok    bool
	}{
		{"exactly one gateway URI", []asn1.RawValue{uriName(good)}, true},
		{"empty fragment marker", []asn1.RawValue{uriName(good + "#")}, false},
		{"empty query marker", []asn1.RawValue{uriName(good + "?")}, false},
		{"upper-case scheme", []asn1.RawValue{uriName("SPIFFE" + strings.TrimPrefix(good, "spiffe"))}, false},
		{"two URIs", []asn1.RawValue{uriName(good), uriName(good)}, false},
		{"URI plus DNS name", []asn1.RawValue{uriName(good), dnsName("x.example")}, false},
		{"DNS name only", []asn1.RawValue{dnsName("x.example")}, false},
		{"other workload", []asn1.RawValue{uriName("spiffe://home-mandate.com/home/" + validID + "/agent")}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := parseCert(t, pki.leaf(t, &x509.Certificate{ExtraExtensions: []pkix.Extension{sanExtension(t, tt.names...)}}))

			id, err := HomeIDFromCertificate(c)

			if (err == nil) != tt.ok || (tt.ok && id != validID) {
				t.Fatalf("%q %v", id, err)
			}
			if err != nil && !errors.Is(err, ErrIdentity) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	t.Run("nil certificate", func(t *testing.T) {
		if _, err := HomeIDFromCertificate(nil); !errors.Is(err, ErrIdentity) {
			t.Fatal(err)
		}
	})
	t.Run("certificate without SAN", func(t *testing.T) {
		c := parseCert(t, pki.leaf(t, &x509.Certificate{}))
		if _, err := HomeIDFromCertificate(c); !errors.Is(err, ErrIdentity) {
			t.Fatal(err)
		}
	})
	t.Run("garbage SAN extension", func(t *testing.T) {
		c := &x509.Certificate{Extensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: []byte{0xFF, 0x01}}}}
		if _, err := HomeIDFromCertificate(c); !errors.Is(err, ErrIdentity) {
			t.Fatal(err)
		}
	})
}

func TestCheckConnection(t *testing.T) {
	pki := newPKI(t)
	good := parseCert(t, pki.leaf(t, &x509.Certificate{ExtraExtensions: []pkix.Extension{sanExtension(t, uriName("spiffe://home-mandate.com/home/"+validID+"/gateway"))}}))
	noSAN := parseCert(t, pki.leaf(t, &x509.Certificate{}))
	state := func(mut func(*tls.ConnectionState)) tls.ConnectionState {
		cs := tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true, NegotiatedProtocol: ALPN, PeerCertificates: []*x509.Certificate{good}}
		if mut != nil {
			mut(&cs)
		}
		return cs
	}
	tests := []struct {
		name string
		cs   tls.ConnectionState
		ok   bool
	}{
		{"good", state(nil), true},
		{"TLS 1.2", state(func(c *tls.ConnectionState) { c.Version = tls.VersionTLS12 }), false},
		{"no ALPN", state(func(c *tls.ConnectionState) { c.NegotiatedProtocol = "" }), false},
		{"other ALPN", state(func(c *tls.ConnectionState) { c.NegotiatedProtocol = "h2" }), false},
		{"handshake not complete", state(func(c *tls.ConnectionState) { c.HandshakeComplete = false }), false},
		{"no peer certificate", state(func(c *tls.ConnectionState) { c.PeerCertificates = nil }), false},
		{"certificate without identity", state(func(c *tls.ConnectionState) { c.PeerCertificates = []*x509.Certificate{noSAN} }), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := CheckConnection(tt.cs)
			if (err == nil) != tt.ok || (tt.ok && id != validID) {
				t.Fatalf("%q %v", id, err)
			}
			if err != nil && !errors.Is(err, ErrIdentity) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}
