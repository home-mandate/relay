// SPDX-License-Identifier: AGPL-3.0-or-later

package tunnel

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"testing"
)

var proxySig = []byte("\r\n\r\n\x00\r\nQUIT\n")

func v4header(srcIP, dstIP [4]byte, sp, dp uint16) []byte {
	b := append([]byte{}, proxySig...)
	b = append(b, 0x21, 0x11, 0x00, 0x0C)
	b = append(b, srcIP[:]...)
	b = append(b, dstIP[:]...)
	return append(b, byte(sp>>8), byte(sp), byte(dp>>8), byte(dp))
}

func TestEncodeProxyV2KnownVectors(t *testing.T) {
	tests := []struct {
		name     string
		src, dst string
		want     []byte
	}{
		{"tcp4", "203.0.113.7:51234", "198.51.100.1:443",
			v4header([4]byte{203, 0, 113, 7}, [4]byte{198, 51, 100, 1}, 51234, 443)},
		{"v4-mapped v6 addresses are written as tcp4", "[::ffff:203.0.113.7]:51234", "[::ffff:198.51.100.1]:443",
			v4header([4]byte{203, 0, 113, 7}, [4]byte{198, 51, 100, 1}, 51234, 443)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeProxyV2(netip.MustParseAddrPort(tt.src), netip.MustParseAddrPort(tt.dst))
			if err != nil || !bytes.Equal(got, tt.want) {
				t.Fatalf("got % x, err %v\nwant % x", got, err, tt.want)
			}
		})
	}
}

func TestProxyV2RoundTrip(t *testing.T) {
	tests := []struct{ name, src, dst string }{
		{"tcp4", "203.0.113.7:51234", "198.51.100.1:443"},
		{"tcp6", "[2001:db8::7]:51234", "[2001:db8:ffff::1]:443"},
		{"lowest ports", "192.0.2.1:1", "192.0.2.2:1"},
		{"highest ports", "192.0.2.1:65535", "192.0.2.2:65535"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src, dst := netip.MustParseAddrPort(tt.src), netip.MustParseAddrPort(tt.dst)
			wire, err := EncodeProxyV2(src, dst)
			if err != nil {
				t.Fatal(err)
			}

			h, n, err := DecodeProxyV2(wire)

			if err != nil || n != len(wire) || h.Source != src || h.Destination != dst {
				t.Fatalf("got %+v n=%d err=%v", h, n, err)
			}
		})
	}
}

func TestEncodeProxyV2RejectsInvalidAddresses(t *testing.T) {
	tests := []struct{ name, src, dst string }{
		{"mixed families", "192.0.2.1:1", "[2001:db8::1]:1"},
		{"source port zero", "192.0.2.1:0", "192.0.2.2:1"},
		{"destination port zero", "192.0.2.1:1", "192.0.2.2:0"},
		{"unspecified source", "0.0.0.0:1", "192.0.2.2:1"},
		{"multicast source", "224.0.0.1:1", "192.0.2.2:1"},
		{"unspecified v6 source", "[::]:1", "[2001:db8::1]:1"},
		{"multicast v6 source", "[ff02::1]:1", "[2001:db8::1]:1"},
		{"zone", "[fe80::1%eth0]:1", "[fe80::2%eth0]:1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EncodeProxyV2(netip.MustParseAddrPort(tt.src), netip.MustParseAddrPort(tt.dst))
			if !errors.Is(err, ErrProxyHeader) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	t.Run("zero values", func(t *testing.T) {
		if _, err := EncodeProxyV2(netip.AddrPort{}, netip.AddrPort{}); !errors.Is(err, ErrProxyHeader) {
			t.Fatal(err)
		}
	})
}

func TestDecodeProxyV2RejectsMalformedHeaders(t *testing.T) {
	good := v4header([4]byte{203, 0, 113, 7}, [4]byte{198, 51, 100, 1}, 5, 443)
	mut := func(f func(b []byte) []byte) []byte { return f(append([]byte{}, good...)) }
	good6, _ := EncodeProxyV2(netip.MustParseAddrPort("[2001:db8::7]:5"), netip.MustParseAddrPort("[2001:db8::1]:443"))
	tests := []struct {
		name string
		in   []byte
		want error
	}{
		{"empty", nil, ErrShortBuffer},
		{"short fixed part", good[:15], ErrShortBuffer},
		{"short address block", good[:len(good)-1], ErrShortBuffer},
		{"v1 text header", []byte("PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n"), ErrProxyHeader},
		{"wrong signature", mut(func(b []byte) []byte { b[3] ^= 1; return b }), ErrProxyHeader},
		{"version 1 in the high nibble", mut(func(b []byte) []byte { b[12] = 0x11; return b }), ErrProxyHeader},
		{"version 3", mut(func(b []byte) []byte { b[12] = 0x31; return b }), ErrProxyHeader},
		{"LOCAL command", mut(func(b []byte) []byte { b[12] = 0x20; return b }), ErrProxyHeader},
		{"unknown command", mut(func(b []byte) []byte { b[12] = 0x22; return b }), ErrProxyHeader},
		{"UNSPEC family", mut(func(b []byte) []byte { b[13] = 0x00; return b }), ErrProxyHeader},
		{"UDP over IPv4", mut(func(b []byte) []byte { b[13] = 0x12; return b }), ErrProxyHeader},
		{"UNIX socket", mut(func(b []byte) []byte { b[13] = 0x31; return b }), ErrProxyHeader},
		{"tcp4 with the tcp6 length", mut(func(b []byte) []byte { b[15] = 36; return b }), ErrProxyHeader},
		{"tcp4 with extra TLV bytes", mut(func(b []byte) []byte { b[15] = 16; return append(b, 0, 0, 0, 0) }), ErrProxyHeader},
		{"tcp4 with a shorter length", mut(func(b []byte) []byte { b[15] = 11; return b }), ErrProxyHeader},
		{"tcp6 with the tcp4 length", mut(func(b []byte) []byte { return append(append([]byte{}, good6[:15]...), 12) }), ErrProxyHeader},
		{"length beyond anything valid", mut(func(b []byte) []byte { b[14], b[15] = 0xFF, 0xFF; return b }), ErrProxyHeader},
		{"source port zero", mut(func(b []byte) []byte { b[24], b[25] = 0, 0; return b }), ErrProxyHeader},
		{"destination port zero", mut(func(b []byte) []byte { b[26], b[27] = 0, 0; return b }), ErrProxyHeader},
		{"unspecified source", mut(func(b []byte) []byte { copy(b[16:20], []byte{0, 0, 0, 0}); return b }), ErrProxyHeader},
		{"multicast source", mut(func(b []byte) []byte { copy(b[16:20], []byte{239, 1, 1, 1}); return b }), ErrProxyHeader},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := DecodeProxyV2(tt.in)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
	t.Run("tcp6 header with v4-mapped source is refused", func(t *testing.T) {
		b := append([]byte{}, good6...)
		copy(b[16:32], netip.MustParseAddr("::ffff:1.2.3.4").AsSlice())
		if _, _, err := DecodeProxyV2(b); !errors.Is(err, ErrProxyHeader) {
			t.Fatal(err)
		}
	})
}

func TestReadProxyV2(t *testing.T) {
	src, dst := netip.MustParseAddrPort("203.0.113.7:51234"), netip.MustParseAddrPort("198.51.100.1:443")
	wire, _ := EncodeProxyV2(src, dst)

	t.Run("reads exactly the header and leaves the stream", func(t *testing.T) {
		r := bytes.NewReader(append(append([]byte{}, wire...), "\x16\x03\x01tls"...))
		h, err := ReadProxyV2(r)
		if err != nil || h.Source != src || h.Destination != dst {
			t.Fatalf("%+v %v", h, err)
		}
		rest, _ := io.ReadAll(r)
		if string(rest) != "\x16\x03\x01tls" {
			t.Fatalf("rest = %q", rest)
		}
	})
	t.Run("a stream that does not start with the signature is refused after 16 bytes at most", func(t *testing.T) {
		r := bytes.NewReader(bytes.Repeat([]byte("x"), 100))
		if _, err := ReadProxyV2(r); !errors.Is(err, ErrProxyHeader) {
			t.Fatal(err)
		}
		if r.Len() < 100-proxyFixedSize {
			t.Fatalf("read %d bytes", 100-r.Len())
		}
	})
	t.Run("truncated stream", func(t *testing.T) {
		if _, err := ReadProxyV2(bytes.NewReader(wire[:20])); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatal(err)
		}
	})
	t.Run("empty stream", func(t *testing.T) {
		if _, err := ReadProxyV2(bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
	})
}

func FuzzParseProxyV2(f *testing.F) {
	w4, _ := EncodeProxyV2(netip.MustParseAddrPort("203.0.113.7:1"), netip.MustParseAddrPort("198.51.100.1:443"))
	w6, _ := EncodeProxyV2(netip.MustParseAddrPort("[2001:db8::7]:1"), netip.MustParseAddrPort("[2001:db8::1]:443"))
	for _, s := range [][]byte{nil, w4, w6, w4[:20], proxySig, []byte("PROXY TCP4 1.1.1.1 2.2.2.2 1 2\r\n"), append(append([]byte{}, w4...), "tail"...)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		h, n, err := DecodeProxyV2(in)
		if err != nil {
			if _, rerr := ReadProxyV2(bytes.NewReader(in)); rerr == nil {
				t.Fatal("ReadProxyV2 accepts what DecodeProxyV2 refuses")
			}
			return
		}
		again, err := EncodeProxyV2(h.Source, h.Destination)
		if err != nil || !bytes.Equal(again, in[:n]) {
			t.Fatalf("not canonical: % x vs % x (%v)", again, in[:n], err)
		}
		r := bytes.NewReader(in)
		h2, err := ReadProxyV2(r)
		if err != nil || h2 != h || len(in)-r.Len() != n {
			t.Fatalf("reader disagrees: %v", err)
		}
	})
}

func TestCheckGatewaySource(t *testing.T) {
	dst := netip.MustParseAddrPort("192.0.2.1:443")
	tests := []struct {
		name string
		src  string
		ok   bool
	}{
		{"public IPv4", "203.0.113.7:5", true},
		{"public IPv6", "[2a00:1450::1]:5", true},
		{"loopback", "127.0.0.1:5", false},
		{"loopback IPv6", "[::1]:5", false},
		{"private 10/8", "10.1.2.3:5", false},
		{"private 192.168/16", "192.168.1.1:5", false},
		{"private 172.16/12", "172.16.0.1:5", false},
		{"unique local IPv6", "[fd00::1]:5", false},
		{"link-local", "169.254.1.1:5", false},
		{"link-local IPv6", "[fe80::1]:5", false},
		{"broadcast", "255.255.255.255:5", false},
		{"this network", "0.1.2.3:5", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := ProxyHeader{Source: netip.MustParseAddrPort(tt.src), Destination: dst}
			err := h.CheckGatewaySource()
			if (err == nil) != tt.ok {
				t.Fatalf("err = %v", err)
			}
			if err != nil && !errors.Is(err, ErrProxyHeader) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestPlaceholderDestinationRevealsNothing(t *testing.T) {
	for _, src := range []string{"203.0.113.7", "2001:db8::7"} {
		a := ProxyDestinationFor(netip.MustParseAddr(src))
		if a.Addr().Is4() != netip.MustParseAddr(src).Is4() {
			t.Fatalf("family differs for %s: %v", src, a)
		}
		if _, err := EncodeProxyV2(netip.AddrPortFrom(netip.MustParseAddr(src), 1), a); err != nil {
			t.Fatalf("placeholder not encodable: %v", err)
		}
	}
	if got := ProxyDestinationFor(netip.MustParseAddr("::ffff:203.0.113.7")); !got.Addr().Is4() {
		t.Fatalf("mapped address: %v", got)
	}
}
