// SPDX-License-Identifier: AGPL-3.0-or-later

package tunnel

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

// ErrProxyHeader marks a PROXY protocol v2 header that is not exactly what the tunnel allows.
var ErrProxyHeader = errors.New("tunnel: invalid PROXY protocol v2 header")

const (
	proxyFixedSize  = 16
	proxyCmdProxy   = 0x21 // version 2, command PROXY
	proxyFamTCP4    = 0x11
	proxyFamTCP6    = 0x21
	proxyAddrLenV4  = 12
	proxyAddrLenV6  = 36
	proxyMaxMessage = proxyFixedSize + proxyAddrLenV6
)

var proxySignature = []byte("\r\n\r\n\x00\r\nQUIT\n")

// ProxyHeader carries the address of the agent as the relay saw it and the address it connected to.
type ProxyHeader struct {
	Source, Destination netip.AddrPort
}

func proxyErr(detail string) error { return fmt.Errorf("%w: %s", ErrProxyHeader, detail) }

// checkAddrs applies the tunnel's rules to a source and destination pair.
func checkAddrs(src, dst netip.AddrPort) error {
	for _, a := range []netip.AddrPort{src, dst} {
		switch {
		case !a.IsValid():
			return proxyErr("invalid address")
		case a.Addr().Zone() != "":
			return proxyErr("zone in address")
		case a.Port() == 0:
			return proxyErr("port zero")
		case a.Addr().IsUnspecified():
			return proxyErr("unspecified address")
		case a.Addr().Is4In6():
			return proxyErr("IPv4-mapped IPv6 address")
		}
	}
	if src.Addr().Is4() != dst.Addr().Is4() {
		return proxyErr("mixed address families")
	}
	if src.Addr().IsMulticast() {
		return proxyErr("multicast source")
	}
	return nil
}

// EncodeProxyV2 returns the PROXY protocol v2 header the relay writes at the start of a data
// stream: command PROXY, TCP over IPv4 or IPv6, no TLV extensions. IPv4-mapped IPv6 addresses
// are written as IPv4.
func EncodeProxyV2(src, dst netip.AddrPort) ([]byte, error) {
	src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
	dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	if err := checkAddrs(src, dst); err != nil {
		return nil, err
	}
	fam, n := byte(proxyFamTCP6), proxyAddrLenV6
	if src.Addr().Is4() {
		fam, n = proxyFamTCP4, proxyAddrLenV4
	}
	b := make([]byte, 0, proxyFixedSize+n)
	b = append(b, proxySignature...)
	b = append(b, proxyCmdProxy, fam)
	b = binary.BigEndian.AppendUint16(b, uint16(n))
	b = append(b, src.Addr().AsSlice()...)
	b = append(b, dst.Addr().AsSlice()...)
	b = binary.BigEndian.AppendUint16(b, src.Port())
	return binary.BigEndian.AppendUint16(b, dst.Port()), nil
}

// parseProxyFixed validates the 16 fixed bytes and returns the length of the address block.
func parseProxyFixed(h []byte) (int, error) {
	if !bytes.Equal(h[:12], proxySignature) {
		return 0, proxyErr("bad signature")
	}
	if h[12] != proxyCmdProxy {
		return 0, proxyErr("version or command not allowed")
	}
	want := 0
	switch h[13] {
	case proxyFamTCP4:
		want = proxyAddrLenV4
	case proxyFamTCP6:
		want = proxyAddrLenV6
	default:
		return 0, proxyErr("address family or protocol not allowed")
	}
	if int(binary.BigEndian.Uint16(h[14:16])) != want {
		return 0, proxyErr("length does not match the address family")
	}
	return want, nil
}

func parseProxyAddrs(fam byte, a []byte) (ProxyHeader, error) {
	var src, dst netip.Addr
	if fam == proxyFamTCP4 {
		src, dst = netip.AddrFrom4([4]byte(a[0:4])), netip.AddrFrom4([4]byte(a[4:8]))
		a = a[8:]
	} else {
		src, dst = netip.AddrFrom16([16]byte(a[0:16])), netip.AddrFrom16([16]byte(a[16:32]))
		a = a[32:]
	}
	h := ProxyHeader{
		Source:      netip.AddrPortFrom(src, binary.BigEndian.Uint16(a[0:2])),
		Destination: netip.AddrPortFrom(dst, binary.BigEndian.Uint16(a[2:4])),
	}
	if err := checkAddrs(h.Source, h.Destination); err != nil {
		return ProxyHeader{}, err
	}
	return h, nil
}

// DecodeProxyV2 parses the header at the start of b and returns it with its length. Anything
// beyond the exact canonical form (see EncodeProxyV2) is refused: LOCAL, UNSPEC, UDP, UNIX,
// TLVs, a length that does not match the family, port zero, unspecified or multicast sources.
func DecodeProxyV2(b []byte) (ProxyHeader, int, error) {
	if len(b) < proxyFixedSize {
		return ProxyHeader{}, 0, ErrShortBuffer
	}
	n, err := parseProxyFixed(b[:proxyFixedSize])
	if err != nil {
		return ProxyHeader{}, 0, err
	}
	if len(b) < proxyFixedSize+n {
		return ProxyHeader{}, 0, ErrShortBuffer
	}
	h, err := parseProxyAddrs(b[13], b[proxyFixedSize:proxyFixedSize+n])
	if err != nil {
		return ProxyHeader{}, 0, err
	}
	return h, proxyFixedSize + n, nil
}

// ReadProxyV2 reads and parses the header from the start of a data stream. It reads exactly the
// header, never a byte of the stream behind it, and never more than 52 bytes.
func ReadProxyV2(r io.Reader) (ProxyHeader, error) {
	var buf [proxyMaxMessage]byte
	if _, err := io.ReadFull(r, buf[:proxyFixedSize]); err != nil {
		return ProxyHeader{}, err
	}
	n, err := parseProxyFixed(buf[:proxyFixedSize])
	if err != nil {
		return ProxyHeader{}, err
	}
	if _, err := io.ReadFull(r, buf[proxyFixedSize:proxyFixedSize+n]); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return ProxyHeader{}, err
	}
	return parseProxyAddrs(buf[13], buf[proxyFixedSize:proxyFixedSize+n])
}

// Destination placeholders: the destination of the PROXY header carries no information. The
// relay writes a documentation address (RFC 5737, RFC 3849) of the agent's family, so the header
// reveals nothing about the relay's addressing, and the gateway never uses it.
var (
	placeholderDest4 = netip.MustParseAddrPort("192.0.2.1:443")
	placeholderDest6 = netip.MustParseAddrPort("[2001:db8::1]:443")
)

// ProxyDestinationFor returns the placeholder destination for an agent at src.
func ProxyDestinationFor(src netip.Addr) netip.AddrPort {
	if src.Unmap().Is4() {
		return placeholderDest4
	}
	return placeholderDest6
}

// CheckGatewaySource applies the additional rule of the gateway: the agent as seen by the relay
// has a public address. Loopback, private, link-local, "this network" and broadcast sources are
// refused, because a forged header must not make a remote agent look like a local one.
func (h ProxyHeader) CheckGatewaySource() error {
	a := h.Source.Addr()
	switch {
	case a.IsLoopback(), a.IsPrivate(), a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast():
		return proxyErr("source is not a public address")
	case a.Is4() && (a.As4()[0] == 0 || a == netip.AddrFrom4([4]byte{255, 255, 255, 255})):
		return proxyErr("source is not a public address")
	}
	return nil
}
