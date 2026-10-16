// SPDX-License-Identifier: AGPL-3.0-or-later

package tunnel

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ErrIdentity marks an identity (SPIFFE ID, server name or certificate) the tunnel does not accept.
var ErrIdentity = errors.New("tunnel: invalid identity")

const (
	spiffePrefix = "spiffe://home-mandate.com/home/"
	spiffeSuffix = "/gateway"
	serverSuffix = ".home-mandate.net"

	// HomeIDLen is the length of a home ID: 26 characters of lower-case base32 (RFC 4648
	// alphabet a-z, 2-7) carry 130 random bits. Same format as installations.public_id in the
	// cloud database.
	HomeIDLen = 26
)

func identityErr(detail string) error { return fmt.Errorf("%w: %s", ErrIdentity, detail) }

// validHomeID accepts exactly HomeIDLen characters of lower-case base32 (a-z, 2-7).
func validHomeID(id string) error {
	if len(id) != HomeIDLen {
		return identityErr("home ID length")
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < 'a' || c > 'z') && (c < '2' || c > '7') {
			return identityErr("home ID character")
		}
	}
	return nil
}

// GatewaySPIFFEID returns spiffe://home-mandate.com/home/<id>/gateway.
func GatewaySPIFFEID(homeID string) (string, error) {
	if err := validHomeID(homeID); err != nil {
		return "", err
	}
	return spiffePrefix + homeID + spiffeSuffix, nil
}

// ParseGatewaySPIFFEID extracts the home ID from a gateway SPIFFE ID. It accepts exactly the
// form GatewaySPIFFEID produces: no port, user info, query, fragment, extra path or other case.
func ParseGatewaySPIFFEID(s string) (string, error) {
	rest, ok := strings.CutPrefix(s, spiffePrefix)
	if !ok {
		return "", identityErr("not a Home-Mandate SPIFFE ID")
	}
	id, ok := strings.CutSuffix(rest, spiffeSuffix)
	if !ok {
		return "", identityErr("not a gateway SPIFFE ID")
	}
	if err := validHomeID(id); err != nil {
		return "", err
	}
	return id, nil
}

// HomeIDFromURIs returns the home ID of already parsed URI SANs. It requires exactly one URI
// and checks every URL field. url.Parse lower-cases the scheme and drops an empty fragment, so
// it cannot see "SPIFFE://" or a trailing "#"; certificates MUST therefore be checked with
// HomeIDFromCertificate (or CheckConnection), which looks at the raw SAN bytes.
func HomeIDFromURIs(uris []*url.URL) (string, error) {
	if len(uris) != 1 || uris[0] == nil {
		return "", identityErr("certificate must carry exactly one URI SAN")
	}
	u := uris[0]
	if u.Scheme != "spiffe" || u.Host != "home-mandate.com" || u.User != nil || u.Opaque != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return "", identityErr("URI is not a gateway SPIFFE ID")
	}
	return ParseGatewaySPIFFEID(u.String())
}

var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

const generalNameURITag = 6

// HomeIDFromCertificate returns the home ID of a gateway certificate from the raw bytes of its
// subject alternative name extension. The extension must hold exactly one entry, a URI that is
// byte for byte a gateway SPIFFE ID.
func HomeIDFromCertificate(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", identityErr("no certificate")
	}
	var raw []byte
	for _, e := range cert.Extensions {
		if e.Id.Equal(oidSubjectAltName) {
			if raw != nil {
				return "", identityErr("duplicate SAN extension")
			}
			raw = e.Value
		}
	}
	if raw == nil {
		return "", identityErr("certificate has no SAN")
	}
	var names []asn1.RawValue
	if rest, err := asn1.Unmarshal(raw, &names); err != nil || len(rest) != 0 {
		return "", identityErr("unreadable SAN extension")
	}
	if len(names) != 1 || names[0].Class != asn1.ClassContextSpecific || names[0].Tag != generalNameURITag {
		return "", identityErr("SAN must be exactly one URI")
	}
	return ParseGatewaySPIFFEID(string(names[0].Bytes))
}

// CheckConnection verifies what the tunnel requires of an established TLS connection and returns
// the installation's home ID: TLS 1.3, the tunnel ALPN, and a peer certificate that carries
// exactly one gateway SPIFFE ID. Call it right after the handshake, on every connection.
func CheckConnection(cs tls.ConnectionState) (string, error) {
	switch {
	case !cs.HandshakeComplete:
		return "", identityErr("handshake not complete")
	case cs.Version != tls.VersionTLS13:
		return "", identityErr("TLS 1.3 required")
	case cs.NegotiatedProtocol != ALPN:
		return "", identityErr("ALPN mismatch")
	case len(cs.PeerCertificates) == 0:
		return "", identityErr("no peer certificate")
	}
	return HomeIDFromCertificate(cs.PeerCertificates[0])
}

// HomeIDFromServerName extracts <id> from an SNI name <id>.home-mandate.net. ASCII case is
// ignored and a trailing dot is dropped; nested labels and every non-ASCII byte are refused
// before any case mapping (so U+212A KELVIN SIGN cannot pose as "k").
func HomeIDFromServerName(name string) (string, error) {
	lower := make([]byte, len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= 0x80 {
			return "", identityErr("non-ASCII server name")
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		lower[i] = c
	}
	id, ok := strings.CutSuffix(strings.TrimSuffix(string(lower), "."), serverSuffix)
	if !ok {
		return "", identityErr("not a home-mandate.net name")
	}
	if err := validHomeID(id); err != nil {
		return "", err
	}
	return id, nil
}

// ALPN is the application protocol both sides must negotiate on every tunnel connection.
const ALPN = "hm-tunnel/1"

// NewTLSConfig returns a fresh tls.Config with the protocol's transport floor: TLS 1.3 only and
// the hybrid post-quantum key exchange X25519MLKEM768 as the only group (both ends are our own
// software, so there is no classical fallback), ALPN hm-tunnel/1 and no session
// tickets (no resumption of client-authenticated sessions). Callers add certificates, the
// peer pool, ClientAuth (the relay uses RequireAndVerifyClientCert) and the server name.
func NewTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		CurvePreferences:       []tls.CurveID{tls.X25519MLKEM768},
		NextProtos:             []string{ALPN},
		SessionTicketsDisabled: true,
	}
}
