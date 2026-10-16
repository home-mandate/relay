// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tunnel implements the wire format and the security-relevant helpers of the
// Home-Mandate tunnel protocol v1 (see docs/tunnel-protocol-v1.md): frames and messages with
// strict validation, version negotiation, one-time stream tokens, PROXY protocol v2 headers and
// the SPIFFE and server-name identity rules. It contains no network server.
//
// Every decoder treats its input as hostile: it validates lengths before allocating, rejects
// trailing bytes and non-canonical encodings, and returns an error instead of guessing.
package tunnel
