# Home-Mandate tunnel protocol v1

Status: draft, in development. Reference implementation of the wire format: package
`github.com/home-mandate/relay/tunnel` in this repository. The key words MUST, MUST NOT, SHOULD
and MAY are used as in RFC 2119.

## 1. Purpose and design

A Home-Mandate gateway runs in a home, usually behind NAT, and must be reachable by cloud agents
at `https://<id>.home-mandate.net/mcp`. The gateway therefore connects **outbound** to the relay.
The relay forwards the agent's TLS byte stream into the tunnel without looking into it: the TLS
connection of the agent ends in the gateway, the relay never sees plaintext.

Decision (ADR-0015 of Home-Mandate Cloud): no multiplexing. Each gateway keeps

- one persistent **control connection** (handshake, heartbeat, signals), and
- one **data connection per agent connection**, which the gateway dials *outbound* after the relay
  signalled the agent connection over the control connection. A small pool of already
  established, still unused TLS connections hides the extra round trip.

Every agent connection is thus its own TCP/TLS connection: limited, closed and observed one by one.
The relay is a byte copier; flow control belongs to the kernel and to TLS.

## 2. Roles and identities

| Role | Identity | Presented as |
|---|---|---|
| Gateway | `spiffe://home-mandate.com/home/<id>/gateway` | exactly one URI SAN in a short-lived (at most 24 h) client certificate from the Home-Mandate CA |
| Relay | a DNS name, for example `relay.home-mandate.com` | DNS SAN in the server certificate; the gateway verifies it against its configured relay name |

`<id>` is the home ID: exactly 26 characters of lower-case base32 `[a-z2-7]` (130 random bits, see
ADR-0003). The same `<id>` is the first label of the public name `<id>.home-mandate.net`. The
**installation** of a connection is the `<id>` taken from the verified client certificate. It is
never taken from any message.

A certificate is accepted only if it chains to the Home-Mandate CA, is valid now, carries the
client-authentication extended key usage, and its subject alternative name extension holds
**exactly one entry, a URI** that matches the form above byte for byte (lower case scheme and
host, no port, user info, query, fragment, not even an empty `?` or `#`, and no extra path
segment). The check MUST look at the raw bytes of the extension (`tunnel.CheckConnection`,
`tunnel.HomeIDFromCertificate`), because parsed URLs normalize the scheme case and drop an empty
fragment. Any other certificate ends the connection during the handshake.

**Certificate lifetime and revocation (normative).**

- The relay MUST close a control connection when the peer certificate's `NotAfter` passes, and a
  data connection at most 60 s later (`tunnel.Guard`, `DataCertGrace`). The gateway MUST renew
  its certificate before it expires and MUST then reconnect with the new one.
- The relay MUST check a serial denylist at every handshake (`Guard.VerifyConnection`) and MUST
  be able to drop all open connections of a serial that is revoked while they are open
  (`Guard.Revoke`). Denylist entries are kept at least until the certificate's `NotAfter`.

## 3. Transport

- TCP, then TLS **1.3 only**. A peer offering a lower maximum version is refused (no fallback).
- Key exchange: `X25519MLKEM768` (hybrid, post-quantum) is the **only** permitted group. Both
  ends are Home-Mandate software, so there is no classical fallback; a peer that cannot offer
  it is refused. Implementations use `tunnel.NewTLSConfig()`.
- After the handshake both sides MUST run `tunnel.CheckConnection` (TLS 1.3, ALPN, exactly one
  gateway identity) before reading the first frame.
- **Mutual authentication.** The relay requires and verifies a client certificate on every
  connection, control and data. The gateway verifies the relay certificate and name.
- No session resumption or 0-RTT for client-authenticated connections, so that a revoked or
  expired certificate cannot be used again after its validity.
- ALPN `hm-tunnel/1` on both connection kinds (`tunnel.ALPN`); a handshake without it is refused. The first
  frame then tells control (`hello`) from data (`data-bind`).
- The relay listens on one port for both connection kinds (default 8443; deployment decision).

## 4. Framing

### 4.1 Frame format

All integers are big endian. The same framing is used for control messages and for the single
`data-bind` frame at the start of a data connection.

```
+----------------+-------------------+----------------------+
| type (u16)     | payload length    | payload              |
|                | (u16)             | (length bytes)       |
+----------------+-------------------+----------------------+
```

- Type 0 is invalid.
- The payload is at most **1024 bytes** (`MaxPayload`). A frame announcing more is a protocol
  error **decided from the four header bytes alone**: the receiver reads no payload, allocates
  nothing for it and closes the connection.
- A receiver reads a header, validates it, and only then reads exactly the announced payload.
- Every message type has exactly one valid encoding. A receiver rejects trailing bytes inside a
  payload, a non-canonical field and values outside the stated ranges. `decode` followed by
  `encode` returns the same bytes (checked by the fuzz tests).
- A sender writes a frame with a single write.

### 4.2 Type numbers and unknown types

| Range | Class | Rule for a type the receiver does not know |
|---|---|---|
| `0x0000` | invalid | protocol error |
| `0x0001`-`0x00FF` | **core** | defined by this specification; unassigned numbers are a **protocol error** (reject) |
| `0x0100`-`0x7FFF` | **extension, capability-gated** | defined by a capability (see 5.1). Receivers **reject** such a frame (protocol error) unless the capability that defines it was negotiated on this connection. v1 defines no extension types, so every one is rejected |
| `0x8000`-`0xFFFF` | **optional** (high bit set) | unknown ones are **ignored**: the receiver discards the frame (its length was already bounded) and continues |

Capability gating of extension types cannot be done by the frame decoder, which does not know
the negotiated capabilities: the **layer above the decoder** (the relay or gateway session code)
MUST reject an extension-range frame unless its capability was negotiated on this connection.
`tunnel.DecodeControl` rejects all of them, as v1 defines none.

Optional-range frames (`0x8000` and up) MUST NOT change state or carry any security semantics:
nothing may depend on whether one was received or ignored. They are not allowed before the
handshake completed: a receiver that gets one before `hello`/`hello-ack` closes the connection
(`tunnel.DecodeControlIn`).

Consequences:

- A later feature such as `checkpoint.submit` is assigned a number in `0x0100`-`0x7FFF` and a
  capability number. A v1 peer that did not negotiate the capability never accepts the frame, and
  a peer never sends it unless both sides listed the capability in the handshake. v1 stays
  unbroken because nothing changes for peers that do not know the capability.
- Purely informational additions (for example a statistics hint) use the optional range and are
  safe to drop.
- Ignored frames count against the frame-rate limit (section 7); a peer that sends nothing but
  ignored frames is closed.
- Core messages of version 1 never get new fields: a changed layout is a new protocol version.

Assigned types:

| Type | Name | Sender | Connection |
|---|---|---|---|
| `0x0001` | `hello` | gateway | control |
| `0x0002` | `hello-ack` | relay | control |
| `0x0003` | `ping` | either | control |
| `0x0004` | `pong` | either | control |
| `0x0010` | `stream-open` | relay | control |
| `0x0011` | `stream-close` | either | control |
| `0x0012` | `error` | either | control |
| `0x0013` | `drain` | either | control |
| `0x0020` | `data-bind` | gateway | data (first frame only) |

A known type from the wrong sender (`hello` from the relay) or on the wrong connection kind
(`data-bind` on a control connection, anything but `data-bind` first on a data connection) is a
protocol error.

## 5. Control connection

### 5.1 Handshake

1. The gateway dials the relay and completes mutual TLS 1.3 (section 3).
2. The gateway sends `hello` within 5 s after the handshake. The relay sends nothing before.
3. The relay answers `hello-ack`, or `error` (`unsupported-version`) and closes.
4. Nothing but `hello`, `hello-ack`, `ping`, `pong`, `error` is valid before the handshake
   completed; `stream-open` and every other type before `hello-ack` is a protocol error, and so
   is a second `hello` or `hello-ack` afterwards (`tunnel.DecodeControlIn`).

`hello` payload:

| Field | Encoding | Rules |
|---|---|---|
| min version | u8 | at least 1, at most max version |
| max version | u8 | |
| gateway version | u8 length, then ASCII | 1 to 64 bytes of printable ASCII (`0x20`-`0x7E`); informational, never used for decisions |
| capability count | u8 | at most 16 |
| capabilities | count x u16 | non-zero, strictly ascending (no duplicates) |

`hello-ack` payload:

| Field | Encoding | Rules |
|---|---|---|
| version | u8 | the selected version, non-zero |
| relay version | u8 length, then ASCII | 1 to 64 printable ASCII bytes; informational |
| heartbeat interval | u16 seconds | 5 to 120 |
| pool size | u8 | 0 to 16: how many unused (warm) data connections the gateway should keep |
| max streams | u16 | 1 to 256: the most simultaneous agent streams for this installation |
| capability count, capabilities | as in `hello` | the **intersection** of the offered capabilities and those the relay supports |

**Version negotiation (N / N-1).** Each side states the range it supports; the relay selects the
highest version in both ranges (`tunnel.NegotiateVersion`). The relay supports the current version
N and N-1. If the ranges do not overlap, the relay sends `error` `unsupported-version` and
closes. The gateway MUST check that the selected version lies in its own range and that every
returned capability was offered by it, and otherwise close. Version 1 is the only version; both
bounds are 1.

Capability numbers are assigned in later versions of this document; none exists in v1. A
capability is only active if it appears in `hello-ack`.

### 5.2 Heartbeat and timeouts

| What | Value |
|---|---|
| TLS handshake complete | within 10 s of the TCP connection |
| `hello` after the TLS handshake | within 5 s |
| heartbeat interval | `heartbeat interval` of `hello-ack` (default 15 s) |
| silence limit | 3 intervals (default 45 s) without **any** valid frame from the peer: close |
| `pong` | within one interval after the `ping` |
| rest of a frame after its first byte | within 5 s (slowloris) |

Each side sends `ping` (u64 random nonce, one outstanding at a time) when it has sent nothing for
one interval; the peer answers at once with `pong` carrying the same nonce. **Only a `pong` with
the expected nonce within one interval counts as liveness** (`tunnel.Liveness`); other traffic
does not. A missing `pong` is a timeout: the side sends `error` `timeout` and closes. A `pong`
with an unknown nonce, without a `ping`, or a second one for the same `ping` is a protocol
error (`error` `protocol`, close). A peer that answers a `ping` with the right `pong` is
"healthy"; one that missed its `pong` has "missed its heartbeat", which matters for superseding
(5.3).

Receivers apply read deadlines to the connection; there is no read without a deadline. **Every
write has a write deadline of 5 s**, the write of an `error` frame before closing included
(`tunnel.WriteMessageTimeout`, `tunnel.SendFatalError`); when the deadline passes the connection
is closed without further attempts.

### 5.3 Signals

All numbers big endian; a token is 32 bytes (section 6).

- **`stream-open`** (relay to gateway): `token (32) | valid for ms (u16, 1..10000)`. An agent
  connection is waiting; the gateway MUST bind a data connection with this token within the stated
  time. The relay sends it only after `hello-ack`, never above the stream limit, and not after
  `drain`.
- **`stream-close`** (either): `token (32) | reason (u8)`. Reasons: 1 agent gone, 2 refused, 3
  timeout, 4 internal. The relay sends it to withdraw a signal (the agent gave up before the
  gateway dialed); the gateway sends it to refuse a signal (it will not serve this stream). Either
  way the token is void. Neither ends the control connection. A `stream-close` for an unknown
  token is ignored.
- **`error`** (either): `code (u16, non-zero) | text length (u8) | text (0..128 printable
  ASCII bytes)`. Codes: 1 unsupported version, 2 malformed, 3 unknown type, 4 limit exceeded, 5
  unauthorized, 6 timeout, 7 internal, 8 superseded, 9 protocol, 10 session exists. Receivers accept any non-zero
  code. `error` is **fatal**: the sender closes the connection right after writing it; the
  receiver closes on reading it. The text is for logs; it never contains tokens, certificates or
  other peer data.
- **`drain`** (either): `reason (u8: 1 shutdown, 2 restart, 3 overload) | grace seconds (u16,
  at most 600)`. The sender asks the peer to start no new streams. A relay drain tells the
  gateway to reconnect to the relay (another instance) after the grace time; open data
  connections may finish within the grace time and are then closed. A gateway drain makes the
  relay stop sending `stream-open` and answer new agent connections itself.

**Superseding (normative).** A new control connection for an installation that already has one
replaces the existing one **only if** (a) the existing one has missed its heartbeat (no matching
`pong` within one interval), **or** (b) the new certificate's `NotBefore` is later than the
existing one's (`tunnel.ShouldSupersede`). Otherwise the **new** connection is refused: the relay
sends `error` `session exists` and closes it. When it supersedes, the relay sends `error`
`superseded` on the old connection, closes it, and discards **all pending stream tokens and all
warm and pooled data connections** of the old session; data connections that are already bound
and streaming end with their stream. This clears half-open connections after a network change
without letting a second holder of an older certificate push out the real gateway.

Control connects are rate limited **per certificate serial and source address** (IPv6 by /64;
`tunnel.RateKey`, `tunnel.Limiter`), not per installation, so that an attacker cannot lock the
real gateway out by connecting often from elsewhere. Exceeding the limit MUST raise an alarm in
the relay's monitoring (the limiter's callback), in addition to refusing the connect.

## 6. Data connections

### 6.1 Binding to a signal

1. The relay accepts an agent connection for `<id>` (SNI, taken from the TLS ClientHello without
   terminating TLS) and asks the token store for a token bound to the installation `<id>`
   (`TokenStore.Issue`; at most 16 unredeemed tokens per installation, valid for **10 s**).
2. The relay sends `stream-open` on the control connection of that installation.
3. The gateway uses an unused warm data connection or dials a new one (mutual TLS 1.3, ALPN as in
   section 3) and sends one `data-bind` frame: `token (32)`. Nothing else is sent first.
4. The relay reads the frame (`ReadDataBind`: at most 36 bytes, never more). It checks the stream
   limit and the pool limit of the installation **before** it redeems the token, so a refusal for
   a full installation does not consume a token. It then redeems the token
   (`TokenStore.Redeem`) with the installation `<id>` of the **client certificate of this data
   connection**. The token is single use: the first presentation consumes it, successful or not.
5. On success the relay writes the PROXY v2 header (6.2) and then forwards the agent's bytes in
   both directions without change. The gateway reads and checks the PROXY header, then treats the
   rest as the agent's TLS connection.

The relay rejects the data connection **silently**, by closing it without any reply, in every
one of these cases: the first frame is not a well-formed `data-bind`; the token is unknown,
already used, cancelled or expired; the token belongs to another installation (the token is
burned); the installation has no control connection; the stream limit or the pool limit is
reached. A silent close gives an attacker no oracle for which tokens exist. (Details go to the
relay's log without the token.)

A **gateway whose bind failed** (the relay closed the data connection, or the connection could
not be established) MUST back off: 1 s after the first failure, doubling to at most 30 s while
failures continue, with random jitter of up to one half, reset by the first successful bind. It
makes at most 3 attempts for one `stream-open` and then sends `stream-close` `refused`. A
`stream-close` that cancels a token is honoured only for tokens of the installation of the
control connection it arrives on (`TokenStore.Cancel` takes the installation).

A **warm** data connection is a TLS connection that has completed the handshake but has not yet
sent `data-bind`. The relay holds at most `pool size` of them per installation, closes any that
sends nothing within **30 s** after the handshake and counts them against the connection limits.
The gateway SHOULD replace warm connections after 25 s. The wait for `data-bind` is the only
case where a data connection may be silent; once the first byte of the frame arrives the rest
must follow within 5 s.

### 6.2 PROXY protocol v2 header

The relay writes, as the first bytes of the relay-to-gateway direction of every bound data
connection, a PROXY protocol v2 header with the agent's address as the relay's listener saw it
(`tunnel.EncodeProxyV2`). Only this exact form is valid:

| Offset | Size | Value |
|---|---|---|
| 0 | 12 | signature `0D 0A 0D 0A 00 0D 0A 51 55 49 54 0A` |
| 12 | 1 | `0x21` (version 2, command PROXY). `LOCAL` and other versions are refused |
| 13 | 1 | `0x11` (TCP over IPv4) or `0x21` (TCP over IPv6). `UNSPEC`, UDP and UNIX are refused |
| 14 | 2 | address block length: exactly 12 (IPv4) or 36 (IPv6). **No TLVs**; any other length is refused |
| 16 | 12 or 36 | source address, destination address, source port, destination port |

Additional rules: both addresses have the same family; ports are not 0; no address is
unspecified; the source is not multicast; no zone; IPv4-mapped IPv6 addresses are written as
IPv4 and refused inside an IPv6 block (one canonical form). The gateway reads exactly the 16
fixed bytes and then the announced block, never more, so no byte of the TLS stream is consumed.
A gateway that sees anything else as the first bytes closes the connection.

The gateway trusts this header **only** on data connections that it dialed itself, authenticated
with the relay's certificate, and bound by its own token. It never accepts a PROXY header on any
other listener. The agent's address serves rate limits and logs. The gateway MUST NOT use it for
any decision about locality or trust (for example "request comes from the LAN"), and MUST apply
`ProxyHeader.CheckGatewaySource`, which refuses loopback, private, link-local, "this network" and
broadcast sources: a remote agent must not be able to look local, even through a forged header.

The destination fields carry no information. The relay MUST write a documentation address of
the agent's family (`192.0.2.1:443` or `[2001:db8::1]:443`, `tunnel.ProxyDestinationFor`), so the
header does not reveal the relay's addressing, and the gateway MUST ignore it.

A relay behind a load balancer or another proxy that hides the agent's address is **out of scope
for v1**: the relay MUST see the agent's real address on the TCP connection it accepts.

### 6.3 Raw bytes, idle and end

After the PROXY header, both directions carry opaque bytes. Either side closes with a normal TCP
close; a half close is propagated (the relay closes its write side towards the gateway when the
agent finished sending, and the other way round). A stream with no byte in either direction for
the idle time (relay setting, default 10 min) is closed by the relay. The control connection is
not involved in the end of a stream.

## 7. Limits

All limits are checked **before** memory is allocated for the item they bound.

| Limit | Value |
|---|---|
| frame payload | 1024 bytes (`data-bind`: exactly 32) |
| version, error text | 64 and 128 bytes |
| capabilities per message | 16 |
| control connections per installation | 1 (a new one supersedes, section 5.3) |
| new control connections per certificate serial and source (IPv6 /64) | 6 per minute, then refused until the minute is over; exceeding it raises an alarm |
| simultaneous agent streams per installation | `max streams` of `hello-ack`, default 64, never above 256 |
| warm (unbound) data connections per installation | `pool size`, default 4, never above 16 |
| unredeemed tokens per installation | 16, valid 10 s |
| new data connections per installation | 20 per second (burst 40); beyond that the relay closes at once |
| frames per second per control connection | 20 (burst 40), ignored frames included |
| handshake and unauthenticated connections, **control and data** | per source address (IPv6 /64) and in total, enforced before the TLS handshake finishes: at most 20 new connections per source per second (burst 40) and 64 half-open handshakes per source; a data connection costs the same as a control connection (`tunnel.Limiter`) |
| entries of the token store | 65536 in total, 16 per installation |
| time limits | section 5.2 and 6.1 |

The values are defaults of the specification; a relay may be stricter but MUST NOT exceed the
maxima. A peer over a limit gets `error` `limit exceeded` (control connection) or a silent close
(data connection) and, if it keeps going, a longer block.

## 8. Errors and fail-closed behaviour

- **Anything not explicitly allowed is an error.** Malformed frame, unknown core or extension type
  (not negotiated), wrong sender, wrong connection kind, value out of range, trailing bytes,
  stalled reads: the receiver sends `error` where possible on a control connection and closes the
  connection. There is no recovery from a framing error, because the byte position is lost.
- Unknown **optional** types are skipped (section 4.2); nothing else is skipped.
- Loss of the control connection ends the installation's routing at once: the relay closes the
  pending tokens and warm connections of that installation and refuses new agent connections with
  a TLS-level close (it does not terminate TLS for the agent). Open data connections may continue
  to their end.
- The gateway keeps working locally without the tunnel. It reconnects with exponential backoff
  (1 s doubling to 60 s, with random jitter of at most one half) and uses a new control
  connection and new tokens; it never reuses a token.
- A certificate that expires or is revoked while a connection is open: the relay closes it as
  specified in section 2 (control at `NotAfter`, data within 60 s). The gateway renews before
  expiry and reconnects.
- Errors visible to an agent are only a closed connection; no detail leaves the tunnel.

## 9. Security considerations

Numbers refer to the Home-Mandate Cloud threat model, sections 2.3 (relay and Traefik) and 2.4
(pairing of home and cloud). C = critical, H = high, M = medium.

| Threat | Priority | Countermeasure in this protocol |
|---|---|---|
| **A foreign gateway claims to be home X** (2.3, S, C) | C | The installation comes only from the single URI SAN of the verified client certificate, on the control and on every data connection. Messages carry no installation. Certificates live at most 24 h. The SPIFFE ID is parsed strictly (one canonical form); anything but one URI SAN is refused, and the raw SAN is checked so that normalizing parsers cannot hide a trailing `#` or an upper-case scheme. |
| **Stolen or stray stream token** (token guessing, token leaked from a log, data connection of another home) | C | 256 random bits from `crypto/rand`; valid 10 s; single use; bound to the installation of the redeeming certificate; redeemed by hash lookup (the relay stores only SHA-256 of tokens) and compared in constant time; a redemption by the wrong installation burns the token; at most 16 open tokens per installation; tokens never print (`Token` formats as redacted) and MUST NOT be logged. Even a token and a stolen certificate of another home do not help: both must belong to the same installation. |
| **Replay** of a captured `stream-open` or `data-bind` | H | TLS 1.3 protects both on the wire. A replay on a new connection finds the token consumed. Fresh tokens are issued for every agent connection. |
| **Routing table or relay logic manipulated** (2.3, T, H) | H | The relay checks the identity of the data connection against the token's installation, not against any table entry; a manipulated table cannot make a token valid for another certificate. |
| **Frame flooding, memory exhaustion** (2.3, D, H) | H | Frames are at most 1024 bytes and refused from the header alone; per-connection frame rate; ignored frames count; capability count, string and message sizes bounded; per-installation limits on connections, streams, pool and tokens (section 7). |
| **Slowloris, SNI flood, tunnel flood** (2.3, D, H) | H | Deadlines for the TLS handshake, `hello`, a frame's remaining bytes and the wait for `data-bind`; heartbeat silence limit; unauthenticated connection limits before the handshake ends; new-connection rate per installation. |
| **Downgrade** of protocol or cipher | H | TLS 1.3 is the minimum, so there is no older TLS to fall back to; the hybrid group `X25519MLKEM768` is the only one accepted, so a classical downgrade does not exist. Version selection happens inside the authenticated channel, the gateway verifies that the selected version is in its own range, and capabilities that were not offered are not accepted. A peer cannot be talked into a feature it did not list. |
| **Forged sender address through PROXY v2** (2.3, E, M) | M | The header is canonical and strict (no TLVs, no LOCAL, no UDP, no zone). The gateway accepts it only on data connections it dialed to the authenticated relay and bound itself. Accepted residual risk, as in the threat model: a **compromised relay can forge sender addresses**; sender addresses influence limits and logs, never authorization. |
| **Relay opens TLS of the agent** (2.3, I, C) | C | Outside this protocol: TLS of the agent ends in the gateway with the home's own certificate; the relay sees only the ClientHello server name and the byte counts. The protocol passes the stream through unchanged after the PROXY header. |
| **Metadata** (2.3, I, M) | M | The relay learns the home ID, byte counts and the agent's address. The protocol has no field for anything else. |
| **Cloud drops or refuses connections** (2.4, D, M) | M | Fail closed: no tunnel, no remote access; the gateway keeps working locally and reconnects with backoff. |
| **Cloud injects approver keys or mandates** (2.4, T/E, C) | C | The tunnel has no message that carries keys, mandates or approvals, and v1 core messages cannot be extended by an unnegotiated capability. Any later extension that touches such data needs its own review (and ADR-0009 applies: issuer keys never leave the home). |
| **Oracle for token existence** | M | A failed bind is a silent close; control connections never confirm or deny a token. |
| **Compromised gateway certificate** | C | The attacker can serve and receive streams of that home only, for the remaining certificate life. Superseding the real control connection needs a later `NotBefore` or a missed heartbeat of the real one, and connects are rate limited per serial and source with an alarm. The relay closes connections at `NotAfter`, refuses revoked serials at the handshake and drops open connections of a serial revoked later (`Guard`). Rotation and the CA runbook: threat model 2.3, T/E. |
| **Token cancelled or redeemed from another home** | H | `Cancel` and `Redeem` take the installation and compare it in constant time; the wrong installation cannot cancel a token and burns it by redeeming. Limits are checked before `Redeem`. |
| **Optional frames used as covert state or to skip checks** | M | Optional-range frames MUST NOT change state or carry security semantics, are refused before the handshake and count against the frame rate. |
| **Token disclosure through logs or JSON** | M | `Token` redacts itself in `fmt`, `encoding/json`, text encoders and `log/slog`, also as a field of `stream-open`, `stream-close` and `data-bind`. |

Implementation notes for both sides: never log tokens, certificate contents or payload bytes;
treat a failed `ReadFrame`, `DecodeControl` or `ReadProxyV2` as the end of the connection; apply
deadlines before every read; never allocate based on a length before it was validated against
the limits above.

## 10. Conformance

The Go package in `tunnel/` is the reference for framing, messages, tokens, PROXY v2 and identity
rules. Every validation rule in this document has a negative test, and every decoder has a native
Go fuzz test (`make fuzz`). Differences between this document and the package are bugs in one of
them.

## 11. Open points

- Encoding of `<id>`: fixed to 26 characters of lower-case base32 `[a-z2-7]`, matching `installations.public_id` in the cloud database;
  ADR-0003 only says "random, at least 128 bit".
- Capability numbers and the first extension types (for example `checkpoint.submit`) are assigned
  when the feature is specified.
- Port and deployment of the relay listener, and the idle time of streams, are deployment choices.
