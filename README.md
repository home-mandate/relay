# Home-Mandate relay

Specification and Go package for the **tunnel protocol** between the Home-Mandate gateway (in the
home) and the Home-Mandate Cloud relay. Public repository, AGPL-3.0-or-later.

**Status: in development.** Protocol v1 is a draft; nothing here is released or deployed.

- `docs/tunnel-protocol-v1.md` is the specification: one persistent mutually authenticated TLS 1.3
  control connection per gateway, plus one new outbound data connection per agent connection,
  with a PROXY protocol v2 header at the start of each forwarded stream.
- `tunnel/` is the Go package `github.com/home-mandate/relay/tunnel` (standard library only):
  frame and message encoding with strict validation, version negotiation, one-time stream tokens,
  PROXY v2 header encoding and parsing, SPIFFE and server-name identity helpers. The gateway
  imports it. The relay server itself is not part of this repository yet.

## Checks

Go 1.27.2 is required. Tools are pinned in the `Makefile` and fetched with `go run`.

```sh
make hooks                          # once: gitleaks on staged changes before every commit
make check                          # everything below except fuzz
make vet cover vulncheck actionlint # the quick set
make fuzz FUZZTIME=15s              # every fuzz target, 15 seconds each
```

Coverage must stay at or above 80 % (the target for the `tunnel` package is 85 %).

## Security

See `SECURITY.md` and the security considerations in the specification.
