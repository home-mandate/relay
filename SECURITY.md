# Security

## Reporting vulnerabilities

Please do **not** use public issues. Report privately through GitHub's private vulnerability
reporting ("Report a vulnerability" under the Security tab of this repository), or to
security@home-mandate.org. We acknowledge within 72 hours and disclose in a coordinated manner.

## Scope

This repository holds the tunnel protocol between the Home-Mandate gateway (in the home) and the
relay (in the cloud), and the Go package that implements its wire format. The protocol is designed
so that the relay never sees plaintext traffic: TLS of the agent connection ends in the gateway.
The security considerations of the protocol are in `docs/tunnel-protocol-v1.md`.

## Rules for contributions

- Every decoder rejects malformed input with an error; it never panics, and it never allocates
  based on a length it has not validated.
- Never write stream tokens, certificates or private keys to a log.
- The default is to refuse. Whatever is not explicitly allowed by the specification is an error.
- New dependencies only with a justification in the pull request.
