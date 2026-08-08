# Security Policy

This repository is an early protocol draft plus a non-production reference demo.

## Scope

The current repository is intended for:

- protocol design discussion
- example payloads and schemas
- educational verification flows

The current repository is **not** intended for:

- direct production deployment
- safety-critical control
- handling real secrets or regulated workloads without further hardening

## Reference Demo Warning

The `reference/minimal-al2-demo` implementation is educational.

It intentionally does **not** claim:

- production-grade JOSE interoperability
- hardware attestation
- full federation security
- hardened key management

Do not treat the demo as a drop-in security component.

## Reporting

For non-sensitive issues, open a normal GitHub issue.
For anything that would expose real secrets, credentials, production exploit details, or a live attack path:

- do not post the raw material publicly
- use [GitHub private vulnerability reporting](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/security/advisories/new), which is enabled for this repository; or
- email `vate@rognalia.com`

The canonical RFC 9116 security contact URL is <https://vate.rognalia.com/.well-known/security.txt>.
