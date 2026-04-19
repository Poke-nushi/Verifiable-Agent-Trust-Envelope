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

This repository does not yet publish a dedicated security email address.

For non-sensitive issues, open a normal GitHub issue.
For anything that would expose real secrets, credentials, production exploit details, or a live attack path:

- do not post the raw material publicly
- prefer GitHub private vulnerability reporting if it is enabled for the repository
- maintainers should enable GitHub private vulnerability reporting before broad public release
- otherwise contact the repository owner privately before disclosure

Until a dedicated channel exists, treat private coordination as preferred for anything that would materially help an attacker.
