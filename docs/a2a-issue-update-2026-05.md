# A2A Issue Update Draft

This is a concise update draft for an A2A-adjacent discussion after the v0.2
AL2 admission artifacts became runnable.

It must be reviewed and edited for the specific venue before posting.

## Suggested Comment

Since the earlier VATE v0.2 discussion draft, I narrowed the proposal to a
metadata-only A2A-oriented community profile and added the current AL2 v0.2
corpus plus an external SUT comparison path.

This is not an official A2A extension proposal and does not require A2A core
changes.

The current boundary is:

- A2A carries task flow and optional digest-bound references in metadata.
- VATE defines a verifier-side admission decision for risky external digital actions.
- The full admission request, policy semantics, attenuation, and receipts stay outside A2A core.
- The profile does not require A2A state-machine changes.

The shortest review path is:

- A2A review package: `docs/a2a/README.md`
- A2A extension profile draft: `docs/a2a/vate-a2a-extension-profile-v0.2.md`
- A2A metadata binding: `docs/a2a-metadata-binding-v0.2.md`
- A2A v1.0 extension sketch: `docs/a2a-v1-extension-sketch-2026-05.md`
- A2A maintainer brief: `docs/a2a-maintainer-brief-v0.2.md`
- Runnable conformance corpus: `conformance/al2-vate-v0.2/`
- External SUT quickstart: `docs/conformance/external-sut-quickstart.md`
- SUT result comparison contract: `docs/conformance/sut-adapter-contract.md`
- Report-bundle integrity guidance: `docs/conformance/report-integrity.md`
- Package-private TypeScript helpers: `packages/vate-core-ts/README.md` and
  `packages/vate-a2a-ts/README.md`

For external implementation review, the primary path is `compare`, documented
in `docs/conformance/external-sut-quickstart.md`.
Repository fixture checks still use `run`, and local report-bundle integrity
checks use `verify-bundle`.

The question for A2A maintainers remains intentionally narrow:

> Is this metadata-only, by-reference admission and receipt pattern compatible
> with the A2A extension model, or should it remain entirely as an adjacent
> community profile?

Either outcome is acceptable for the draft.
The goal at this stage is to keep the boundary reviewable and avoid pushing
verifier policy, identity, payment, or receipt-storage semantics into A2A core.

## Local Checklist Before Posting

- Run `python3 scripts/check_repo.py`.
- Confirm `compare` passes against the example SUT result and the current corpus
  snapshot.
- Confirm `verify-bundle` passes for any report bundle intended for publication.
- If mentioning TypeScript, keep it framed as package-private helper code, not a
  published SDK or A2A middleware package.
- Do not post local `/tmp/` report paths or placeholder report URIs. Include
  implementation-report URIs only when stable public artifacts already exist.
- Keep the issue comment focused on A2A extension compatibility, not business positioning.
- Confirm the repository owner has reviewed the exact text before posting.
