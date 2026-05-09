# A2A Issue Update Draft

This is a concise update draft for an A2A-adjacent discussion after the v0.2
AL2 admission artifacts became runnable.

It must be reviewed and edited for the specific venue before posting.

## Suggested Comment

Since the earlier VATE v0.2 discussion draft, I narrowed the proposal to a
metadata-only A2A-oriented community profile and added the current AL2 v0.2
corpus plus an external SUT comparison path.

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

For external implementation review, the primary path is `compare`:

```bash
python3 scripts/vate_conformance.py compare \
  --corpus-root conformance/al2-vate-v0.2 \
  --sut-results examples/conformance/sut-results-pass.example.json \
  --report /tmp/vate-sut-compare-report.json \
  --implementation-report /tmp/vate-sut-implementation-report.json \
  --conformance-report-uri https://example.invalid/vate/reports/vate-sut-compare-report.json \
  --implementation-report-uri https://example.invalid/vate/reports/vate-sut-implementation-report.json
```

The `example.invalid` report URI values above are placeholders. Before sharing
an implementation report, replace them with stable URIs under the implementer's
control, or omit implementation-report generation from the posted command.

The resulting local report bundle can be checked with:

```bash
python3 scripts/vate_conformance.py verify-bundle \
  --corpus-root conformance/al2-vate-v0.2 \
  --sut-results examples/conformance/sut-results-pass.example.json \
  --conformance-report /tmp/vate-sut-compare-report.json \
  --implementation-report /tmp/vate-sut-implementation-report.json \
  --report /tmp/vate-report-bundle-verification.json
```

For a repository fixture sanity check, the reference runner can still be
exercised with:

```bash
python3 scripts/vate_conformance.py run \
  --corpus-root conformance/al2-vate-v0.2 \
  --report /tmp/vate-reference-run.json
```

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
- Replace local `/tmp/` report paths with durable links only if those files are intentionally published.
- Keep the issue comment focused on A2A extension compatibility, not business positioning.
- Confirm the repository owner has reviewed the exact text before posting.
