# A2A Issue Update Draft

This is a concise update draft for an A2A-adjacent discussion after the v0.2 AL2 admission artifacts became runnable.

It should be edited for the specific venue before posting.

## Suggested Comment

Since the earlier VATE v0.2 discussion draft, I narrowed the proposal to a metadata-only adjacent profile and added runnable artifacts.

The current boundary is:

- A2A carries task flow and optional digest-bound references in metadata.
- VATE defines a verifier-side admission decision for risky external digital actions.
- The full admission request, policy semantics, attenuation, and receipts stay outside A2A core.
- The profile does not require A2A state-machine changes.

New reviewable artifacts:

- AL2 admission interop profile: `docs/profiles/vate-al2-admission-interop-profile-2026-07.md`
- A2A metadata binding: `docs/a2a-metadata-binding-v0.2.md`
- A2A v1.0 extension sketch: `docs/a2a-v1-extension-sketch-2026-05.md`
- A2A maintainer brief: `docs/a2a-maintainer-brief-v0.2.md`
- Runnable conformance corpus: `conformance/al2-vate-v0.2/`
- Dependency-free runner: `scripts/vate_conformance.py`
- Dependency-free verifier core: `reference/vate-verifier-core/`
- A2A-shaped adapter demo: `reference/a2a-metadata-adapter-demo/`
- SUT result comparison contract: `docs/conformance/sut-adapter-contract.md`
- OAP / APort evidence crosswalk: `docs/interop/oap-aport-crosswalk.md`
- AP2 Human Not Present evidence fixtures: `docs/interop/ap2-human-not-present-evidence.md`

The runner can be exercised with:

```bash
python3 scripts/vate_conformance.py run \
  --corpus-root conformance/al2-vate-v0.2 \
  --report /tmp/vate-conformance-report.json \
  --implementation-report /tmp/vate-implementation-report.json
```

External implementation results can be compared with:

```bash
python3 scripts/vate_conformance.py compare \
  --corpus-root conformance/al2-vate-v0.2 \
  --sut-results examples/conformance/sut-results-pass.example.json \
  --report /tmp/vate-sut-compare-report.json
```

The question for A2A maintainers remains intentionally narrow:

> Is this by-reference admission / receipt metadata pattern compatible with A2A's extension model, or should it remain entirely as an adjacent profile outside A2A governance?

Either outcome is acceptable for the draft.
The goal at this stage is to keep the boundary reviewable and avoid pushing verifier policy, identity, payment, or receipt-storage semantics into A2A core.

## Local Checklist Before Posting

- Run `python3 scripts/check_repo.py`.
- Confirm the conformance runner still reports zero failed cases.
- Replace local `/tmp/` report paths with durable links only if those files are intentionally published.
- Keep the issue comment focused on A2A extension compatibility, not business positioning.
