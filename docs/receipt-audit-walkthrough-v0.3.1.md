# Receipt Audit Walkthrough v0.3.1

## Status

This is a reviewability note for the `VATE-AL2-Verifier-Admission-v0.3`
discussion draft.

It does not define a production receipt storage service, a certification
program, or a production signature profile. It explains how an auditor or
implementer can follow digest-bound VATE receipt references in the current
review package.

## What Is Being Audited

The audit target is one verifier-side admission decision and any linked
post-execution evidence for the same transaction.

The useful starting points are:

- A2A metadata carrying a VATE artifact reference;
- a SUT result entry submitted for `compare`;
- a conformance report and implementation report bundle;
- a deployment-controlled artifact bundle published by an implementer.

In all cases, a reference is review-critical only when it carries:

- `uri`;
- `media_type`;
- `digest.alg`;
- `digest.value`.

The URI tells the reviewer where the artifact is expected to be found. The
digest identifies the artifact that was evaluated. A mutable URI without a
digest is discovery metadata, not AL2 review evidence.

## Retention Model

VATE does not require one global receipt store.

For the current AL2 review package, any of these deployment patterns can be
valid when they preserve digest-bound reviewability:

- the verifier stores admission receipts;
- a broker stores admission and post-execution receipts for the transaction;
- a runtime or agent stores post-execution receipts and links them to the
  admission receipt;
- an implementer publishes a controlled artifact bundle for external SUT review.

Independent review should prefer maintainer-controlled origins, release assets,
content-addressed bundles, or signed release material. Local paths, temporary
uploads, or copied repository fixtures are not enough by themselves to prove that
an external SUT produced the referenced artifacts.

## Audit Path

1. Start from the submitted metadata, SUT result, or implementation report.
2. Find the `admission_receipt` artifact reference.
3. Fetch or locate the referenced admission receipt artifact according to local
   dereference policy.
4. Check that the fetched bytes match `digest.alg: "sha-256"` and the expected
   lowercase hex digest.
5. Check the media type and parse the artifact as a VATE admission receipt.
6. Read the admission receipt `verifier`, `request`, `subject`, `evidence`,
   `policy`, and `decision` blocks.
7. If `decision.outcome` is `attenuate`, verify that the receipt carries
   `attenuation.original_request_hash`, `attenuation.effective_request_hash`,
   canonical `attenuation.effective_constraints`, and
   `attenuation.require_new_permit`.
8. Resolve any digest-bound `policy_snapshot` or evidence references needed for
   the review. VATE records those references; it does not replace the adjacent
   protocol's own validation rules.
9. If a post-execution receipt exists, check its `admission.receipt_id`,
   `admission.uri`, `admission.digest`, and `admission.decision` against the
   admission receipt.
10. Check `execution.transaction_id`, `execution.runtime`,
    `execution.effective_request_hash`, and execution timing against the
    admitted receipt.
11. Compare side effects and policy violations against the admitted effective
    constraints. For `max_amount`, the AL2 corpus treats the value as an
    aggregate cap across amount-bearing side effects.
12. If an implementation report is published, verify that its conformance report
    digest, SUT result digest, corpus digest, summary, and case projection match
    the files in the bundle.

`scripts/vate_conformance.py verify-bundle` performs the local digest-chain
checks among corpus, SUT result, conformance report, and implementation report.
It does not fetch remote URIs, prove origin control, or verify external
signatures.

## Trust And Proof Boundary

The current conformance runner checks dependency-free fixture semantics for
trust-bundle binding and detached JOSE proof inputs. It does not perform
production JOSE, PKI, DID, Sigstore, or certificate path validation.

A production deployment must still define:

- accepted proof formats and algorithms;
- issuer metadata and key discovery;
- status and revocation source priority;
- key rollover behavior;
- dereference policy for receipt and evidence URIs;
- external proof or release signing requirements for published bundles.

Passing `compare` or `verify-bundle` means only that the submitted files matched
one corpus snapshot under the stated comparison rules. It does not imply
production readiness, endorsement, certification, or future compatibility.
