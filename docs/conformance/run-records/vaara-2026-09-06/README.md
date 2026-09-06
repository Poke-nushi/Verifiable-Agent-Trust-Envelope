# Vaara: one-case partial external SUT run

Vaara at `4459c4614d5a978de6d311bc7735085f33c3938a` denied a grant when its
revocation registry was 301 seconds old and the configured freshness bound was
300 seconds. Its native result was `ok=False`, `reason='revocation_stale'`.
VATE's maintainer replayed the two unchanged scripts on 6 September 2026:
all 3 TTL assertions and 13 freshness/admission assertions passed, and the
10 native verdicts and 3 registry controls matched the Vaara maintainer's report.

This is a solicited, candidate-reported native evaluation with VATE-maintainer
replay and VATE-side result formatting. It covers one partial VATE case;
the comparison retains reason-code differences and unevaluated checks. It
does not establish full-corpus conformance, organic adoption, endorsement or
production approval.

## Sources and fixed inputs

- [Vaara maintainer's report and mapping](https://github.com/vaaraio/vaara/discussions/502#discussioncomment-18307758)
- [Unchanged scripts at the evaluated commit](https://github.com/vaaraio/vaara/tree/4459c4614d5a978de6d311bc7735085f33c3938a/scripts/vate-al2)
- VATE `v0.4.0`, commit `cc072ef86f54791213a3e603a65b2f24f64b1b6d`:
  76 corpus cases and 216 manifest artifacts.
- Corpus digest: `b2a281e372b2e1d6b49be219c715fa69c0b2be237d29a6e1f0dda9c0659b6130`.
- Case: `deny-status-stale-just-over-boundary`.
- [Consumed status context](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/blob/cc072ef86f54791213a3e603a65b2f24f64b1b6d/conformance/al2-vate-v0.3/fixtures/status-stale-just-over-boundary-context.json),
  raw SHA-256 `5045e9bcf3711e2de9431d50befb03662c0c868988dcccd616d2392375a545b2`.

The Vaara version string is `1.80.0`; the full commit above identifies the
implementation used here. The earlier `a8b0705` report stopped at registry
observation. Freshness rejection was subsequently added in
[PR #660](https://github.com/vaaraio/vaara/pull/660), and forwarding through
the Gateway/emitter/CLI in [PR #662](https://github.com/vaaraio/vaara/pull/662).
[PR #669](https://github.com/vaaraio/vaara/pull/669) saved the rewritten scripts.

## Native results and mapping

| Observation | Native result |
| --- | --- |
| Registry exactly 300 seconds old | `fresh` |
| Registry 301 seconds old | `stale` |
| Registry without `as_of` | `unknown` |
| `verify_grant`, 301 seconds old with a 300-second bound | `False`, `revocation_stale` |
| `verify_grant`, exactly at the bound | `True`, `ok` |
| `verify_grant`, no configured bound | `True`, `ok` |
| TTL bridge, one second beyond lifetime, skew 0 / 30 | `False`, `expired` / `True`, `ok` |
| Real-clock Gateway, old registry, no bound / bound 300 | `True`, `ok` / `False`, `revocation_stale` |
| Real-clock Gateway, expired short-lived grant, skew 0 / 30 | `False`, `expired` / `True`, `ok` |

For the submitted case, the native refusal maps to `outcome: deny` and
`should_execute: false`; the sole native reason remains `revocation_stale`.
The [projection script](project_replay.py) reads that verdict from the saved
reviewer output. It neither executes Vaara nor reads an expected receipt.

The fixture's `source_issued_at` sets registry `as_of`, test-grant `iat` and
the fixed credential clock. `checked_at` is passed separately as
`revocation_now`, while `max_age_seconds` sets the freshness bound and the
test-grant lifetime. This split clock keeps credential expiry from masking
the registry-freshness check. The HS256 key, tool, tenant, arguments and known
binding digest are test scaffolding; the grant's timing fields are VATE-derived.

`required` remains unmapped. Source `availability` and artifact `status: active`
were not evaluated. Vaara's registry speaks about the grant issuer and key;
their relationship to the VATE status-source subject and authority remains
unresolved. TTL, registry and Gateway controls are auxiliary observations.
The Gateway controls use a real clock and do not test the exact one-second
boundary or invoke an upstream tool.

## Replay environment and artifacts

| | Candidate report | VATE-maintainer replay |
| --- | --- | --- |
| Python | CPython 3.12.13 | CPython 3.12.14 |
| Platform | Linux aarch64 | macOS 26.5.2 arm64 |
| Optional dependencies | Exact versions not supplied | `rfc8785 0.1.4`, `cryptography 50.0.1`, `cffi 2.1.1`, `pycparser 3.0`; `cbor2` absent |

The replay verified 231 source-file hashes before and after execution, the
fixture digest, and the imported Vaara module locations. The original
candidate stdout/stderr files were not supplied; the saved outputs below
come from the reviewer replay. This reproduces the reported verdicts, not
the candidate's exact environment.

- [TTL stdout](ttl_bridge.stdout.txt) and [stderr](ttl_bridge.stderr.txt)
- [Freshness/admission stdout](freshness_admission.stdout.txt) and [stderr](freshness_admission.stderr.txt)
- [Replay metadata, dependency versions, script hashes and per-assertion results](replay.json)
- [SUT result](sut-results.json), [comparison](compare-report.json),
  [implementation report](implementation-report.json), and [bundle verification](bundle-verification.json)
- [Artifact SHA-256 manifest](MANIFEST.json)

To rerun the native checks, use the fixed Vaara checkout and VATE fixture
above with the recorded reviewer dependencies. From that Vaara checkout,
with its `src` and the dependency directory on `PYTHONPATH`, run:

```sh
python3 -B scripts/vate-al2/ttl_bridge.py /path/to/status-stale-just-over-boundary-context.json
python3 -B scripts/vate-al2/freshness_admission.py /path/to/status-stale-just-over-boundary-context.json
```

The commands create temporary test attestation/grant files; the Gateway
controls wait two seconds on the real clock. The scripts reject a fixture
digest mismatch. The saved stdout/stderr files are byte-unmodified; metadata
uses portable paths in place of machine-specific executable and directory
prefixes.

## VATE comparison

The fixed `v0.4.0` runner returns exit `1`. The submitted case agrees on
`deny` and `should_execute: false`, with four comparison failures:

- native `revocation_stale` differs from `STATUS_STALE, FAIL_CLOSED`;
- the primary reason consequently differs;
- `decision.outcome` has no submitted named check;
- `evidence.verification.failure_reason` has no submitted named check.

Matching `outcome` does not supply the separate named `checks[]` entries
described in the [SUT contract](../../sut-adapter-contract.md#check-semantics).

The other 75 cases have no submitted result. Thus `0 passed / 76 failed`
means one partially evaluated case with differences plus 75 unexecuted cases,
not 76 failed Vaara executions. All three report schemas validate;
`verify-bundle` passes 54/54 local consistency checks. Read the SUT result,
replay metadata and this record with the generated implementation report,
which omits the custom provenance and detailed limitations.

The following uses the saved native output to rebuild the SUT result and
compare it with a separate VATE checkout at `cc072ef`. `VATE_CHECKOUT` names
that checkout. Copy this record directory to
`docs/conformance/run-records/vaara-2026-09-06` inside it so the runner emits
portable repository-relative paths; run from that copied directory:

```sh
python3 -B project_replay.py
python3 "$VATE_CHECKOUT/scripts/vate_conformance.py" compare \
  --corpus-root "$VATE_CHECKOUT/conformance/al2-vate-v0.3" \
  --sut-results sut-results.json --report compare-report.json \
  --implementation-report implementation-report.json \
  --conformance-report-uri compare-report.json
python3 "$VATE_CHECKOUT/scripts/vate_conformance.py" verify-bundle \
  --corpus-root "$VATE_CHECKOUT/conformance/al2-vate-v0.3" \
  --sut-results sut-results.json --conformance-report compare-report.json \
  --implementation-report implementation-report.json \
  --report bundle-verification.json
```

Regenerated reports contain a new generation time and therefore have new
digests; the saved manifest identifies the original files in this record.
