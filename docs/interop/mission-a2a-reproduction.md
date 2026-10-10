# Mission A2A Evidence-Review Reproduction

## Result

On 10 October 2026, [Mission / gomission](https://github.com/gomission)
reported running the unchanged VATE A2A evidence starter-06. The report
reproduces the distinction between completing an evidence-review Task and
establishing the original operation's outcome: R52's review completes while
the original effect remains `UNKNOWN`.

## Sources And Package Identity

- [Mission's report in VATE issue #2](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/2#issuecomment-6098586704).
- [Maintainer's response](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/2#issuecomment-6100562822).
- [Guide at the contributor's cited commit](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/blob/f4d69176af79a684b42294f2ae05092f1efb89a2/docs/a2a/evidence-reproduction.md).
- [Published package identity](../a2a/evidence-reproduction.package.json).

The reported SHA-256 matches the published `vate-a2a-evidence-starter-06.zip`:

```text
ec9b2286a18f5500f10a10281dfe6e2620b9aa31b5045ce0748bb89c8308fd31
```

The bundled source pins are VATE
`2348fe12870acc0d6821a47e3b10f49655d5aadb` and A2A proto
`afda8316c64951a2ecb2a0d3d10867405d2b4095`. The guide commit identifies the
instructions, not a newer version of the bundled implementation.

## Contributor-Reported Execution

Mission describes an AI-assisted run on macOS arm64 with Python 3.14.6,
Node.js 22.23.2 and the exact package locks, without optional Python format
extras. These commands reportedly exited 0:

```sh
.venv/bin/python -I -B starter.py check
.venv/bin/python -I -B starter.py run --name mission-20261010-01
.venv/bin/python -I -B starter.py verify-run --name mission-20261010-01
.venv/bin/python -I -B test_digest_basis.py
```

| Case | Review Task | Assessment | Original effect | Retry guidance |
| --- | --- | --- | --- | --- |
| R17 | `completed` | `CONFIRMED_SUCCESS` | `OBSERVED_LOCAL_BYTES` | `DO_NOT_REPEAT` |
| R52 | `completed` | `INDETERMINATE` | `UNKNOWN` | `QUERY_SAME_ATTEMPT` |
| R86 | `completed` | `INCOMPLETE` | `REPORTED_ONLY` | `QUERY_SAME_ATTEMPT` |

The live run reportedly passed 23 boundary probes and created three review
Tasks with three recipient evaluations. Its lost-`GetTask` probe recovered
R52 without another evidence fetch or evaluation. Saved-run verification
reportedly recomputed the assessments from 131 received files, reconciled
49 requests and checked 36 delivered RPC shapes. Both digest-basis regressions
passed according to the report.

`QUERY_SAME_ATTEMPT` is guidance about the original operation. Recovering its
review Task neither queries nor repeats that original operation. Saved-run
verification does not independently re-establish all 23 live probes or the
runtime no-refetch observation.

## Source Correspondence And Scope

The VATE maintainer checked the reported package hash and source pins against
the published descriptor, and the reported outcomes against the guide. Mission's
saved-run artifacts were not supplied or independently reverified for this
record; the maintainer did not rerun Mission's execution.

This is an external contributor's reproduction of the supplied single-operator,
one-process loopback example with historical inputs. It is not an independently
implemented VATE SUT, an exchange between different A2A implementations, or
validation of issuer signatures, durable recovery or production operation.
The report does not exercise Mission's own Trust Graduation implementation.

## Acknowledgement

Thanks to [Mission / gomission](https://github.com/gomission) for reproducing
the published package and returning its environment, commands and case results,
including the distinction between live observations and saved verification.
