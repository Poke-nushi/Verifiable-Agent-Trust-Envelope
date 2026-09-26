# HandoffProbe A2A Evidence-Review Reproduction

## Result

On 25 September 2026, HandoffProbe maintainer
[Heaviside479](https://github.com/Heaviside479) reported reproducing the fixed
VATE A2A evidence-review package. The reported R52 result keeps the
evidence-review Task completed while the original operation's effect remains
unknown. This records an external contributor's reproduction of the published
example.

## Fixed Sources

- [Result returned to VATE issue #2](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/2#issuecomment-5837858177).
- [HandoffProbe reproduction record at `6cb2267e`](https://github.com/Heaviside479/handoffprobe/blob/6cb2267e8b14f15294cf8187c40410c45d28da18/docs/VATE_A2A_EVIDENCE_REPRODUCTION_20260925.md).
- VATE instructions at `b847004c683de0ed81c7ee5a78d5342b82930fb8`:
  [guide](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/blob/b847004c683de0ed81c7ee5a78d5342b82930fb8/docs/a2a/evidence-reproduction.md)
  and [package identity](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/blob/b847004c683de0ed81c7ee5a78d5342b82930fb8/docs/a2a/evidence-reproduction.package.json).

The reported download matches the published identity:

- Archive: `vate-a2a-evidence-starter-06.zip`
- Size: 234,820 bytes
- SHA-256:

```text
ec9b2286a18f5500f10a10281dfe6e2620b9aa31b5045ce0748bb89c8308fd31
```

The guide commit identifies the instructions. The package identity separately
pins its bundled VATE source to
`2348fe12870acc0d6821a47e3b10f49655d5aadb` and lists its A2A and historical
fixture sources.

## Reported Execution

The contributor records Python 3.13.15, Node.js v24.17.0 and npm 11.13.0 in a
local POSIX environment. These commands each returned exit code 0 and `PASS`:

```sh
python -I -B starter.py check
python -I -B starter.py run --name handoffprobe-20260925T183006Z
python -I -B starter.py verify-run --name handoffprobe-20260925T183006Z
```

| Case | Reported assessment | Reported effect | Retry guidance |
| --- | --- | --- | --- |
| R17 | `CONFIRMED_SUCCESS` | `OBSERVED_LOCAL_BYTES` | `DO_NOT_REPEAT` |
| R52 | `INDETERMINATE` | `UNKNOWN` | `QUERY_SAME_ATTEMPT` |
| R86 | `INCOMPLETE` | `REPORTED_ONLY` | `QUERY_SAME_ATTEMPT` |

The live exchange reportedly completed 23 boundary probes. Saved-run
verification reportedly reconciled 72 request/response pairs, rechecked 131
received files and recomputed the three assessments.

R52 illustrates why recovery of a known review Task must preserve the original
operation's uncertainty. In this package, `QUERY_SAME_ATTEMPT` is guidance for
the original operation; retrieving the review Task does not query or execute
the original provider operation. The [reproduction guide](../a2a/evidence-reproduction.md)
explains the live recovery probe and saved-run checks.

## Source Correspondence And Scope

For this record, the VATE maintainer checked the contributor's stated package
size and SHA-256 against the fixed published identity, and the reported
outcomes against the guide. The contributor's saved-run files were not
retrieved or reverified, and the VATE maintainer did not rerun the package for
this record. `verify-run` does not independently reconstruct all 23 live
boundary probes or the no-refetch observation.

The contributor used the package's one-process, single-operator loopback
exchange and fixed historical inputs. It is not a VATE external-SUT comparison,
a cross-implementation A2A result, certification or production validation.

The earlier [HandoffProbe reconciliation review](handoffprobe-reconciliation-review.md)
records a separate synthetic provider-query experiment. Its results and source
pins remain separate from this A2A package reproduction.

## Acknowledgement

Thanks to [Heaviside479](https://github.com/Heaviside479) for reproducing the
fixed package, preserving the environment and results, and returning the
report to VATE issue #2.
