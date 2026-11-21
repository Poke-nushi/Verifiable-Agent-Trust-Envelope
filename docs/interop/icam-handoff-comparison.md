# ICAM handoff comparison for VATE case 3

Nika Novak built and ran two ICAM fixtures to test when a new worker may take
over a write after an earlier attempt was issued. In both fixtures, the primary
interface signed the same rejection payload, byte for byte. The handoff
decision turned on which write paths the verifier could rule out for the old
worker.
[Novak’s submission in AuthZEN #795](https://github.com/openid/authzen/issues/795#issuecomment-7044919792).

## Evidence at handoff

VATE case 3 models a two-file operation. The ICAM fixtures apply its handoff
conditions to one SQLite row. In both fixtures, the provider advanced the
authorization generation while its history showed no acceptance or write for
the earlier attempt.

| Input | Evidence available to the verifier | Decision for the same write |
| --- | --- | --- |
| A | Both declared interfaces check the current generation inside the write transaction. The old worker also lacks direct write access to the database. | `conditional_continuation` |
| B | The reviewed configuration leaves a known write path outside that control. This is visible before the old worker’s write appears in the journal. | `hold_same_logical_effect` |
| Launch evidence withheld from A or B | The verifier cannot establish which paths enforce the generation check. | `hold_same_logical_effect` |

The verifier can inspect the provider source, launch arguments, process
identity, and permissions on the database and its directory. The history
snapshot precedes the process checks. Continuing from A assumes the host runs
the reviewed code and keeps those controls in force through dispatch, covering
every route by which the old worker could produce the write.

For a new attempt, the pinned VATE case calls for a fresh evaluation by the
policy decision point, an atomic check and reservation by the policy enforcement
point, and registration of a signed receipt. These are separate integration
steps beyond the ICAM experiment.
[Case 3 decision at `c7533ad`](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/blob/c7533ad70c20e71b7912cdf708f33220e49c1f00/reference/authzen-receipt-vectors/cases/03-confirmed-nonexecution-handoff/fenced-handoff/expected-pep-decision.json).

## VATE maintainer’s checks

On 21 November 2026 (JST), I reran A in an isolated Ubuntu VM. Both interfaces
rejected the old attempt, and the new worker wrote the row once. For B, I
replayed the handoff decision from the submitted records and matched the old
worker’s recorded write to its signed response and the final row. I verified
all five archived Ed25519 response signatures with their respective fixture keys,
three from A and two from B.
[Maintainer’s reply in AuthZEN #795](https://github.com/openid/authzen/issues/795#issuecomment-7053281471).

The SHA-256 of Novak’s attached `ICAM_VATE_REVIEW_01.zip` is
`00f1c50dafe7a6e5ef4251e831ef0ad78951a67643eb5495f25c7d783c06a7cc`.
