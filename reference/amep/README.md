# AMEP comparisons

[AMEP](https://github.com/stafordtituss/amep) (Agentic Mandate Evidence Protocol) evaluates signed evidence of what an
agent executed against the authority it was delegated, and returns `preserved`, `violated` or `unresolved`. This
directory holds AMEP's evaluation of VATE cases, for the comparison in
[openid/authzen#795](https://github.com/openid/authzen/issues/795).

| Case | Folder | VATE revision | AMEP revision |
|---|---|---|---|
| 1, lost response, then recovery (`with-unknown-observation`) | [`case-01-lost-response/`](case-01-lost-response/) | `c7533ad` | `765855d` |
| 2, accepted work interrupted (`zero-effects`, `partial-effects`) | [`case-02-accepted-interrupted/`](case-02-accepted-interrupted/) | `093194d` | `160159d` |
| 3, confirmed nonexecution and handoff (`fenced-handoff`, `live-worker`) | [`case-03-confirmed-nonexecution/`](case-03-confirmed-nonexecution/) | `3e9c262` | `957be02` |
| 4, a new permit does not reopen (`completed`, `unresolved`) | to follow | | |

Each case pins both revisions and carries a standard-library check. The AMEP files are copied unchanged from the pinned
AMEP revision, under the Apache License 2.0; `NOTICE` is AMEP's notice, kept as that licence requires.

## The AMEP column, across cases

AMEP's result for each VATE phase, as pinned in each case's `expected-results.json`. AMEP answers whether what
executed stayed within delegated authority, given the evidence, so `preserved` doesn't mean "the operation finished".

| Case | VATE phase | VATE | AMEP |
|---|---|---|---|
| 1 | pending | `unresolved` | `unresolved` (I7), gap `receipt` |
| 1 | recovered | `completed` | `preserved` |
| 2 | zero-effects, interrupted | `unresolved` | `unresolved` (I7), gap `receipt` |
| 2 | zero-effects, after handoff | `unresolved` | `unresolved`; a re-run is held (`held_outcome`) |
| 2 | partial-effects, interrupted | `unresolved` | `preserved` (the one write was within authority) |
| 2 | partial-effects, after handoff | `unresolved` | a re-run is `violated` (I8) |
| 3 | fenced-handoff, pending | `unresolved` | `unresolved` (I7), gap `receipt` |
| 3 | fenced-handoff, fenced | `confirmed_unexecuted` | `preserved`, nothing executed; the admission is released |
| 3 | fenced-handoff, completed | `completed` | `preserved` |
| 3 | live-worker, pending | `unresolved` | `unresolved` (I7), gap `receipt` |
| 3 | live-worker, completed | `completed` | `preserved` |

Case 4 depends on AMEP's operation identity (an operation key that holds across approvals), which is under review
in [stafordtituss/amep#24](https://github.com/stafordtituss/amep/pull/24). It will be added here once that is merged,
pinned to the merged commit.
