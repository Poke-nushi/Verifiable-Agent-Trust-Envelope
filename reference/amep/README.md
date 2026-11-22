# AMEP comparisons

[AMEP](https://github.com/stafordtituss/amep) (Agentic Mandate Evidence Protocol) evaluates signed evidence of what an
agent executed against the authority it was delegated, and returns `preserved`, `violated` or `unresolved`. This
directory holds AMEP's evaluation of VATE cases, for the comparison in
[openid/authzen#795](https://github.com/openid/authzen/issues/795).

| Case | Folder | VATE revision | AMEP revision |
|---|---|---|---|
| 1, lost response, then recovery (`with-unknown-observation`) | [`case-01-lost-response/`](case-01-lost-response/) | `c7533ad` | `765855d` |

Each case pins both revisions and carries a standard-library check. The AMEP files are copied unchanged from the pinned
AMEP revision, under the Apache License 2.0; `NOTICE` is AMEP's notice, kept as that licence requires.
