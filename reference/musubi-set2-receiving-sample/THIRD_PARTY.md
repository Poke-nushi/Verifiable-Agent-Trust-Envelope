# Sources and licenses

VATE sample code is available under the Apache-2.0 license in [LICENSE](LICENSE).

The 43 files under `sample/evaluator-source/workers/` and the base 68 originals under
`sample/originals/` are unmodified material from
[Horizon Shield](https://github.com/ogasurfproject-jpg/horizon-shield/tree/b85029de8d22c5246886f4f50ede03da0f54dfcf).
The upstream repository is licensed under the MIT license, reproduced in
[sample/evaluator-source/LICENSE](sample/evaluator-source/LICENSE).
`evaluator-template.json` and `sample/manifest.json` retain the per-file source
URLs, commit, Git blob IDs, byte lengths and raw SHA-256 hashes.

The unmodified audit and dataset under `sample/originals/supplementary/` also
come from Horizon Shield. Their source commits differ: the audit is pinned to
`b85029de8d22c5246886f4f50ede03da0f54dfcf`, the dataset to
`5b22c203248b0149cd0456f77d32feb887f48ee0`. See
[audit-sources.json](sample/audit-sources.json) for their exact source URLs and
identities, and [AUDIT-CONTRACT.md](AUDIT-CONTRACT.md) for the selected linkage.

The additional header view in `sample/extended-view.json` is selected by the
receiver for a separate replay. It is not an additional signed acceptance record.

Dependency wheels and virtual environments are not included. Preparation obtains
the exact packages listed in `requirements.lock`; each installed distribution
retains its own license and metadata. `evaluator-template.json` lists the selected
versions, including ca2a-runtime 0.4.0. No dependency version is selected from the
received originals.

The optional foreign acceptance example uses the caller's separately obtained
[HS51 acceptance set](https://github.com/babyblueviper1/preaction-governance-conformance/tree/235aaabc45ebe6fa36dd02ca2cd6a44a69297d93/examples/hs51-acceptance-set)
and [WAR verifier](https://github.com/maximusrufus/work-acceptance-record/blob/6b2f730b81e0818826f274742d883c2b475d5227/verifier/war_verify.py).
Those records, the verifier source and its TSA-root test vectors are not bundled
in this sample. The sample's Apache-2.0 license does not grant rights to those
separate materials. Their exact bytes and the caller-selected roots are retained
in local run exports for inspection and recovery.
