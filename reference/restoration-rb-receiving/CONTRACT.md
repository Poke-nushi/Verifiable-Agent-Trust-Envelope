# RB receiving contract

`vate-local-restoration-rb-receiving-v1` is an experimental local contract for
one decoded in-toto RB Statement. It leaves VATE's common schemas, semantic
profile, receipt digests and Required Records kinds unchanged.

## Sources and rule interpretation

The source is [Restoration Evidence -00](https://www.ietf.org/archive/id/draft-gilda-audit-restoration-evidence-00.txt),
especially §§4, 5.5, 7.1, 7.4, 7.7 and 8. The comparison anchor is
`probityai/agent-evidence-vectors` commit
`1177028f6276f439768ab7d02fb734054832612c` (v0.31.2):
[RB predicate](https://github.com/probityai/agent-evidence-vectors/blob/1177028f6276f439768ab7d02fb734054832612c/spec/predicates/revocation-boundary.md),
[profile](https://github.com/probityai/agent-evidence-vectors/blob/1177028f6276f439768ab7d02fb734054832612c/profiles/restoration-evidence.md),
and the RB members of its restart-records corpus.

The reader implements only the RB rule table, in order. Document-defined closed
values are checked in rule 2; the pinned profile says rule 3 covers registry
values, of which RB has none. `registryDigest` has a checked shape; its value is
matched separately to the receiver's selected, pinned registry digest.
`subject` must contain exactly one member, following draft §5.5. Predecessors
are shape-checked but not resolved into a restoration bundle.

The local reader accepts one bounded JSON representation. It does not verify a
DSSE envelope or enforce JCS bytes. Each input is at most 1 MiB, with at most
256 elements per array, depth 24 and 20,000 visited values/keys. Numbers must
be JSON integer tokens within ±9007199254740991; booleans are not integers.
Duplicate keys, non-finite/fraction/exponent numbers, lone surrogates, invalid
UTF-8 and excessive complexity leave the record `not_assessed` with a parsing
reason. Unicode noncharacters are not rejected; this is not full I-JSON
validation. Other Statement/predicate rule failures are `failed` with the first
rule's reason. These representation limits and the single-subject requirement
are explicit limits of this reader, not a claim of complete equivalence to
every possible upstream-checker input.

Times use valid UTC `YYYY-MM-DDTHH:MM:SSZ` strings. All comparisons are by instant.
HTTPS identifier checks use the pinned checker's ECMAScript whitespace set.
Only the selected predicate URI is read. Different types and unknown fields
are never reinterpreted as RB success. No reference URL is fetched.

## Receiver selection

The selection has exactly `profile: vate-local-rb-selection-v1`, a nonempty
`receiver_id`, and `expected`. Expected fields are:

| Field | Required shape / comparison |
| --- | --- |
| `incident` | `{issuer, id}`; HTTPS issuer and nonempty text id; exact primary incident, without related-incident alias inference |
| `producer` | `{id}`; HTTPS id |
| `sink` | `{id, kind, commitBoundary}`; nonempty text id and commitBoundary; kind is `database`, `filesystem`, `http_endpoint`, `subprocess`, `queue` or `other` |
| `observer` | `{id, vantage}`; nonempty text id; vantage is `sink_side` or `agent_side` |
| `revocation` | `{credential, effectiveAt, timeSource}`; nonempty text credential and timeSource; effectiveAt uses the UTC format above |
| `window` | `{start, end}`; both use the UTC format above, with start ≤ effectiveAt ≤ end |
| `test_plan_sha256` | Lowercase hex SHA-256 of the selected plan bytes |
| `registry_sha256` | `1c5ff80bd97237a603afc402db692ffe5abe15e4a7f9eca13f20068ada347fdc` |

The selected registry digest is the raw-file SHA-256 of the pinned upstream
`packages/vocabulary/vocabulary.yaml`. It is also the `source_sha256` value in
that version's `packages/vocabulary/registry.json`, not the hash of the JSON
index itself. [SOURCE-PINS.json](SOURCE-PINS.json) identifies both originals
and their download URLs.

The caller selects these outside the incoming submission. Matching checks the
Statement's declarations; it does not establish the identity or authority of
the producer, observer, clock or credential. Credential identifiers are opaque
aliases. Draft §8 excludes secrets, hashes of secrets and key fingerprints from
that RB field. The capture keeps the alias-to-native-selection relationship in
a separate provenance record.

Invalid selection is an invocation error. Absent selection is allowed by the
Python assessment API and leaves binding `not_assessed`. The CLI requires it.

## Test-plan binding

The optional local plan has exactly `sink` and `window`, with values identical
to the Statement. Its **raw bytes**, including whitespace and final newline,
must hash to the Statement subject digest. The result is
`matched_under_local_profile`, named `vate-local-rb-plan-raw-v1`. The examples
generate compact ASCII JSON with a final newline and retain those bytes.

This chooses a concrete preimage for these local examples. Other producers'
plan representations require an explicit mapping and remain unsupported here.
It neither changes VATE object digests nor substitutes re-serialized JSON for
the original bytes referenced by upstream predecessors.

## Optional local observation

This contract is an input to this example, not an extra RB predicate field.
It has exactly:

- `profile: vate-local-rb-observation-v1`;
- `statement_sha256`, binding the original Statement bytes;
- `context`, with the same eight fields as selection `expected`;
- `collection`, either `closed` or `partial`, asserted by the local observer;
- `attempts`, up to 256 attempt objects;
- `exclusions`, the RB-shaped list of `{count, reason}`.

Each attempt has exactly `id`, `kind`, `replay_of`, `started_at`, `finished_at`,
`commit_state` and `committed_at`. IDs are unique. Kind is `initial` or `replay`.
An initial attempt has null `replay_of`; a replay names a carried initial ID.
`started_at` means attempt start, not arrival at the sink. A replay cannot start
before its referenced initial attempt. It can start before that attempt finishes;
equal start timestamps are allowed. Input row order does not establish causality.
These labels are the observer's assertions, not duplicate detection by this
reader. This local profile counts initial attempts in `attempts` and replay
attempts separately in `replaysAttempted`.

An initial attempt must start strictly before effectiveAt to establish complete
counts under this profile. Replays start at or after effectiveAt. Starts and
finishes fall within the window, with start at or before finish. An initial
attempt is in flight when it started before effectiveAt and has not finished
before it. A finish strictly after effectiveAt establishes that it was in flight.
A missing finish or a finish exactly at effectiveAt leaves that count uncertain.

Commit state is `committed`, `not_committed` or `unknown`. Committed requires a
commit timestamp between its start and finish. Not-committed requires a finish
and a null commit timestamp. Unknown has a null commit timestamp and may have
a null finish. Not-committed is an observation assertion over the declared
boundary and window; absence of a timestamp alone never creates that result.

The reader recomputes the five RB counts. Post-revocation initial commits and
replay commits are counted separately. A commit exactly at effectiveAt leaves
ordering unestablished; it is not counted as definitely before or after.
One task reaching its selected boundary once counts once, regardless of how
many files its operation creates.

Complete counts require `closed`, known ordering and known commit states.
`closed` asserts that all attempts in the selected test population are supplied;
it does not prove continuous observation or the absence of other operations.
Complete counts, exclusions and result are compared with the RB. Exclusion
arrays are compared in order, including repeated entries; they are not sets.
A declared
`not_established` is compatible with either observed result and stays visible
as the producer's declared result. An agent-side observation cannot establish
a zero-post-commit result. A positive observation can be reported from either
vantage, as permitted by the RB rules.

Partial collection, unknown effects or time ties leave `derived_counts: null`.
The reader retains `observed_positive: true` and a positive `derived_result`
when the supplied events contain an unambiguous positive witness even in a
partial collection. `observed_positive: false` means no such witness was found
in those supplied events; it is not a claim that the full population had zero.
Known lower bounds on any of the five counts can contradict smaller declared
counts, even in a partial collection. For a `closed` collection, the supplied
rows also bound each count from above. Initial and replay attempt totals are
exact even when their effects remain unknown. A missing finish is not treated
as certain evidence that an attempt was in flight. The declared counts must
also be jointly possible: each observed initial attempt must fit one of the
three disjoint categories (outside in-flight, in-flight without a post-revocation
commit, or in-flight with one), and each replay must fit its committed or
non-committed category. Unknown effects and time ties retain all compatible
categories. Unobserved attempts may fill spare capacity in a partial collection,
but cannot replace an already observed attempt to make incompatible counts fit.
Under this local observation contract, a nonzero `replaysAttempted` also requires
at least one declared initial attempt, even when a partial collection has no
rows. One initial may have multiple replays. This existence check belongs to the
bound local observation assessment; it does not add an upstream RB record rule
or apply when no valid, bound local observation is supplied.
A joint contradiction lists the initial or replay count group in
`different_fields`; it does not identify one field as the sole incorrect claim.
The two groups are checked independently: a single-count violation in one does
not suppress a joint contradiction in the other. A missing initial for declared
replays identifies `attempts` and `replaysAttempted`. Fields are listed once in
this order: `attempts`, `inFlightAtRevocation`, `postRevocationCommits`,
`replaysAttempted`, `replaysCommitted`.
A known positive witness
also contradicts a declared no-commit result. Count contradictions identify the
affected `different_fields`. Full derived counts remain null when collection
or ordering is incomplete; without a definite positive witness, the derived
result remains `not_established` in that case.

## Results and preserved inputs

| Result field | What it establishes |
| --- | --- |
| `record_check` | First failed RB rule, parsing limitation, or internal record consistency |
| `receiver_binding` | Exact agreement/disagreement of claimed context and receiver selection |
| `test_plan_binding` | Raw plan identity and sink/window under the local plan profile |
| `observation_check` | Input assertion consistency, contradiction, missing input or unestablished counts |
| `signature_verification` | Always `not_assessed` in this example |
| `issuer_authority` | Always `not_assessed` |
| `evidence_sufficiency` | Always `not_assessed`; receiver sufficiency criteria are not evaluated |
| `permission_to_resume` | Always `not_assessed`; no admission policy is evaluated |

The first four checks are separate: an observation may agree with its Statement
while that Statement names the wrong receiver-selected target. There is no
combined pass/allow flag. Observation success is explicitly
`consistent_under_local_assumptions`, not an independent observation or time
proof. Selecting `closed` or `sink_side` does not prove those assertions true.

Reports include raw input identities and the reader source identity. The
process refuses assessment if its loaded source has changed. `receive` creates
a new directory with exact original bytes, the report and a manifest; it
refuses an existing destination. The manifest excludes itself. The output
directory and its parents belong to the trusted local caller. A partial I/O
failure can leave an incomplete directory; inspect it and use a fresh path.
File inputs must be regular, bounded files; a final symlink is refused.

Receipt storage and reassessment do not execute the represented operation.
Only `run_capture.py` performs the documented synthetic file writes. The
capture requires its query's file inventory to match the separately exported,
verified native inventory, including field types, order and values. The comparison
uses JSON encoding so integer sizes cannot be replaced by booleans or floats.
A mismatch stops before saving that RB report, its `CAPTURE.json`, or the final
`SUMMARY.json`; earlier successful scenarios and provider evidence are retained.
The comparison remains within the same local provider and is not independent
observation.

The Inbox example preserves two readings with separate originals and history;
its empty requirement set does not evaluate RB coverage. No signing key,
network authority, independent observer, complete restoration bundle or
production restart policy is supplied by this contract.
