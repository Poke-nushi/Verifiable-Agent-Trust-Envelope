# Runtime handoff and receiver contract

## Operation, authority, and uncertainty

The coordinator registers one operation with a provider-assigned resource.
Changing a runtime task ID or nonce does not create a new operation. The sample
has exactly two runtime keys, one status authority, and one provider SQLite
store per scenario. Receipt intake uses a separate receiver Inbox database. Owner operations require the coordinator's local Python
object capability; a runtime signature does not confer coordinator authority.

An unknown response remains an observation in the journal. Handoff can close
A's generation as confirmed unexecuted only after excluding the old worker and
checking the absence of acceptance and effects against consistent local state.
B then needs its own current admission, signature, and key status. Issuing B's
ticket makes the current operation unresolved again; the earlier confirmation
remains historical evidence, not B's execution result.

Once the provider has accepted A, zero or partial observed effects do not allow
B to restart. Completed A work remains A's work. Revocation after acceptance
does not cancel accepted work. The provider's operation identity, SQLite
uniqueness, worker lock, and generation checks prevent duplicate acceptance
within this local contract. The receiver checks the resulting evidence.

## Time, evidence, and linkage

The original admission is an unsigned local VATE demo artifact. Runtime and
key-status signatures use the constrained P-256 helpers included in the
distribution. The reader checks the chosen public keys, canonical inputs,
signature roles, journal chain, operation, admission, runtime, generation,
effects, and observation ordering. It does not infer execution times from the
time a later observer asks for a result.

A post-execution receipt is derived only when the provider's native record has
actual start and finish times. A's native result links to A's admission, and B's
to B's. Completion outside admission validity retains the completed effect and
reports linkage failure. A late observation of an in-window completion does
not itself cause that failure. Derived receipts are not producer-signed
originals.

The journal hashes check structure and continuity against the supplied record.
They are not an independently witnessed ledger. A malicious trusted provider
can rewrite a complete history or replace its head. The sample trusts its
local provider, coordinator, OS, SQLite, locks, and effect directory. It does
not isolate an adversary running arbitrary code as the same OS user. Process
interruption tests do not establish power-loss or storage-hardware guarantees.
Fixture clocks and synthetic unknown observations are test inputs, not
independent real-world timestamps or external network-failure measurements.

## Receiver selection and preservation

The receiver selects context, expected operation, both runtime identities,
provider/store, namespace, and required admission/post-execution records before
intake. The incoming evidence cannot replace that selection. Each requirement
names a runtime; an A-or-B alternative requirement is outside this contract.
Receiver-side operation labels distinguish the runtime/operation pair without
changing original transaction IDs, admission bytes, or request hashes.

The same Inbox database holds source capsules and native receipt deliveries in
separate namespaces. Capsules preserve original bytes using base64, which is
not encryption. Validated admissions and derived post-execution receipts enter
the existing `receipt_pair` assessment path. The source capsule is the receipt
delivery's evidence reference, so replay can reconstruct and check the
projection instead of trusting its labels.

Later accepted evidence must extend the previous accepted journal prefix and
must not regress observation time. Forks and truncated histories are retained
as unassessable input, without replacing the previous assessment. An earlier
cutoff keeps its earlier result even after later records arrive. Unknown
receipt time retains unknown cutoff membership. Missing records can be
assessed and replayed with zero capsules; missing evidence is not evidence of
nonexecution. An old run's displayed Inbox `head` may advance with later
history, while its frozen originals, decision, and report reference remain.

## Interruption and bounds

Intake uses a single-writer nonwaiting lock. A delivery event fixes its bytes
and claimed receipt time. Repeating that exact event can resume registration
after capsule storage. An existing run ID retrieves the saved assessment after
output loss. Persistent capacity or environment failures must be corrected;
they do not become confirmed nonexecution. The receiver never invokes provider
submission, uses a signing key, or returns an execution ticket.

The provider journal allows 256 events and 1 MiB of original journal bytes.
Acceptance reserves three 4 KiB result/clock records; the store also reserves
one terminal clock-fault record. A stopped accepted worker retains its
reservation. Detected clock regression closes further execution and
registration, including after restart. Old unknown and accepted records are
not discarded to continue at capacity.

The receiver accepts at most eight intakes, 384 KiB per bundle, four admissions
per bundle, and a 1 MiB capsule, also subject to the existing Inbox aggregate
limits. Oversized input, I/O failure, and busy state are not successful intake.
Invalid source inputs remain in the source partition and are not automatically
part of a successful receipt export.

## Replay and source versions

Replay takes a separately supplied receiver selection and does not reopen the
provider or Inbox database. It checks export membership and hashes, the capsule
chain, receipt projection, cutoff, and required records, then reruns the fixed
native evaluator. Report comparison distinguishes JSON booleans from numbers.
Only measured elapsed time, a temporary native-bundle path, and the integer
native-output byte count recalculated from retained calls are normalized.
Decisions, reasons, selected inputs, and time boundaries are not normalized.

Preserve the source distribution, its location, and the Python environment used
for the assessment. The receiver pins the sample and bridge sources as well as
the evaluator/runtime identity. A changed distribution is a new selected
implementation; silently migrating old databases or rewriting old evidence is
not supported. A source-version rejection says that this implementation cannot
replay the selected record, not that its earlier effects did not happen.

Multiple providers/stores, partial-effect continuation or compensation,
network cancellation, general JOSE/PKI validation, independent time proof,
cross-platform report equivalence, and long-term retention are outside this
sample. The existing VATE core, schemas, and semantic profile are unchanged.
