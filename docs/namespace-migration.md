# Namespace Migration

## Status

The v0.3 AL2 artifacts use repository-scoped draft URI values. They are stable
enough for review and fixture comparison, but they are not a permanent standards
namespace.

This note defines the migration discipline before any persistent namespace is
introduced.

## Current Draft URIs

The archived v0.2 A2A metadata extension URI was:

```text
https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/a2a/admission/v0.2
```

The current v0.3 A2A metadata extension URI is:

```text
https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/a2a/admission/v0.3
```

Schema identifiers currently use draft `urn:vate:*` identifiers or repository
paths. Current v0.3 schemas and examples use the `v0.3` profile line. The
older `v0.2` URI remains a historical draft URI for archived v0.2 artifacts.

## Persistent Namespace Target

A future draft may move to a persistent namespace such as `w3id.org` or another
controlled URI space.

The persistent namespace must provide:

- documented control by the project maintainer or future stewardship body
- stable redirects for schema, profile, and extension identifiers
- immutable or versioned paths for already-published artifacts
- a public mapping from repository-scoped draft URI values to persistent URI
  values

## Migration Conditions

Do not migrate identifiers until all of the following are true:

- the AL2 admission profile shape has survived external review
- at least one independent implementation report can be compared with
  `scripts/vate_conformance.py compare`
- the target namespace is controlled, documented, and redirectable
- the mapping can be tested by the repository sanity checks

## Compatibility Rule

Do not break existing v0.3 corpus artifacts during namespace migration.

If a persistent namespace is added, v0.3 repository-scoped draft URI values must
continue to resolve in examples, reports, and corpus snapshots that already use
them. Historical v0.2 repository-scoped draft URI values should remain
resolvable for archived snapshots. A verifier may recognize multiple identifiers
during a transition window, but must not treat namespace aliases as additional
authority.

## Non-Goals

This migration plan does not create an official standards namespace, governance
process, or registry. It only prevents premature identifier churn while the AL2
artifact line is still under review.
