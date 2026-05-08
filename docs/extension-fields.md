# Extension Fields

## Status

The v0.2 schemas intentionally keep some `additionalProperties` surfaces open
while the AL2 admission profile is still under review.

This note defines how implementations should handle extension data before those
schemas are tightened.

## Rule

Unknown extension fields must not grant authority.

A verifier may preserve unknown extension fields for round-tripping, logging, or
future review, but it must not use them to widen action scope, bypass local
policy, change reason-code ordering, override freshness, satisfy replay checks,
or replace trust-bundle verification.

## Handling Requirements

Implementations should:

- preserve unknown extension fields when doing so is operationally useful
- ignore unknown extension fields for admission authority unless a profile
  explicitly registers and validates the field
- fail closed when an extension field appears in a critical verification surface
  and the verifier cannot validate it
- keep profile-defined fields and extension fields separate in implementation
  reports
- document any implementation-specific extension interpretation in the
  implementation report

Implementations should not:

- treat an unknown field as an additional permission
- reinterpret a standard field based on an unknown extension field
- silently promote extension data into policy, trust, status, or receipt linkage
  semantics
- depend on schema permissiveness as evidence of interoperability

## Tightening Path

Future drafts can tighten `additionalProperties` only after extension points are
named explicitly.

Before tightening a schema, the repository should identify:

- which object owns the extension surface
- whether the extension field is advisory, evidentiary, or policy-affecting
- whether unknown values must be ignored, preserved, or rejected
- which conformance fixture proves the behavior

This keeps the v0.2 corpus extensible without letting extension data become
implicit authority.
