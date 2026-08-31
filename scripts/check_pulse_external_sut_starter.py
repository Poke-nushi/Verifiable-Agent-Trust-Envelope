#!/usr/bin/env python3
"""Fail-closed checks for the bounded VATE-to-Pulse external SUT starter.

The full-history checker reads VATE source bytes from the fixed Git object
rather than from the current checkout.  ``--archive-safe`` instead verifies the
committed 12-path starter closure against byte-identical files in a source
archive without claiming that the historical Git object was replayed.  With
--pulse-repo it also verifies that the frozen Pulse
checkout and reviewed verifier surface are byte-identical to the recorded pin.
With --run-bundle it validates completed, partial, or blocked Pulse-side
records using a closed, starter-specific contract and bundle-local raw-byte
bindings. Every claimed completed case is replayed through candidate code and
the frozen Pulse verifier.
It intentionally does not implement a VATE-to-Pulse adapter or project a Pulse
report into a VATE verdict.
"""

from __future__ import annotations

import argparse
import ast
import base64
import copy
import hashlib
import json
import math
import os
import posixpath
import re
import selectors
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path, PurePosixPath
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
KIT_ROOT = ROOT / "examples" / "external-sut-pulse-starter"
MANIFEST_PATH = KIT_ROOT / "manifest.json"
WORKSHEET_PATH = KIT_ROOT / "mapping-worksheet.template.json"
RESULT_TEMPLATE_PATH = KIT_ROOT / "pulse-sut-result.template.json"

VATE_COMMIT = "5a37f87de0190da44e619b1800261637e83dd7ed"
PULSE_COMMIT = "e06a6cbfe3ddb965c8fc70f50838f5014ec2038e"
CORPUS_ROOT = "conformance/al2-vate-v0.3"
CORPUS_INDEX_PATH = f"{CORPUS_ROOT}/corpus.json"
PROFILE = "VATE-AL2-Verifier-Admission-v0.3"
CORPUS_DIGEST = "988aae7d03dd5bb743e8e03e6ab1120ce8735a4837ac818ffd9d665de0c1e370"
SELECTED_SET_DIGEST = "473bb174e08b93c67fa64f6d668275023ca934a00d72be7bc2720fa127f96a0d"
SELECTED_CASE_IDS = (
    "allow-ap2-hnp-preauthorized-mandate",
    "attenuate-ap2-hnp-amount-overrun",
    "deny-ap2-hnp-stale-mandate",
)
EXPECTED_CLOSURE_DIGESTS = {
    "allow-ap2-hnp-preauthorized-mandate": "1a2058d71869f1530f461479b9b9f505da318702eedeef7bca4afd9e92c1d5a3",
    "attenuate-ap2-hnp-amount-overrun": "e0be368ae171cd9198aedaaf0713728537b6e16263268da2a1eed7c81fa04aa1",
    "deny-ap2-hnp-stale-mandate": "fded9e057a80f78c4a3119d9232f34d3098594dad975ad8ad7eee56abd77f600",
}
PULSE_REVIEWED_SURFACE = {
    "src/verifier.ts": "53cb93d85261c443685c22e61ecf7c1b85fc8ec67789e7f51684164cbf614795",
    "src/types.ts": "8a9f935f855f4ed1e2c89264a67715c31a783ce0ce3944630c584be3c5965993",
    "src/failures.ts": "40b7c575fbb595939e3e2c9fb876629083c7ac0e0675db200f25868e170b5d33",
    "src/canonical.ts": "4d4086040514dea1314c964127e8e1164d254cda6471f993a4c114c740fb1d07",
    "src/ap2-crypto.ts": "3ed18dec4795fcee0c717d5e821ce21897451a879eb08252ffaccb9e10e11068",
    "src/x402-producer.ts": "38563df20b0d0565fd075201dd17e4c8757116410c1ee750ca406146c6ab973d",
    "package.json": "49b4831a0bcf1b012b4b40120249ff41bdfda488ff43361010f09bd30ebc81c2",
    "package-lock.json": "303ef334398310ab1ccef6159fdc85c55a80f0c5eea5d49d2da6306252f4e379",
    "fixtures/v0.3/cases.json": "8f40be1bdc3d4458f758100e91b418b6a335c5d8d358723f118e2d3e1ad84ee0",
}
PULSE_REFERENCE_CASE_ID = "valid-base-sepolia-01"
PULSE_LEAF_PATH_DIGEST = "8e7ea0b60120e84c5763cd6d80e512f8d27af26ea25edae0620c17c3f5edc0fe"
PULSE_REQUIRED_EMPTY_CONTAINERS = ("/expected/failureCodes",)
STARTER_MANIFEST_VERSION = "vate-pulse-external-sut-starter-manifest-0.6"
WORKSHEET_VERSION = "vate-pulse-mapping-worksheet-0.5"
RUN_RECORD_VERSION = "vate-pulse-external-sut-run-record-0.6"
RAW_OUTPUT_VERSION = "vate-pulse-raw-verifier-output-0.3"
ELIGIBLE_INPUT_VERSION = "vate-pulse-eligible-inputs-0.1"
GENERATED_RECORD_VERSION = "vate-pulse-generated-leaf-records-0.2"
CANDIDATE_INTERFACE_VERSION = "vate-pulse-candidate-executable-0.2"
CANDIDATE_EXPORT_MAX_FILES = 4096
CANDIDATE_EXPORT_MAX_BYTES = 64 * 1024 * 1024
CANDIDATE_STDOUT_MAX_BYTES = 32 * 1024 * 1024
CANDIDATE_STDERR_MAX_BYTES = 1024 * 1024
CANDIDATE_EXECUTION_TIMEOUT_SECONDS = 45.0
CANDIDATE_FORBIDDEN_EXPORT_COMPONENTS = frozenset(
    {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build"}
)
CANDIDATE_FORBIDDEN_EXPORT_SUFFIXES = frozenset(
    {".dll", ".dylib", ".node", ".pyd", ".pyc", ".pyo", ".so"}
)
PYTHON_FORBIDDEN_RUNTIME_MODULES = frozenset(
    {
        "asyncio",
        "ctypes",
        "ftplib",
        "http",
        "imaplib",
        "importlib",
        "multiprocessing",
        "poplib",
        "pty",
        "smtplib",
        "socket",
        "ssl",
        "subprocess",
        "telnetlib",
        "urllib",
        "webbrowser",
    }
)
NODE_FORBIDDEN_BUILTINS = frozenset(
    {
        "child_process",
        "cluster",
        "dgram",
        "dns",
        "http",
        "http2",
        "https",
        "module",
        "net",
        "tls",
        "worker_threads",
    }
)
CANDIDATE_WORK_ITEM_IDS = ("work-item-0", "work-item-1", "work-item-2")
MACHINE_COVERAGE_SCOPE = "frozen-pulse-input-json-142-primitive-leaves-and-42-containers-only"
EXPECTED_MACHINE_COVERAGE_CONTRACT = {
    "scope": MACHINE_COVERAGE_SCOPE,
    "compact_jose_sd_jwt_internals_verified": False,
    "eip3009_signature_internals_verified": False,
    "private_signing_material_recorded": False,
    "public_generated_leaf_hashes_recorded": True,
}
EXPECTED_CLAIM_CONTRACT = {
    "engagement_type": "solicited_reciprocal_external_sut_attempt",
    "artifact_status": "starter_only",
    "organic_adoption": False,
    "formal_audit": False,
    "endorsement": False,
    "certification": False,
    "production_approval": False,
    "general_compatibility": False,
    "cross_validation": "neither_party_validates_or_endorses_the_other",
    "pulse_issue_18_completion": False,
    "vate_result_is_pulse_security_review": False,
    "candidate_execution_is_tamper_proof": False,
    "candidate_repository_remote_fetch_verified": False,
    "candidate_runtime_os_supply_chain_verified": False,
}
EXPECTED_SOURCE_POLICY = {
    "vate_expected_used": False,
    "vate_admission_receipt_used_as_source": False,
    "vate_post_execution_receipt_used_as_source": False,
    "case_id_verdict_lookup_used": False,
    "unchanged_pulse_fixture_used": False,
    "pulse_verifier_semantic_change": False,
    "comparison_receipts_used_only_by_vate_compare": True,
    "candidate_runtime_received_eligible_inputs_only": True,
    "source_scan_is_primary_control": False,
}
EXPECTED_CANDIDATE_EXECUTION_CONTRACT = {
    "interface_version": CANDIDATE_INTERFACE_VERSION,
    "launcher_allowlist": ["python3", "node"],
    "command_shape": "isolated-launcher-flags-plus-tracked-entrypoint-only",
    "shell": False,
    "execution_source": "fresh-tracked-regular-commit-export-per-invocation",
    "working_tree_scope": "identity-and-cleanliness-check-only-never-executed",
    "runtime_selection": "operator-selected-absolute-cli-path",
    "ambient_path_resolution": False,
    "runtime_identity_rechecked_before_and_after_each_execution": True,
    "runtime_os_supply_chain_proof": False,
    "live_checkout_executed": False,
    "symlinks_submodules_special_files_allowed": False,
    "external_packages_allowed": False,
    "runtime_network_allowed": False,
    "export_write_allowed": False,
    "temporary_home_and_tmp": True,
    "python_runtime": "-I -S -B; stdlib plus tracked source/data only",
    "node_runtime": "--no-addons --no-global-search-paths; built-ins plus tracked source only",
    "export_max_files": CANDIDATE_EXPORT_MAX_FILES,
    "export_max_bytes": CANDIDATE_EXPORT_MAX_BYTES,
    "stdout_max_bytes": CANDIDATE_STDOUT_MAX_BYTES,
    "stderr_max_bytes": CANDIDATE_STDERR_MAX_BYTES,
    "timeout_seconds": int(CANDIDATE_EXECUTION_TIMEOUT_SECONDS),
    "stdin_scope": "eligible-admission-request-and-ap2-mandate-only",
    "vate_case_id_supplied": False,
    "vate_expected_supplied": False,
    "vate_receipt_supplied": False,
    "independent_recomputation": True,
    "sensitivity_dimensions": ["amount", "merchant", "evaluation_time", "replay_nonce"],
    "candidate_code_is_untrusted": True,
    "maintainer_direct_execution_without_review_or_sandbox": False,
    "tamper_proof_claim": False,
    "remote_fetch_verified": False,
}
CANDIDATE_EXPORT_TEMPLATE_CONTRACT = {
    "mode": "fresh-tracked-regular-commit-export-per-invocation",
    "working_tree_scope": "identity-and-cleanliness-check-only-never-executed",
    "file_count": None,
    "total_bytes": None,
    "file_inventory_sha256": None,
    "inventory_basis": "sorted canonical JSON [{path,file_type,git_mode,raw_sha256,size}]",
    "fresh_per_invocation": True,
    "regular_files_only": True,
    "live_checkout_executed": False,
    "external_packages_available": False,
    "runtime_network_allowed": False,
    "export_write_allowed": False,
}
CANDIDATE_RUNTIME_TEMPLATE_RECORD = {
    "logical_name": None,
    "requested_absolute_path": None,
    "requested_file_type": None,
    "realpath": None,
    "realpath_file_type": None,
    "raw_sha256": None,
    "version": None,
}
SELF_TEST_FIXTURE_SOURCE_POLICY = {
    **EXPECTED_SOURCE_POLICY,
    "unchanged_pulse_fixture_used": True,
}
EXPECTED_COMPARISON_CONTRACT = {
    "corpus_case_count": 75,
    "selected_case_count": 3,
    "out_of_scope_case_count": 72,
    "fixed_runner_treats_skipped_as_failure": True,
    "completed_expected_summary": {
        "passed": 2,
        "failed": 73,
        "skipped": 72,
    },
    "selected_expected_relation_counts": {
        "match": 2,
        "mismatch": 1,
    },
    "verify_bundle_is_integrity_only": True,
}
MATCHED_SELECTED_RESULT_CONTRACTS = {
    "allow-ap2-hnp-preauthorized-mandate": {
        "outcome": "allow",
        "should_execute": True,
        "reason_codes": ["EVIDENCE_VERIFIED", "POLICY_MATCH"],
        "required_checks": {
            "decision.outcome",
            "request.audience",
            "evidence[0].protocol_hint",
            "evidence.verification.result",
        },
    },
    "deny-ap2-hnp-stale-mandate": {
        "outcome": "deny",
        "should_execute": False,
        "reason_codes": ["PERMIT_EXPIRED", "FAIL_CLOSED"],
        "required_checks": {
            "decision.outcome",
            "evidence.verification.failure_reason",
        },
    },
}
ATTEMPT_STAGES = {
    "source-validation",
    "mapping",
    "generation",
    "pulse-install",
    "pulse-replay",
    "projection",
    "comparison",
    "complete",
}
ATTEMPT_REASON_CODES = {
    "COMPLETED",
    "TIMEBOX_REACHED",
    "ENVIRONMENT_BLOCKER",
    "MAPPING_BLOCKER",
    "GENERATION_BLOCKER",
    "REPLAY_BLOCKER",
    "PROJECTION_BLOCKER",
    "COMPARISON_BLOCKER",
}
GENERATOR_IDS = {
    "candidate-owned-jose-and-eip3009",
    "frozen-pulse-canonical-rule",
    "payment-receipt",
    "public-fixture-key-record",
    "synthetic-settlement",
}
SCAFFOLD_DEPENDENCIES = {
    "ap2-generation-profile",
    "asset-profile",
    "evm-participants",
    "fixture-key-handling",
    "instrument-profile",
    "merchant-profile",
    "neutral-pulse-expected",
    "pulse-profile",
    "pulse-schema",
    "resource-profile",
    "settlement-profile",
    "x402-profile",
}
FORBIDDEN_MAPPING_SOURCE_TOKENS = (
    "/expected",
    "expected_outcome",
    "expectedoutcome",
    "expected_reason_codes",
    "expectedreasoncodes",
    "precomputed_vate",
    "precomputed-vate",
    "admission_receipt",
    "admission-receipt",
    "post_execution_receipt",
    "post-execution-receipt",
    *SELECTED_CASE_IDS,
)
PULSE_REPLAY_SCRIPT = """import { readFile } from \"node:fs/promises\";
import { verifyConformanceCase } from \"./src/verifier.ts\";
const reports = [];
for (const path of process.argv.slice(1)) {
  const value = JSON.parse(await readFile(path, \"utf8\"));
  reports.push(await verifyConformanceCase(value));
}
process.stdout.write(JSON.stringify(reports));
"""
PULSE_REPLAY_SCRIPT_SHA256 = hashlib.sha256(PULSE_REPLAY_SCRIPT.encode("utf-8")).hexdigest()
EXPECTED_TIMEBOX_CONTRACT = {
    "clock_start": "immutable_starter_publication",
    "independent_attempts": True,
    "vate_to_pulse": {
        "maximum_business_days": 1,
        "may_stop_on_partial_or_blocker": True,
    },
    "pulse_to_vate": {
        "maximum_business_days": 1,
        "may_stop_on_partial_or_blocker": True,
    },
}
EXPECTED_KIT_FILES = {
    "README.md",
    "manifest.json",
    "mapping-worksheet.template.json",
    "pulse-sut-result.template.json",
}
EXPECTED_TOPICS = {
    "usd_decimal_to_asset_decimals_and_atomic_amount",
    "merchant_to_pulse_payee_identity",
    "evaluation_time_and_window",
    "vate_replay_nonce_to_pulse_key_binding_and_eip3009_nonce",
    "generated_ap2_fields_and_fixture_keys",
    "generated_x402_fields",
    "generated_eip3009_fields_and_signature",
    "generated_payment_receipt_fields_and_key",
    "frozen_pulse_verifier_invocation",
    "raw_pulse_output_preservation",
    "pulse_to_vate_result_projection_without_expected_lookup",
}
REQUIRED_ROW_IDS = {
    "case-id-label",
    "evaluation-time",
    "verification-time",
    "open-checkout-reference",
    "closed-transaction-reference",
    "open-reference-constraint",
    "request-usd-minor-units",
    "request-usd-currency",
    "mandate-limit-minor-units",
    "mandate-limit-currency",
    "request-atomic-amount",
    "permitted-atomic-amount",
    "merchant-payee-id",
    "merchant-allowed-id",
    "merchant-ap2-payee-id",
    "resource-url",
    "open-issued-at",
    "closed-issued-at",
    "open-expiry",
    "closed-expiry",
    "eip3009-valid-after",
    "eip3009-valid-before",
    "terminal-key-binding-nonce",
    "closed-mandate-reference",
    "eip3009-nonce",
    "asset-network-scaffolding",
    "asset-address-scaffolding",
    "payer-scaffolding",
    "pay-to-scaffolding",
    "generated-ap2-artifacts",
    "generated-x402-objects",
    "pulse-input-hash",
    "neutral-pulse-expected-envelope",
    "observed-pulse-report",
    "pulse-to-vate-outcome",
    "pulse-to-vate-execution-gate",
    "pulse-to-vate-reasons",
    "pulse-to-vate-checks",
}
PULSE_PRIMITIVE_LEAF_PATHS = (
    "/ap2/closedMandate/execution_date",
    "/ap2/closedMandate/exp",
    "/ap2/closedMandate/iat",
    "/ap2/closedMandate/payee/id",
    "/ap2/closedMandate/payee/name",
    "/ap2/closedMandate/payee/website",
    "/ap2/closedMandate/payment_amount/amount",
    "/ap2/closedMandate/payment_amount/currency",
    "/ap2/closedMandate/payment_instrument/description",
    "/ap2/closedMandate/payment_instrument/id",
    "/ap2/closedMandate/payment_instrument/type",
    "/ap2/closedMandate/payment_instrument/x402/amount",
    "/ap2/closedMandate/payment_instrument/x402/ap2PayeeId",
    "/ap2/closedMandate/payment_instrument/x402/ap2PaymentAmount/amount",
    "/ap2/closedMandate/payment_instrument/x402/ap2PaymentAmount/currency",
    "/ap2/closedMandate/payment_instrument/x402/asset",
    "/ap2/closedMandate/payment_instrument/x402/eip712Domain/name",
    "/ap2/closedMandate/payment_instrument/x402/eip712Domain/version",
    "/ap2/closedMandate/payment_instrument/x402/maxTimeoutSeconds",
    "/ap2/closedMandate/payment_instrument/x402/network",
    "/ap2/closedMandate/payment_instrument/x402/nonceBinding",
    "/ap2/closedMandate/payment_instrument/x402/payTo",
    "/ap2/closedMandate/payment_instrument/x402/payer",
    "/ap2/closedMandate/payment_instrument/x402/scheme",
    "/ap2/closedMandate/payment_instrument/x402/version",
    "/ap2/closedMandate/transaction_id",
    "/ap2/closedMandate/vct",
    "/ap2/openMandate/cnf/jwk/alg",
    "/ap2/openMandate/cnf/jwk/crv",
    "/ap2/openMandate/cnf/jwk/kid",
    "/ap2/openMandate/cnf/jwk/kty",
    "/ap2/openMandate/cnf/jwk/x",
    "/ap2/openMandate/cnf/jwk/y",
    "/ap2/openMandate/constraints/0/conditional_transaction_id",
    "/ap2/openMandate/constraints/0/type",
    "/ap2/openMandate/constraints/1/allowed/0/description",
    "/ap2/openMandate/constraints/1/allowed/0/id",
    "/ap2/openMandate/constraints/1/allowed/0/type",
    "/ap2/openMandate/constraints/1/allowed/0/x402/amount",
    "/ap2/openMandate/constraints/1/allowed/0/x402/ap2PayeeId",
    "/ap2/openMandate/constraints/1/allowed/0/x402/ap2PaymentAmount/amount",
    "/ap2/openMandate/constraints/1/allowed/0/x402/ap2PaymentAmount/currency",
    "/ap2/openMandate/constraints/1/allowed/0/x402/asset",
    "/ap2/openMandate/constraints/1/allowed/0/x402/eip712Domain/name",
    "/ap2/openMandate/constraints/1/allowed/0/x402/eip712Domain/version",
    "/ap2/openMandate/constraints/1/allowed/0/x402/maxTimeoutSeconds",
    "/ap2/openMandate/constraints/1/allowed/0/x402/network",
    "/ap2/openMandate/constraints/1/allowed/0/x402/nonceBinding",
    "/ap2/openMandate/constraints/1/allowed/0/x402/payTo",
    "/ap2/openMandate/constraints/1/allowed/0/x402/payer",
    "/ap2/openMandate/constraints/1/allowed/0/x402/scheme",
    "/ap2/openMandate/constraints/1/allowed/0/x402/version",
    "/ap2/openMandate/constraints/1/type",
    "/ap2/openMandate/constraints/2/currency",
    "/ap2/openMandate/constraints/2/max",
    "/ap2/openMandate/constraints/2/min",
    "/ap2/openMandate/constraints/2/type",
    "/ap2/openMandate/constraints/3/allowed/0/id",
    "/ap2/openMandate/constraints/3/allowed/0/name",
    "/ap2/openMandate/constraints/3/allowed/0/website",
    "/ap2/openMandate/constraints/3/type",
    "/ap2/openMandate/exp",
    "/ap2/openMandate/iat",
    "/ap2/openMandate/vct",
    "/ap2/paymentReceipt/error",
    "/ap2/paymentReceipt/error_description",
    "/ap2/paymentReceipt/iat",
    "/ap2/paymentReceipt/iss",
    "/ap2/paymentReceipt/network_confirmation_id",
    "/ap2/paymentReceipt/payment_id",
    "/ap2/paymentReceipt/psp_confirmation_id",
    "/ap2/paymentReceipt/reference",
    "/ap2/paymentReceipt/status",
    "/ap2/verification/clockSkewSeconds",
    "/ap2/verification/closedMandateClaimsHash",
    "/ap2/verification/closedMandateReference",
    "/ap2/verification/cryptographicEvidence/expectedAudience",
    "/ap2/verification/cryptographicEvidence/expectedNonce",
    "/ap2/verification/cryptographicEvidence/mandateChain",
    "/ap2/verification/cryptographicEvidence/paymentReceiptJwt",
    "/ap2/verification/cryptographicEvidence/trustedReceiptPublicJwk/alg",
    "/ap2/verification/cryptographicEvidence/trustedReceiptPublicJwk/crv",
    "/ap2/verification/cryptographicEvidence/trustedReceiptPublicJwk/kid",
    "/ap2/verification/cryptographicEvidence/trustedReceiptPublicJwk/kty",
    "/ap2/verification/cryptographicEvidence/trustedReceiptPublicJwk/x",
    "/ap2/verification/cryptographicEvidence/trustedReceiptPublicJwk/y",
    "/ap2/verification/cryptographicEvidence/trustedRootPublicJwk/alg",
    "/ap2/verification/cryptographicEvidence/trustedRootPublicJwk/crv",
    "/ap2/verification/cryptographicEvidence/trustedRootPublicJwk/kid",
    "/ap2/verification/cryptographicEvidence/trustedRootPublicJwk/kty",
    "/ap2/verification/cryptographicEvidence/trustedRootPublicJwk/x",
    "/ap2/verification/cryptographicEvidence/trustedRootPublicJwk/y",
    "/ap2/verification/openCheckoutReference",
    "/ap2/verification/openMandateClaimsHash",
    "/ap2/verification/verifiedAtEpochSeconds",
    "/ap2/verification/verifier",
    "/caseVersion",
    "/description",
    "/expected/consistent",
    "/id",
    "/inputHash",
    "/nowEpochSeconds",
    "/sourcePins/ap2Commit",
    "/sourcePins/x402Commit",
    "/sourcePins/x402PackageVersion",
    "/x402/payload/accepted/amount",
    "/x402/payload/accepted/asset",
    "/x402/payload/accepted/extra/ap2MandateReference",
    "/x402/payload/accepted/extra/ap2NonceDerivation",
    "/x402/payload/accepted/extra/assetTransferMethod",
    "/x402/payload/accepted/extra/name",
    "/x402/payload/accepted/extra/version",
    "/x402/payload/accepted/maxTimeoutSeconds",
    "/x402/payload/accepted/network",
    "/x402/payload/accepted/payTo",
    "/x402/payload/accepted/scheme",
    "/x402/payload/payload/authorization/from",
    "/x402/payload/payload/authorization/nonce",
    "/x402/payload/payload/authorization/to",
    "/x402/payload/payload/authorization/validAfter",
    "/x402/payload/payload/authorization/validBefore",
    "/x402/payload/payload/authorization/value",
    "/x402/payload/payload/signature",
    "/x402/payload/resource/description",
    "/x402/payload/resource/mimeType",
    "/x402/payload/resource/url",
    "/x402/payload/x402Version",
    "/x402/requirements/amount",
    "/x402/requirements/asset",
    "/x402/requirements/extra/ap2MandateReference",
    "/x402/requirements/extra/ap2NonceDerivation",
    "/x402/requirements/extra/assetTransferMethod",
    "/x402/requirements/extra/name",
    "/x402/requirements/extra/version",
    "/x402/requirements/maxTimeoutSeconds",
    "/x402/requirements/network",
    "/x402/requirements/payTo",
    "/x402/requirements/scheme",
    "/x402/settlement/network",
    "/x402/settlement/payer",
    "/x402/settlement/success",
    "/x402/settlement/transaction",
)
PULSE_CONTAINER_PATH_DIGEST = "22721558cc9a4f37aa87d024a59816e3e08bd2ea3dc9a56f2a11d50321b34160"
PULSE_CONTAINER_PATHS = (
    "",
    "/ap2",
    "/ap2/closedMandate",
    "/ap2/closedMandate/payee",
    "/ap2/closedMandate/payment_amount",
    "/ap2/closedMandate/payment_instrument",
    "/ap2/closedMandate/payment_instrument/x402",
    "/ap2/closedMandate/payment_instrument/x402/ap2PaymentAmount",
    "/ap2/closedMandate/payment_instrument/x402/eip712Domain",
    "/ap2/openMandate",
    "/ap2/openMandate/cnf",
    "/ap2/openMandate/cnf/jwk",
    "/ap2/openMandate/constraints",
    "/ap2/openMandate/constraints/0",
    "/ap2/openMandate/constraints/1",
    "/ap2/openMandate/constraints/1/allowed",
    "/ap2/openMandate/constraints/1/allowed/0",
    "/ap2/openMandate/constraints/1/allowed/0/x402",
    "/ap2/openMandate/constraints/1/allowed/0/x402/ap2PaymentAmount",
    "/ap2/openMandate/constraints/1/allowed/0/x402/eip712Domain",
    "/ap2/openMandate/constraints/2",
    "/ap2/openMandate/constraints/3",
    "/ap2/openMandate/constraints/3/allowed",
    "/ap2/openMandate/constraints/3/allowed/0",
    "/ap2/paymentReceipt",
    "/ap2/verification",
    "/ap2/verification/cryptographicEvidence",
    "/ap2/verification/cryptographicEvidence/trustedReceiptPublicJwk",
    "/ap2/verification/cryptographicEvidence/trustedRootPublicJwk",
    "/expected",
    "/expected/failureCodes",
    "/sourcePins",
    "/x402",
    "/x402/payload",
    "/x402/payload/accepted",
    "/x402/payload/accepted/extra",
    "/x402/payload/payload",
    "/x402/payload/payload/authorization",
    "/x402/payload/resource",
    "/x402/requirements",
    "/x402/requirements/extra",
    "/x402/settlement",
)
PULSE_FAILURE_CODES = {
    "INPUT_SCHEMA_INVALID",
    "INPUT_HASH_MISMATCH",
    "AP2_CRYPTOGRAPHIC_EVIDENCE_INVALID",
    "AP2_CLOSED_MANDATE_UNVERIFIED",
    "AP2_OPEN_MANDATE_UNVERIFIED",
    "AP2_KEY_BINDING_UNVERIFIED",
    "AP2_CHECKOUT_BINDING_UNVERIFIED",
    "AP2_RECEIPT_UNVERIFIED",
    "AP2_CLOSED_MANDATE_REFERENCE_MISMATCH",
    "AP2_CLOSED_MANDATE_CLAIMS_HASH_MISMATCH",
    "AP2_OPEN_MANDATE_CLAIMS_HASH_MISMATCH",
    "AP2_PAYMENT_REFERENCE_MISMATCH",
    "AP2_CLOSED_TRANSACTION_ID_MISMATCH",
    "AP2_CONSTRAINT_VIOLATION",
    "AP2_UNSUPPORTED_CONSTRAINT",
    "AP2_OPEN_PRESET_MISMATCH",
    "AP2_VERIFICATION_CONTEXT_MISMATCH",
    "AP2_MANDATE_TIME_INVALID",
    "AP2_PAYMENT_INSTRUMENT_NOT_ALLOWED",
    "AP2_RECEIPT_NOT_SUCCESSFUL",
    "AP2_RECEIPT_REFERENCE_MISMATCH",
    "AP2_RECEIPT_TRANSACTION_MISMATCH",
    "AP2_X402_SCHEME_MISMATCH",
    "AP2_X402_NETWORK_MISMATCH",
    "AP2_X402_ASSET_MISMATCH",
    "AP2_X402_AMOUNT_MISMATCH",
    "AP2_X402_PAYEE_MISMATCH",
    "AP2_X402_COMMERCE_BINDING_MISMATCH",
    "AP2_X402_TIMEOUT_MISMATCH",
    "AP2_X402_EIP712_DOMAIN_MISMATCH",
    "X402_MANDATE_REFERENCE_MISMATCH",
    "X402_ACCEPTED_REQUIREMENTS_MISMATCH",
    "X402_UNSUPPORTED_EXTENSION",
    "EIP3009_PAYER_MISMATCH",
    "EIP3009_RECIPIENT_MISMATCH",
    "EIP3009_VALUE_MISMATCH",
    "EIP3009_VALID_AFTER_IN_FUTURE",
    "EIP3009_VALID_BEFORE_EXPIRED",
    "EIP3009_VALIDITY_EXCEEDS_TIMEOUT",
    "EIP3009_VALIDITY_EXCEEDS_AP2_EXPIRY",
    "EIP3009_NONCE_BINDING_MISMATCH",
    "EIP3009_SIGNATURE_INVALID",
    "SETTLEMENT_FAILED",
    "SETTLEMENT_NETWORK_MISMATCH",
    "SETTLEMENT_PAYER_MISMATCH",
    "SETTLEMENT_AMOUNT_MISMATCH",
    "SETTLEMENT_TRANSACTION_INVALID",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
NODE_VERSION_RE = re.compile(r"^v[0-9]+(?:\.[0-9]+){2}(?:[-+][0-9A-Za-z.-]+)?$")
NPM_VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){2}(?:[-+][0-9A-Za-z.-]+)?$")
EVM_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
DECIMAL_RULE_RE = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")
CREDENTIAL_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\b(?:private[_-]?key|secret[_-]?key)\s*[:=]"),
    re.compile(r"(?<![A-Za-z0-9])(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9]{20,}"),
    re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])"),
    re.compile(r"(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{10,}"),
)
HEX32_VALUE_RE = re.compile(r"(?<![0-9A-Fa-f])0x[0-9A-Fa-f]{64}(?![0-9A-Fa-f])")
PUBLIC_HEX32_JSON_KEYS = {
    "nonce",
    "expectednonce",
    "transaction",
    "networkconfirmationid",
    "expected",
    "actual",
}
SECRET_KEY_NAMES = {
    "apikey",
    "accesstoken",
    "refreshtoken",
    "clientsecret",
    "privatekey",
    "secretkey",
    "secret",
    "password",
    "passphrase",
    "mnemonic",
    "seedphrase",
    "signingkey",
    "d",
}


class CheckFailure(RuntimeError):
    """A fail-closed validation error."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailure(message)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_value(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def reject_non_finite_json_constant(value: str) -> None:
    raise CheckFailure(f"non-finite JSON number is prohibited: {value}")


def parse_finite_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise CheckFailure(f"non-finite JSON number is prohibited: {value}")
    return parsed


def unique_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CheckFailure(f"duplicate JSON object key is prohibited: {key}")
        result[key] = value
    return result


def parse_strict_json(raw: bytes, label: str) -> Any:
    require(bool(raw), f"{label}: zero-byte JSON file is prohibited")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CheckFailure(f"{label}: JSON must be UTF-8") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=unique_object_pairs,
            parse_constant=reject_non_finite_json_constant,
            parse_float=parse_finite_json_float,
        )
    except CheckFailure:
        raise
    except (json.JSONDecodeError, ValueError) as exc:
        raise CheckFailure(f"{label}: invalid strict JSON: {exc}") from exc


def read_regular_nonempty(path: Path) -> bytes:
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise CheckFailure(f"required file is missing or unreadable: {path}") from exc
    require(stat.S_ISREG(mode), f"required path must be a regular non-symlink file: {path}")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise CheckFailure(f"required file is unreadable: {path}") from exc
    require(bool(raw), f"zero-byte public file is prohibited: {path}")
    return raw


def load_json_file(path: Path) -> Any:
    return parse_strict_json(read_regular_nonempty(path), str(path))


def expect_object(value: Any, label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label}: expected object")
    return value


def expect_array(value: Any, label: str) -> list[Any]:
    require(isinstance(value, list), f"{label}: expected array")
    return value


def expect_nonempty_string(value: Any, label: str) -> str:
    require(isinstance(value, str) and bool(value), f"{label}: expected non-empty string")
    return value


def require_exact_keys(value: dict[str, Any], keys: set[str], label: str) -> None:
    actual = set(value)
    require(
        actual == keys,
        f"{label}: exact keys required; missing={sorted(keys - actual)} unknown={sorted(actual - keys)}",
    )


def primitive_leaf_paths(value: Any, path: str = "") -> list[str]:
    paths: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            escaped = key.replace("~", "~0").replace("/", "~1")
            paths.extend(primitive_leaf_paths(child, f"{path}/{escaped}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            paths.extend(primitive_leaf_paths(child, f"{path}/{index}"))
    else:
        paths.append(path)
    return paths


def container_paths(value: Any, path: str = "") -> list[str]:
    paths: list[str] = []
    if isinstance(value, dict):
        paths.append(path)
        for key, child in value.items():
            escaped = key.replace("~", "~0").replace("/", "~1")
            paths.extend(container_paths(child, f"{path}/{escaped}"))
    elif isinstance(value, list):
        paths.append(path)
        for index, child in enumerate(value):
            paths.extend(container_paths(child, f"{path}/{index}"))
    return paths


def json_pointer_value(value: Any, pointer: str, label: str) -> Any:
    require(pointer == "" or pointer.startswith("/"), f"{label}: invalid JSON Pointer")
    current = value
    if pointer == "":
        return current
    for raw_part in pointer[1:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            require(part in current, f"{label}: missing JSON Pointer target {pointer}")
            current = current[part]
        elif isinstance(current, list):
            require(part.isdigit(), f"{label}: array pointer must use a decimal index")
            index = int(part)
            require(index < len(current), f"{label}: array pointer out of range")
            current = current[index]
        else:
            raise CheckFailure(f"{label}: JSON Pointer traverses a primitive value")
    return current


def require_no_completion_sentinel(value: Any, label: str) -> None:
    sentinel_fragments = (
        "open_mapping_decision",
        "replace-with",
        "example.invalid",
        "template sentinel",
        "not recorded",
        "unmapped",
    )
    if isinstance(value, dict):
        for key, child in value.items():
            require_no_completion_sentinel(child, f"{label}/{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            require_no_completion_sentinel(child, f"{label}/{index}")
    elif isinstance(value, str):
        lowered = value.lower()
        for fragment in sentinel_fragments:
            require(fragment not in lowered, f"{label}: unresolved completion sentinel {fragment!r}")


def validate_mapping_source_boundary(source_document: str, pointer: str, label: str) -> None:
    require(
        not (source_document == "vate_case" and pointer.startswith("/expected")),
        f"{label}: VATE /expected source is prohibited",
    )
    require(
        source_document != "vate_admission_receipt",
        f"{label}: VATE admission receipt is comparison-only and prohibited as a source",
    )


def read_bundle_file(bundle_root: Path, raw_path: Any, label: str) -> tuple[str, bytes]:
    relative = validate_safe_repo_path(raw_path, f"{label}.path")
    try:
        root_mode = bundle_root.lstat().st_mode
    except OSError as exc:
        raise CheckFailure(f"{label}: bundle root is missing or unreadable") from exc
    require(stat.S_ISDIR(root_mode), f"{label}: bundle root must be a real directory, not a symlink")
    current = bundle_root
    parts = PurePosixPath(relative).parts
    for index, part in enumerate(parts):
        current = current / part
        try:
            mode = current.lstat().st_mode
        except OSError as exc:
            raise CheckFailure(f"{label}: referenced bundle path is missing: {relative}") from exc
        if index == len(parts) - 1:
            require(stat.S_ISREG(mode), f"{label}: reference must be a regular non-symlink file: {relative}")
        else:
            require(stat.S_ISDIR(mode), f"{label}: parent path must be a real directory: {relative}")
    raw = read_regular_nonempty(current)
    return relative, raw


def validate_bundle_ref(
    bundle_root: Path,
    value: Any,
    label: str,
    *,
    expected_digest: str | None = None,
) -> tuple[str, bytes, str]:
    reference = expect_object(value, label)
    require_exact_keys(reference, {"path", "raw_sha256"}, label)
    path, raw = read_bundle_file(bundle_root, reference.get("path"), label)
    recorded = validate_sha256(reference.get("raw_sha256"), f"{label}.raw_sha256")
    actual = sha256_bytes(raw)
    require(recorded == actual, f"{label}: raw SHA-256 does not match referenced bytes")
    if expected_digest is not None:
        require(actual == expected_digest, f"{label}: raw SHA-256 does not match the fixed expected digest")
    return path, raw, actual


def at(value: Any, *parts: str) -> Any:
    current = value
    walked: list[str] = []
    for part in parts:
        walked.append(part)
        require(isinstance(current, dict), f"/{'/'.join(walked[:-1])}: expected object")
        require(part in current, f"/{'/'.join(walked)}: required")
        current = current[part]
    return current


def validate_safe_repo_path(value: Any, label: str) -> str:
    path = expect_nonempty_string(value, label)
    pure = PurePosixPath(path)
    require(not pure.is_absolute(), f"{label}: absolute path is prohibited")
    require("\\" not in path and "\x00" not in path, f"{label}: unsafe path characters")
    require(path == pure.as_posix(), f"{label}: path must be normalized POSIX form")
    require(all(part not in {"", ".", ".."} for part in pure.parts), f"{label}: unsafe path segment")
    return path


def validate_sha256(value: Any, label: str) -> str:
    digest = expect_nonempty_string(value, label)
    require(SHA256_RE.fullmatch(digest) is not None, f"{label}: expected lowercase SHA-256 hex")
    return digest


def scan_text_for_credentials(text: str, label: str, *, allow_public_hex32: bool = False) -> None:
    for pattern in CREDENTIAL_PATTERNS:
        require(pattern.search(text) is None, f"{label}: unsafe secret-like material detected")
    if not allow_public_hex32:
        require(HEX32_VALUE_RE.search(text) is None, f"{label}: unsafe 32-byte hex material detected")


def scan_json_for_credentials(value: Any, label: str = "root", *, field_name: str | None = None) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", key.lower())
            require(normalized not in SECRET_KEY_NAMES, f"{label}/{key}: secret-bearing key is prohibited")
            scan_json_for_credentials(child, f"{label}/{key}", field_name=normalized)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            scan_json_for_credentials(child, f"{label}/{index}", field_name=field_name)
    elif isinstance(value, str):
        scan_text_for_credentials(
            value,
            label,
            allow_public_hex32=field_name in PUBLIC_HEX32_JSON_KEYS,
        )


def run_git(repo: Path, arguments: list[str]) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise CheckFailure(f"git {' '.join(arguments)} failed for {repo}: {stderr}")
    return result.stdout


def require_commit(repo: Path, commit: str, label: str) -> None:
    try:
        resolved = run_git(repo, ["rev-parse", "--verify", f"{commit}^{{commit}}"])
    except CheckFailure as exc:
        raise CheckFailure(f"{label}: exact commit is unavailable") from exc
    require(resolved.decode("ascii").strip() == commit, f"{label}: exact commit is unavailable")


def git_blob(repo: Path, commit: str, raw_path: Any, label: str) -> bytes:
    path = validate_safe_repo_path(raw_path, label)
    listing = run_git(repo, ["ls-tree", "--full-tree", commit, "--", path]).decode("utf-8")
    lines = [line for line in listing.splitlines() if line]
    require(len(lines) == 1, f"{label}: expected exactly one Git tree entry")
    metadata, separator, listed_path = lines[0].partition("\t")
    fields = metadata.split()
    require(separator == "\t" and listed_path == path, f"{label}: Git path identity mismatch")
    require(len(fields) == 3 and fields[1] == "blob", f"{label}: expected Git blob")
    require(fields[0] in {"100644", "100755"}, f"{label}: unsupported Git mode {fields[0]}")
    raw = run_git(repo, ["cat-file", "blob", f"{commit}:{path}"])
    require(bool(raw), f"{label}: zero-byte source blob is prohibited")
    return raw


@dataclass(frozen=True)
class SourceSnapshot:
    corpus: dict[str, Any]
    blobs: dict[str, bytes]
    manifest_hashes: dict[str, str]
    cases_by_id: dict[str, dict[str, Any]]


@dataclass(frozen=True)
class CandidateCommitFile:
    path: str
    git_mode: str
    raw_sha256: str
    raw: bytes


@dataclass(frozen=True)
class CandidateRuntimeIdentity:
    requested_absolute_path: str
    requested_file_type: str
    requested_link_target: str | None
    requested_device: int
    requested_inode: int
    requested_mode: int
    requested_size: int
    realpath: str
    realpath_file_type: str
    realpath_device: int
    realpath_inode: int
    realpath_mode: int
    realpath_size: int
    raw_sha256: str


@dataclass(frozen=True)
class CandidateRuntime:
    logical_name: str
    identity: CandidateRuntimeIdentity
    version: str


def load_source_snapshot(source_repo: Path) -> SourceSnapshot:
    require_commit(source_repo, VATE_COMMIT, "VATE source pin")
    corpus = expect_object(
        parse_strict_json(
            git_blob(source_repo, VATE_COMMIT, CORPUS_INDEX_PATH, "fixed corpus index"),
            f"{VATE_COMMIT}:{CORPUS_INDEX_PATH}",
        ),
        "fixed corpus index",
    )
    require(at(corpus, "profile") == PROFILE, "fixed corpus profile mismatch")
    require(at(corpus, "summary", "case_count") == 75, "fixed corpus case count mismatch")
    require(at(corpus, "summary", "artifact_count") == 212, "fixed corpus artifact count mismatch")

    manifest = expect_array(at(corpus, "manifest"), "fixed corpus manifest")
    require(len(manifest) == 212, "fixed corpus manifest must contain 212 entries")
    blobs: dict[str, bytes] = {}
    manifest_hashes: dict[str, str] = {}
    ordered_paths: list[str] = []
    for index, raw_entry in enumerate(manifest):
        entry = expect_object(raw_entry, f"fixed corpus manifest[{index}]")
        require(set(entry) == {"path", "sha256"}, f"fixed corpus manifest[{index}]: unexpected keys")
        path = validate_safe_repo_path(entry["path"], f"fixed corpus manifest[{index}].path")
        require(path not in manifest_hashes, f"fixed corpus manifest: duplicate path {path}")
        digest = validate_sha256(entry["sha256"], f"fixed corpus manifest[{index}].sha256")
        raw = git_blob(source_repo, VATE_COMMIT, path, f"fixed source {path}")
        require(sha256_bytes(raw) == digest, f"fixed source raw SHA-256 mismatch: {path}")
        ordered_paths.append(path)
        manifest_hashes[path] = digest
        blobs[path] = raw
    require(ordered_paths == sorted(ordered_paths), "fixed corpus manifest paths are not sorted")
    require(sha256_value(manifest) == CORPUS_DIGEST, "fixed corpus digest recomputation mismatch")
    require(
        at(corpus, "digest") == {"alg": "sha-256", "value": CORPUS_DIGEST},
        "fixed corpus recorded digest mismatch",
    )

    cases = expect_array(at(corpus, "cases"), "fixed corpus cases")
    require(len(cases) == 75, "fixed corpus index must contain 75 cases")
    cases_by_id: dict[str, dict[str, Any]] = {}
    case_paths: set[str] = set()
    for index, raw_case in enumerate(cases):
        case = expect_object(raw_case, f"fixed corpus cases[{index}]")
        case_id = expect_nonempty_string(case.get("case_id"), f"fixed corpus cases[{index}].case_id")
        case_path = validate_safe_repo_path(case.get("path"), f"fixed corpus cases[{index}].path")
        require(case_id not in cases_by_id, f"fixed corpus index: duplicate case_id {case_id}")
        require(case_path not in case_paths, f"fixed corpus index: duplicate case path {case_path}")
        require(case_path in manifest_hashes, f"fixed corpus case is absent from manifest: {case_path}")
        cases_by_id[case_id] = case
        case_paths.add(case_path)
    require(set(SELECTED_CASE_IDS).issubset(cases_by_id), "fixed corpus is missing a selected case")
    return SourceSnapshot(corpus, blobs, manifest_hashes, cases_by_id)


def load_archive_source_snapshot(
    source_root: Path,
    manifest: dict[str, Any],
) -> SourceSnapshot:
    """Load only the fixed starter closure from a ``.git``-free source tree.

    This lane proves that the committed starter manifest still binds the same
    12 source files.  It deliberately does not reconstruct or claim a replay of
    the historical 212-entry corpus manifest; that remains the responsibility
    of :func:`load_source_snapshot` in a full-history checkout.
    """

    raw_cases = expect_array(manifest.get("cases"), "archive-safe starter cases")
    require(len(raw_cases) == 3, "archive-safe starter manifest must contain exactly three cases")
    blobs: dict[str, bytes] = {}
    manifest_hashes: dict[str, str] = {}
    cases_by_id: dict[str, dict[str, Any]] = {}

    for case_index, raw_case in enumerate(raw_cases):
        starter_case = expect_object(raw_case, f"archive-safe starter cases[{case_index}]")
        case_id = expect_nonempty_string(
            starter_case.get("case_id"),
            f"archive-safe starter cases[{case_index}].case_id",
        )
        require(
            case_id == SELECTED_CASE_IDS[case_index],
            f"archive-safe starter case order/identity mismatch at index {case_index}",
        )
        inputs = expect_array(
            starter_case.get("inputs"),
            f"archive-safe starter case {case_id}.inputs",
        )
        require(
            len(inputs) == 4,
            f"archive-safe starter case {case_id} must contain four closure inputs",
        )
        case_path: str | None = None
        for input_index, raw_input in enumerate(inputs):
            entry = expect_object(
                raw_input,
                f"archive-safe starter case {case_id}.inputs[{input_index}]",
            )
            path = validate_safe_repo_path(
                entry.get("path"),
                f"archive-safe starter case {case_id}.inputs[{input_index}].path",
            )
            require(path not in manifest_hashes, f"archive-safe starter closure has duplicate path: {path}")
            expected_digest = validate_sha256(
                entry.get("raw_sha256"),
                f"archive-safe starter case {case_id}.inputs[{input_index}].raw_sha256",
            )
            raw = read_regular_nonempty(source_root / path)
            require(
                sha256_bytes(raw) == expected_digest,
                f"archive-safe current-tree raw SHA-256 mismatch: {path}",
            )
            blobs[path] = raw
            manifest_hashes[path] = expected_digest
            if entry.get("role") == "case" and entry.get("artifact_key") == "case":
                case_path = path

        require(case_path is not None, f"archive-safe starter case {case_id} lacks its case document")
        case_document = expect_object(
            parse_strict_json(blobs[case_path], f"archive-safe:{case_path}"),
            f"archive-safe case {case_id}",
        )
        require(case_document.get("case_id") == case_id, f"archive-safe case identity mismatch: {case_id}")
        cases_by_id[case_id] = {
            "case_id": case_id,
            "path": case_path,
        }

    require(
        len(blobs) == 12 and len(manifest_hashes) == 12,
        "archive-safe starter closure must contain 12 unique files",
    )
    return SourceSnapshot({}, blobs, manifest_hashes, cases_by_id)


def validate_manifest(manifest: dict[str, Any], source: SourceSnapshot) -> dict[str, dict[str, Any]]:
    require_exact_keys(
        manifest,
        {
            "version",
            "status",
            "claim_contract",
            "timebox_contract",
            "machine_coverage_contract",
            "candidate_execution_contract",
            "source",
            "target",
            "selected_input_set",
            "cases",
        },
        "starter manifest",
    )
    require(at(manifest, "version") == STARTER_MANIFEST_VERSION, "starter manifest version mismatch")
    require(at(manifest, "status") == "starter-kit", "starter manifest status mismatch")
    claim = expect_object(at(manifest, "claim_contract"), "starter claim contract")
    require(claim == EXPECTED_CLAIM_CONTRACT, "starter claim contract must retain the exact negative claim boundary")
    timebox = expect_object(at(manifest, "timebox_contract"), "starter timebox contract")
    require(timebox == EXPECTED_TIMEBOX_CONTRACT, "starter timebox contract mismatch")
    machine_coverage = expect_object(at(manifest, "machine_coverage_contract"), "starter machine coverage contract")
    require(
        machine_coverage == EXPECTED_MACHINE_COVERAGE_CONTRACT,
        "starter machine coverage contract must retain the exact bounded scope",
    )
    require(
        expect_object(at(manifest, "candidate_execution_contract"), "starter candidate execution contract")
        == EXPECTED_CANDIDATE_EXECUTION_CONTRACT,
        "starter candidate execution contract mismatch",
    )
    source_record = expect_object(at(manifest, "source"), "starter source")
    require_exact_keys(source_record, {"repository", "commit", "corpus"}, "starter source")
    corpus_record = expect_object(source_record.get("corpus"), "starter source corpus")
    require_exact_keys(corpus_record, {"root", "profile", "case_count", "artifact_count", "digest"}, "starter source corpus")
    require_exact_keys(expect_object(corpus_record.get("digest"), "starter source corpus digest"), {"alg", "basis", "value"}, "starter source corpus digest")
    require(source_record.get("repository") == "https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope", "starter VATE repository mismatch")
    require(at(manifest, "source", "commit") == VATE_COMMIT, "starter VATE pin mismatch")
    require(at(manifest, "source", "corpus", "root") == CORPUS_ROOT, "starter corpus root mismatch")
    require(at(manifest, "source", "corpus", "profile") == PROFILE, "starter corpus profile mismatch")
    require(at(manifest, "source", "corpus", "case_count") == 75, "starter corpus case count mismatch")
    require(at(manifest, "source", "corpus", "artifact_count") == 212, "starter corpus artifact count mismatch")
    require(at(manifest, "source", "corpus", "digest", "alg") == "sha-256", "starter corpus digest algorithm mismatch")
    require(at(manifest, "source", "corpus", "digest", "value") == CORPUS_DIGEST, "starter corpus digest mismatch")

    target = expect_object(at(manifest, "target"), "starter target")
    require_exact_keys(
        target,
        {"repository", "commit", "entry_point", "invocation_boundary", "reviewed_surface", "input_leaf_contract"},
        "starter target",
    )
    require(target.get("repository") == "https://github.com/shibutatsu/pulse-ap2-x402-conformance", "starter Pulse repository mismatch")
    require(at(manifest, "target", "commit") == PULSE_COMMIT, "starter Pulse pin mismatch")
    require(at(manifest, "target", "entry_point") == "src/verifier.ts#verifyConformanceCase", "starter Pulse entry point mismatch")
    invocation_boundary = expect_nonempty_string(at(manifest, "target", "invocation_boundary"), "Pulse invocation boundary")
    require("directly" in invocation_boundary and "Do not change" in invocation_boundary, "Pulse invocation boundary is incomplete")
    reviewed = expect_array(at(manifest, "target", "reviewed_surface"), "Pulse reviewed surface")
    reviewed_by_path: dict[str, str] = {}
    for index, raw_entry in enumerate(reviewed):
        entry = expect_object(raw_entry, f"Pulse reviewed surface[{index}]")
        require_exact_keys(entry, {"path", "raw_sha256"}, f"Pulse reviewed surface[{index}]")
        path = validate_safe_repo_path(entry.get("path"), f"Pulse reviewed surface[{index}].path")
        require(path not in reviewed_by_path, f"Pulse reviewed surface: duplicate path {path}")
        reviewed_by_path[path] = validate_sha256(entry.get("raw_sha256"), f"Pulse reviewed surface[{index}].raw_sha256")
    require(reviewed_by_path == PULSE_REVIEWED_SURFACE, "Pulse reviewed surface path/hash set mismatch")
    leaf_contract = expect_object(target.get("input_leaf_contract"), "Pulse input leaf contract")
    require_exact_keys(
        leaf_contract,
        {
            "source_path",
            "source_raw_sha256",
            "reference_case_id",
            "primitive_leaf_count",
            "primitive_leaf_path_digest",
            "container_count",
            "container_path_digest",
            "required_empty_containers",
        },
        "Pulse input leaf contract",
    )
    require(leaf_contract.get("source_path") == "fixtures/v0.3/cases.json", "Pulse leaf source path mismatch")
    require(leaf_contract.get("source_raw_sha256") == PULSE_REVIEWED_SURFACE["fixtures/v0.3/cases.json"], "Pulse leaf source hash mismatch")
    require(leaf_contract.get("reference_case_id") == PULSE_REFERENCE_CASE_ID, "Pulse reference case mismatch")
    require(leaf_contract.get("primitive_leaf_count") == 142, "Pulse primitive leaf count mismatch")
    require(leaf_contract.get("primitive_leaf_path_digest") == PULSE_LEAF_PATH_DIGEST, "Pulse primitive leaf digest mismatch")
    require(leaf_contract.get("container_count") == 42, "Pulse container count mismatch")
    require(leaf_contract.get("container_path_digest") == PULSE_CONTAINER_PATH_DIGEST, "Pulse container digest mismatch")
    require(tuple(leaf_contract.get("required_empty_containers", [])) == PULSE_REQUIRED_EMPTY_CONTAINERS, "Pulse required empty-container contract mismatch")

    selected_set = expect_object(at(manifest, "selected_input_set"), "starter selected_input_set")
    require_exact_keys(selected_set, {"entry_count", "digest"}, "starter selected_input_set")
    require_exact_keys(expect_object(selected_set.get("digest"), "starter selected_input_set.digest"), {"alg", "basis", "value"}, "starter selected_input_set.digest")

    raw_cases = expect_array(at(manifest, "cases"), "starter cases")
    require(len(raw_cases) == 3, "starter manifest must contain exactly three cases")
    selected_by_id: dict[str, dict[str, Any]] = {}
    selected_entries: list[dict[str, str]] = []
    selected_paths: set[str] = set()
    for index, raw_starter_case in enumerate(raw_cases):
        starter_case = expect_object(raw_starter_case, f"starter cases[{index}]")
        require_exact_keys(starter_case, {"case_id", "input_closure_digest", "inputs"}, f"starter cases[{index}]")
        require_exact_keys(expect_object(starter_case.get("input_closure_digest"), f"starter cases[{index}].input_closure_digest"), {"alg", "basis", "value"}, f"starter cases[{index}].input_closure_digest")
        case_id = expect_nonempty_string(starter_case.get("case_id"), f"starter cases[{index}].case_id")
        require(case_id == SELECTED_CASE_IDS[index], f"starter case order/identity mismatch at index {index}")
        require(case_id not in selected_by_id, f"starter manifest: duplicate case_id {case_id}")
        corpus_case = source.cases_by_id[case_id]
        case_path = validate_safe_repo_path(corpus_case.get("path"), f"fixed case path for {case_id}")
        case_document = expect_object(
            parse_strict_json(source.blobs[case_path], f"{VATE_COMMIT}:{case_path}"),
            f"fixed case {case_id}",
        )
        require(case_document.get("case_id") == case_id, f"fixed case document identity mismatch: {case_id}")
        artifacts = expect_object(case_document.get("artifacts"), f"fixed case {case_id}.artifacts")
        require(
            set(artifacts) == {"admission_request", "admission_receipt", "ap2_mandate"},
            f"fixed case artifact closure changed: {case_id}",
        )
        expected_inputs = (
            ("case", "case", case_path, "selection-and-closure-only"),
            ("source", "admission_request", artifacts["admission_request"], "eligible source bytes"),
            ("source", "ap2_mandate", artifacts["ap2_mandate"], "eligible source bytes"),
            ("comparison-only", "admission_receipt", artifacts["admission_receipt"], "prohibited as a Pulse input"),
        )
        inputs = expect_array(starter_case.get("inputs"), f"starter case {case_id}.inputs")
        require(len(inputs) == 4, f"starter case {case_id}: closure must have four inputs")
        closure_entries: list[dict[str, str]] = []
        local_paths: set[str] = set()
        for input_index, (raw_input, expected) in enumerate(zip(inputs, expected_inputs, strict=True)):
            entry = expect_object(raw_input, f"starter case {case_id}.inputs[{input_index}]")
            require_exact_keys(
                entry,
                {"role", "artifact_key", "path", "raw_sha256", "mapping_use"},
                f"starter case {case_id}.inputs[{input_index}]",
            )
            role, artifact_key, expected_path, mapping_phrase = expected
            require(entry.get("role") == role, f"starter case {case_id}: role mismatch for {artifact_key}")
            require(entry.get("artifact_key") == artifact_key, f"starter case {case_id}: artifact key mismatch")
            path = validate_safe_repo_path(entry.get("path"), f"starter case {case_id}.{artifact_key}.path")
            require(path not in local_paths, f"starter case {case_id}: duplicate closure path {path}")
            require(path not in selected_paths, f"starter selected set: duplicate path {path}")
            require(path == expected_path, f"starter case {case_id}: path mismatch for {artifact_key}")
            require(path in source.manifest_hashes, f"starter case {case_id}: path absent from fixed manifest")
            raw_digest = validate_sha256(entry.get("raw_sha256"), f"starter case {case_id}.{artifact_key}.raw_sha256")
            require(raw_digest == source.manifest_hashes[path], f"starter case {case_id}: raw hash mismatch for {artifact_key}")
            mapping_use = expect_nonempty_string(entry.get("mapping_use"), f"starter case {case_id}.{artifact_key}.mapping_use")
            require(mapping_phrase in mapping_use, f"starter case {case_id}: mapping boundary mismatch for {artifact_key}")
            local_paths.add(path)
            selected_paths.add(path)
            closure_entry = {"path": path, "sha256": raw_digest}
            closure_entries.append(closure_entry)
            selected_entries.append(closure_entry)
        closure_digest = sha256_value(sorted(closure_entries, key=lambda item: item["path"]))
        require(closure_digest == EXPECTED_CLOSURE_DIGESTS[case_id], f"starter case closure digest changed: {case_id}")
        require(at(starter_case, "input_closure_digest", "alg") == "sha-256", f"starter case closure algorithm mismatch: {case_id}")
        require(at(starter_case, "input_closure_digest", "value") == closure_digest, f"starter recorded closure digest mismatch: {case_id}")
        selected_by_id[case_id] = starter_case

    require(len(selected_entries) == 12 and len(selected_paths) == 12, "starter selected closure must contain 12 unique paths")
    selected_digest = sha256_value(sorted(selected_entries, key=lambda item: item["path"]))
    require(selected_digest == SELECTED_SET_DIGEST, "starter selected input-set digest changed")
    require(at(manifest, "selected_input_set", "entry_count") == 12, "starter selected input count mismatch")
    require(at(manifest, "selected_input_set", "digest", "alg") == "sha-256", "starter selected digest algorithm mismatch")
    require(at(manifest, "selected_input_set", "digest", "value") == selected_digest, "starter recorded selected digest mismatch")
    return selected_by_id


def validate_worksheet(
    worksheet: dict[str, Any],
    selected_by_id: dict[str, dict[str, Any]],
    *,
    source: SourceSnapshot | None = None,
    completed: bool = False,
) -> None:
    require_exact_keys(
        worksheet,
        {
            "version",
            "status",
            "ownership",
            "pins",
            "leaf_contract",
            "case_sources",
            "prohibited_sources",
            "scaffolding_inputs",
            "required_coverage_topics",
            "mapping_rows",
            "generated_field_inventory",
            "completion_requirements",
        },
        "mapping worksheet",
    )
    require(at(worksheet, "version") == WORKSHEET_VERSION, "worksheet version mismatch")
    expected_status = "completed" if completed else "template"
    require(at(worksheet, "status") == expected_status, f"worksheet status must be {expected_status}")
    require_exact_keys(
        expect_object(at(worksheet, "ownership"), "worksheet ownership"),
        {"final_mapping_source", "final_projection_source", "pulse_verifier", "instructions"},
        "worksheet ownership",
    )
    require_exact_keys(
        expect_object(at(worksheet, "pins"), "worksheet pins"),
        {"vate_source_commit", "vate_corpus_digest", "pulse_verifier_commit"},
        "worksheet pins",
    )
    require(at(worksheet, "ownership", "final_mapping_source") == "candidate_owned", "worksheet final mapping owner mismatch")
    require(at(worksheet, "ownership", "final_projection_source") == "candidate_owned", "worksheet final projection owner mismatch")
    require(at(worksheet, "ownership", "pulse_verifier") == "frozen_upstream", "worksheet verifier boundary mismatch")
    require(at(worksheet, "pins", "vate_source_commit") == VATE_COMMIT, "worksheet VATE pin mismatch")
    require(at(worksheet, "pins", "vate_corpus_digest") == CORPUS_DIGEST, "worksheet corpus digest mismatch")
    require(at(worksheet, "pins", "pulse_verifier_commit") == PULSE_COMMIT, "worksheet Pulse pin mismatch")
    leaf_contract = expect_object(at(worksheet, "leaf_contract"), "worksheet leaf contract")
    require_exact_keys(
        leaf_contract,
        {
            "reference_pulse_case",
            "primitive_leaf_count",
            "primitive_leaf_path_digest",
            "container_count",
            "container_path_digest",
            "machine_coverage_scope",
            "required_empty_containers",
            "basis",
        },
        "worksheet leaf contract",
    )
    require(leaf_contract.get("reference_pulse_case") == PULSE_REFERENCE_CASE_ID, "worksheet reference Pulse case mismatch")
    require(leaf_contract.get("primitive_leaf_count") == 142, "worksheet leaf count mismatch")
    require(leaf_contract.get("primitive_leaf_path_digest") == PULSE_LEAF_PATH_DIGEST, "worksheet leaf digest mismatch")
    require(leaf_contract.get("container_count") == 42, "worksheet container count mismatch")
    require(leaf_contract.get("container_path_digest") == PULSE_CONTAINER_PATH_DIGEST, "worksheet container digest mismatch")
    require(leaf_contract.get("machine_coverage_scope") == MACHINE_COVERAGE_SCOPE, "worksheet machine coverage scope mismatch")
    require(tuple(leaf_contract.get("required_empty_containers", [])) == PULSE_REQUIRED_EMPTY_CONTAINERS, "worksheet required empty-container mismatch")

    case_sources = expect_array(at(worksheet, "case_sources"), "worksheet case_sources")
    require(len(case_sources) == 3, "worksheet must contain exactly three case source records")
    for index, raw_source in enumerate(case_sources):
        source_record = expect_object(raw_source, f"worksheet case_sources[{index}]")
        case_id = source_record.get("case_id")
        require(case_id == SELECTED_CASE_IDS[index], f"worksheet case source order/identity mismatch at index {index}")
        starter_inputs = {
            item["artifact_key"]: item
            for item in expect_array(selected_by_id[case_id]["inputs"], f"manifest inputs for {case_id}")
        }
        require(set(source_record) == {"case_id", "admission_request", "ap2_mandate"}, f"worksheet {case_id}: only eligible source artifacts may be listed")
        for artifact_key in ("admission_request", "ap2_mandate"):
            worksheet_ref = expect_object(source_record[artifact_key], f"worksheet {case_id}.{artifact_key}")
            require_exact_keys(worksheet_ref, {"path", "raw_sha256"}, f"worksheet {case_id}.{artifact_key}")
            manifest_ref = starter_inputs[artifact_key]
            require(worksheet_ref.get("path") == manifest_ref["path"], f"worksheet {case_id}: source path mismatch for {artifact_key}")
            require(worksheet_ref.get("raw_sha256") == manifest_ref["raw_sha256"], f"worksheet {case_id}: source hash mismatch for {artifact_key}")

    fixed_vate_documents: dict[str, list[dict[str, Any]]] = {
        "vate_admission_request": [],
        "vate_ap2_mandate": [],
    }
    if source is not None:
        for case_id in SELECTED_CASE_IDS:
            inputs_by_key = {
                item["artifact_key"]: item
                for item in expect_array(selected_by_id[case_id]["inputs"], f"manifest inputs for {case_id}")
            }
            for source_document, artifact_key in (
                ("vate_admission_request", "admission_request"),
                ("vate_ap2_mandate", "ap2_mandate"),
            ):
                path = inputs_by_key[artifact_key]["path"]
                fixed_vate_documents[source_document].append(
                    expect_object(
                        parse_strict_json(source.blobs[path], f"{VATE_COMMIT}:{path}"),
                        f"fixed {source_document} for {case_id}",
                    )
                )

    prohibited = expect_array(at(worksheet, "prohibited_sources"), "worksheet prohibited_sources")
    prohibited_pairs: set[tuple[Any, Any]] = set()
    for index, raw_entry in enumerate(prohibited):
        entry = expect_object(raw_entry, f"worksheet prohibited_sources[{index}]")
        require_exact_keys(entry, {"document", "json_pointer_prefix", "reason"}, f"worksheet prohibited_sources[{index}]")
        prohibited_pairs.add((entry.get("document"), entry.get("json_pointer_prefix")))
    require(("vate_case", "/expected") in prohibited_pairs, "worksheet must prohibit VATE expected lookup")
    require(("vate_admission_receipt", "") in prohibited_pairs, "worksheet must prohibit VATE admission receipt mapping")

    scaffolding = expect_object(at(worksheet, "scaffolding_inputs"), "worksheet scaffolding_inputs")
    require_exact_keys(
        scaffolding,
        {
            "pulse_profile",
            "asset_profile",
            "evm_participants",
            "merchant_profile",
            "instrument_profile",
            "x402_profile",
            "ap2_generation_profile",
            "resource_profile",
            "settlement_profile",
            "fixture_key_handling",
            "pulse_expected_envelope",
        },
        "worksheet scaffolding_inputs",
    )
    profile = expect_object(at(worksheet, "scaffolding_inputs", "pulse_profile"), "worksheet Pulse profile")
    require_exact_keys(profile, {"ownership", "status", "case_version", "source_pins", "boundary"}, "worksheet Pulse profile")
    require_exact_keys(expect_object(profile.get("source_pins"), "worksheet Pulse source_pins"), {"ap2Commit", "x402Commit", "x402PackageVersion"}, "worksheet Pulse source_pins")
    require(profile.get("ownership") == "candidate_owned", "worksheet Pulse profile owner mismatch")
    require(profile.get("status") == "fixed_invocation_scaffolding", "worksheet Pulse profile status mismatch")
    require(profile.get("case_version") == "ap2-x402-conformance/0.3", "worksheet Pulse case version mismatch")
    require(
        profile.get("source_pins")
        == {
            "ap2Commit": "e1ea56db72a6385bce3e5c1112b3a56ce60acb43",
            "x402Commit": "17d319fab5c17a6b4873eb41197894db924f59ed",
            "x402PackageVersion": "2.23.0",
        },
        "worksheet Pulse v0.3 sourcePins mismatch",
    )
    asset = expect_object(at(worksheet, "scaffolding_inputs", "asset_profile"), "worksheet asset profile")
    require_exact_keys(asset, {"ownership", "status", "network", "asset", "decimals", "usd_to_asset_conversion", "boundary"}, "worksheet asset profile")
    conversion = expect_object(asset.get("usd_to_asset_conversion"), "worksheet USD-to-asset conversion")
    require_exact_keys(conversion, {"asset_units_per_usd", "rounding"}, "worksheet USD-to-asset conversion")
    require(conversion.get("rounding") == "reject_non_integral", "worksheet atomic rounding policy mismatch")
    participants = expect_object(at(worksheet, "scaffolding_inputs", "evm_participants"), "worksheet EVM participants")
    require_exact_keys(participants, {"ownership", "status", "payer", "pay_to", "boundary"}, "worksheet EVM participants")
    merchant_profile = expect_object(scaffolding["merchant_profile"], "worksheet merchant profile")
    require_exact_keys(merchant_profile, {"ownership", "status", "id_transform", "name_transform", "website_transform"}, "worksheet merchant profile")
    require(merchant_profile.get("id_transform") == "exact-source-merchant", "worksheet Merchant.id transform mismatch")
    require_exact_keys(expect_object(scaffolding["instrument_profile"], "worksheet instrument profile"), {"ownership", "status", "id_transform", "description"}, "worksheet instrument profile")
    x402 = expect_object(at(worksheet, "scaffolding_inputs", "x402_profile"), "worksheet x402 profile")
    require_exact_keys(
        x402,
        {"ownership", "status", "version", "scheme", "max_timeout_seconds", "eip712_domain_name", "eip712_domain_version", "asset_transfer_method", "nonce_derivation"},
        "worksheet x402 profile",
    )
    require(x402.get("version") == 2 and x402.get("scheme") == "exact", "worksheet x402 fixed literals mismatch")
    require(x402.get("nonce_derivation") == "base64url-decode-ap2-mandate-reference", "worksheet x402 nonce derivation mismatch")
    neutral_expected = expect_object(at(worksheet, "scaffolding_inputs", "pulse_expected_envelope"), "worksheet neutral expected envelope")
    require_exact_keys(neutral_expected, {"ownership", "status", "value", "boundary"}, "worksheet neutral expected envelope")
    require_exact_keys(expect_object(neutral_expected.get("value"), "worksheet neutral expected value"), {"consistent", "failureCodes"}, "worksheet neutral expected value")
    require(neutral_expected.get("value") == {"consistent": True, "failureCodes": []}, "worksheet neutral Pulse expected envelope changed")
    require_exact_keys(
        expect_object(scaffolding["ap2_generation_profile"], "worksheet AP2 generation profile"),
        {
            "ownership",
            "status",
            "verifier_label",
            "clock_skew_seconds",
            "expected_audience",
            "evaluation_time_transform",
            "window_transform",
            "execution_date_transform",
            "expected_nonce_transform",
            "open_issuer_key_label",
            "terminal_holder_key_label",
            "receipt_issuer_key_label",
            "receipt_issuer",
            "receipt_status",
            "payment_id_transform",
            "psp_confirmation_id_transform",
            "network_confirmation_id_transform",
        },
        "worksheet AP2 generation profile",
    )
    ap2_profile = expect_object(scaffolding["ap2_generation_profile"], "worksheet AP2 generation profile")
    require(ap2_profile.get("evaluation_time_transform") == "admission-request-issued-at", "worksheet evaluation-time transform mismatch")
    require(ap2_profile.get("window_transform") == "intersection-of-request-expiry-mandate-window-and-timeout", "worksheet window transform mismatch")
    require(ap2_profile.get("execution_date_transform") == "admission-request-issued-at", "worksheet execution-date transform mismatch")
    require(ap2_profile.get("expected_nonce_transform") == "exact-vate-replay-nonce", "worksheet expected-nonce transform mismatch")
    require_exact_keys(expect_object(scaffolding["resource_profile"], "worksheet resource profile"), {"ownership", "status", "description", "mime_type"}, "worksheet resource profile")
    require_exact_keys(expect_object(scaffolding["settlement_profile"], "worksheet settlement profile"), {"ownership", "status", "success", "transaction_transform"}, "worksheet settlement profile")
    require_exact_keys(expect_object(scaffolding["fixture_key_handling"], "worksheet fixture key handling"), {"ownership", "status", "candidate_source", "required_record"}, "worksheet fixture key handling")
    open_sections = (
        "asset_profile",
        "evm_participants",
        "merchant_profile",
        "instrument_profile",
        "x402_profile",
        "ap2_generation_profile",
        "resource_profile",
        "settlement_profile",
        "fixture_key_handling",
    )
    for section_name in open_sections:
        section = expect_object(scaffolding[section_name], f"worksheet scaffolding {section_name}")
        if completed:
            require(section.get("ownership") == "candidate_owned", f"completed worksheet {section_name} ownership must be candidate_owned")
            require(section.get("status") == "completed", f"completed worksheet {section_name} status must be completed")
            for key, value in section.items():
                if key not in {"boundary", "required_record"}:
                    require(value is not None, f"completed worksheet {section_name}.{key} must be resolved")
        else:
            require(section.get("ownership") == "open_mapping_decision", f"template worksheet {section_name} ownership must remain open")
            require(section.get("status") == "open_mapping_decision", f"template worksheet {section_name} status must remain open")
    if completed:
        require(re.fullmatch(r"eip155:[1-9][0-9]*", str(asset.get("network", ""))) is not None, "completed worksheet asset network is invalid")
        require(EVM_ADDRESS_RE.fullmatch(str(asset.get("asset", ""))) is not None, "completed worksheet asset address is invalid")
        require(isinstance(asset.get("decimals"), int) and not isinstance(asset.get("decimals"), bool) and 0 <= asset["decimals"] <= 36, "completed worksheet asset decimals are invalid")
        units_per_usd = expect_nonempty_string(conversion.get("asset_units_per_usd"), "completed worksheet asset units per USD")
        require(DECIMAL_RULE_RE.fullmatch(units_per_usd) is not None, "completed worksheet asset units per USD is invalid")
        try:
            require(Decimal(units_per_usd) > 0, "completed worksheet asset units per USD must be positive")
        except InvalidOperation as exc:
            raise CheckFailure("completed worksheet asset units per USD is invalid") from exc
        for field in ("payer", "pay_to"):
            require(EVM_ADDRESS_RE.fullmatch(str(participants.get(field, ""))) is not None, f"completed worksheet {field} is invalid")
        require(isinstance(x402.get("max_timeout_seconds"), int) and x402["max_timeout_seconds"] > 0, "completed worksheet x402 timeout is invalid")
        expect_nonempty_string(x402.get("eip712_domain_name"), "completed worksheet EIP-712 domain name")
        expect_nonempty_string(x402.get("eip712_domain_version"), "completed worksheet EIP-712 domain version")
        require(isinstance(scaffolding["settlement_profile"].get("success"), bool), "completed worksheet settlement success must be boolean")
        require_no_completion_sentinel(worksheet, "completed worksheet")

    topics = expect_array(at(worksheet, "required_coverage_topics"), "worksheet required coverage topics")
    require(len(topics) == len(set(topics)), "worksheet required coverage topics contain duplicates")
    require(set(topics) == EXPECTED_TOPICS, "worksheet required coverage topics are incomplete")

    rows = expect_array(at(worksheet, "mapping_rows"), "worksheet mapping rows")
    rows_by_id: dict[str, dict[str, Any]] = {}
    destination_keys: set[tuple[str, str]] = set()
    starter_manifest_for_rows = expect_object(
        parse_strict_json(read_regular_nonempty(MANIFEST_PATH), "starter manifest for mapping-row pointers"),
        "starter manifest for mapping-row pointers",
    )
    allowed_source_documents = {
        "starter_manifest",
        "candidate_execution_request",
        "vate_admission_request",
        "vate_ap2_mandate",
        "pulse_case",
        "worksheet",
        "generated_ap2_artifacts",
        "pulse_case_preimage",
        "raw_pulse_output",
    }
    for index, raw_row in enumerate(rows):
        row = expect_object(raw_row, f"worksheet mapping_rows[{index}]")
        required_fields = {
            "row_id",
            "case_ids",
            "source_document",
            "source_json_pointer",
            "transform",
            "pulse_destination",
            "provenance",
            "ownership",
            "decision_relevant",
        }
        require_exact_keys(row, required_fields, f"worksheet mapping_rows[{index}]")
        row_id = expect_nonempty_string(row.get("row_id"), f"worksheet mapping_rows[{index}].row_id")
        require(row_id not in rows_by_id, f"worksheet mapping rows: duplicate row_id {row_id}")
        case_ids = expect_array(row.get("case_ids"), f"worksheet row {row_id}.case_ids")
        require(tuple(case_ids) == SELECTED_CASE_IDS, f"worksheet row {row_id}: selected-case coverage mismatch")
        source_document = expect_nonempty_string(row.get("source_document"), f"worksheet row {row_id}.source_document")
        pointer = row.get("source_json_pointer")
        require(isinstance(pointer, str) and (pointer == "" or pointer.startswith("/")), f"worksheet row {row_id}: invalid source JSON Pointer")
        validate_mapping_source_boundary(source_document, pointer, f"worksheet row {row_id}")
        require(source_document in allowed_source_documents, f"worksheet row {row_id}: unknown source document")
        if source_document == "worksheet":
            json_pointer_value(worksheet, pointer, f"worksheet row {row_id}.source_json_pointer")
        if source_document in fixed_vate_documents and source is not None:
            for case_index, document in enumerate(fixed_vate_documents[source_document]):
                json_pointer_value(document, pointer, f"worksheet row {row_id}.source_json_pointer case[{case_index}]")
        if source_document == "starter_manifest":
            for case_index in range(3):
                expanded_pointer = pointer.replace("{case_index}", str(case_index))
                json_pointer_value(starter_manifest_for_rows, expanded_pointer, f"worksheet row {row_id}.source_json_pointer")
        if source_document == "candidate_execution_request":
            require(
                pointer == "/items/{case_index}/workItemId",
                f"worksheet row {row_id}: candidate execution request pointer mismatch",
            )
        if source_document == "pulse_case":
            require(
                pointer == "" or pointer in PULSE_PRIMITIVE_LEAF_PATHS or pointer in PULSE_CONTAINER_PATHS,
                f"worksheet row {row_id}: pulse_case source pointer does not exist in the fixed input contract",
            )
        if source_document == "pulse_case_preimage":
            require(pointer in PULSE_CONTAINER_PATHS, f"worksheet row {row_id}: pulse preimage pointer does not exist")
        if source_document == "generated_ap2_artifacts":
            require(pointer == "/closedPaymentMandateLeafJwt", f"worksheet row {row_id}: unknown generated AP2 artifact pointer")
        if source_document == "raw_pulse_output":
            require(
                re.fullmatch(r"/reports/\{case_index\}(?:/(?:consistent|failures))?", pointer) is not None,
                f"worksheet row {row_id}: unknown raw Pulse output pointer",
            )
        transform = expect_nonempty_string(row.get("transform"), f"worksheet row {row_id}.transform")
        destination = expect_nonempty_string(row.get("pulse_destination"), f"worksheet row {row_id}.pulse_destination")
        require(destination.startswith("/"), f"worksheet row {row_id}: invalid Pulse destination")
        provenance = row.get("provenance")
        require(provenance in {"vate-derived", "non-vate-scaffolding"}, f"worksheet row {row_id}: invalid provenance")
        ownership = row.get("ownership")
        require(ownership in {"candidate_owned", "open_mapping_decision"}, f"worksheet row {row_id}: invalid ownership")
        require(isinstance(row.get("decision_relevant"), bool), f"worksheet row {row_id}: decision_relevant must be boolean")
        if completed:
            require(ownership == "candidate_owned", f"completed worksheet row {row_id}: ownership must be candidate_owned")
        key = (source_document, destination)
        require(key not in destination_keys, f"worksheet mapping rows: duplicate source/destination mapping {key}")
        destination_keys.add(key)
        rows_by_id[row_id] = row
    require(REQUIRED_ROW_IDS.issubset(rows_by_id), f"worksheet missing required rows: {sorted(REQUIRED_ROW_IDS - set(rows_by_id))}")

    row_contracts = {
        "request-usd-minor-units": ("/constraints/max_amount/value", "/ap2/closedMandate/payment_amount/amount", "multiply by 100"),
        "request-atomic-amount": ("/constraints/max_amount/value", "/x402/requirements/amount", "exact decimal"),
        "permitted-atomic-amount": ("/constraints/max_amount/value", "/ap2/closedMandate/payment_instrument/x402/amount", "permitted atomic amount"),
        "merchant-payee-id": ("/merchant", "/ap2/closedMandate/payee/id", "Merchant.id"),
        "evaluation-time": ("/issued_at", "/nowEpochSeconds", "Unix epoch seconds"),
        "terminal-key-binding-nonce": ("/constraints/replay_nonce", "/ap2/verification/cryptographicEvidence/expectedNonce", "copy exactly"),
        "eip3009-nonce": ("/ap2/verification/closedMandateReference", "/x402/payload/payload/authorization/nonce", "exactly 32 bytes"),
        "observed-pulse-report": ("/reports/{case_index}", "/external_run/case_runs/{case_index}", "raw SHA-256"),
    }
    for row_id, (source_pointer, destination, transform_phrase) in row_contracts.items():
        row = rows_by_id[row_id]
        require(row["source_json_pointer"] == source_pointer, f"worksheet row {row_id}: source pointer mismatch")
        require(row["pulse_destination"] == destination, f"worksheet row {row_id}: destination mismatch")
        require(transform_phrase in row["transform"], f"worksheet row {row_id}: transform lost required boundary")
    if not completed:
        require(rows_by_id["request-atomic-amount"]["ownership"] == "open_mapping_decision", "atomic conversion must remain an open candidate decision")
        for row_id in ("pulse-to-vate-outcome", "pulse-to-vate-execution-gate", "pulse-to-vate-reasons", "pulse-to-vate-checks"):
            require(rows_by_id[row_id]["ownership"] == "open_mapping_decision", f"worksheet row {row_id}: projection must remain open")

    inventory = expect_array(at(worksheet, "generated_field_inventory"), "worksheet generated field inventory")
    require(len(inventory) == 142, "worksheet generated inventory must contain exactly 142 primitive leaves")
    inventory_destinations: list[str] = []
    inventory_by_destination: dict[str, dict[str, Any]] = {}
    pulse_leaf_edges: dict[str, list[str]] = {}
    starter_manifest_document = expect_object(
        parse_strict_json(read_regular_nonempty(MANIFEST_PATH), "starter manifest for worksheet pointers"),
        "starter manifest for worksheet pointers",
    )
    allowed_inventory_sources = {
        "starter_manifest",
        "candidate_execution_request",
        "vate_admission_request",
        "vate_ap2_mandate",
        "pulse_case",
        "worksheet",
        "candidate_generator_output",
    }
    dependency_prefixes = ("mapping_row:", "pulse_leaf:", "scaffold:", "generator:")
    for index, raw_leaf in enumerate(inventory):
        leaf = expect_object(raw_leaf, f"worksheet generated_field_inventory[{index}]")
        require_exact_keys(
            leaf,
            {
                "pulse_destination",
                "source_document",
                "source_json_pointer",
                "dependencies",
                "transform",
                "provenance",
                "ownership",
            },
            f"worksheet generated_field_inventory[{index}]",
        )
        destination = expect_nonempty_string(leaf.get("pulse_destination"), f"worksheet generated leaf[{index}].pulse_destination")
        require(destination.startswith("/"), f"worksheet generated leaf[{index}]: invalid Pulse destination")
        require(destination not in inventory_by_destination, f"worksheet generated inventory: duplicate destination {destination}")
        source_document = expect_nonempty_string(leaf.get("source_document"), f"worksheet generated leaf {destination}.source_document")
        pointer = leaf.get("source_json_pointer")
        require(isinstance(pointer, str) and (pointer == "" or pointer.startswith("/")), f"worksheet generated leaf {destination}: invalid source JSON Pointer")
        validate_mapping_source_boundary(source_document, pointer, f"worksheet generated leaf {destination}")
        require(source_document in allowed_inventory_sources, f"worksheet generated leaf {destination}: unknown source document")
        if source_document == "worksheet":
            json_pointer_value(worksheet, pointer, f"worksheet generated leaf {destination}.source_json_pointer")
        if source_document in fixed_vate_documents and source is not None:
            for case_index, document in enumerate(fixed_vate_documents[source_document]):
                json_pointer_value(document, pointer, f"worksheet generated leaf {destination}.source_json_pointer case[{case_index}]")
        if source_document == "starter_manifest":
            for case_index in range(3):
                expanded_pointer = pointer.replace("{case_index}", str(case_index))
                json_pointer_value(
                    starter_manifest_document,
                    expanded_pointer,
                    f"worksheet generated leaf {destination}.source_json_pointer",
                )
        if source_document == "candidate_execution_request":
            require(
                pointer == "/items/{case_index}/workItemId",
                f"worksheet generated leaf {destination}: candidate execution request pointer mismatch",
            )
        if source_document == "pulse_case":
            require(
                pointer in PULSE_PRIMITIVE_LEAF_PATHS or pointer in PULSE_CONTAINER_PATHS,
                f"worksheet generated leaf {destination}: pulse_case source pointer does not exist in the fixed input contract",
            )
        if source_document == "candidate_generator_output":
            require(pointer == destination, f"worksheet generated leaf {destination}: generator pointer must bind the same Pulse leaf")
        dependencies = expect_array(leaf.get("dependencies"), f"worksheet generated leaf {destination}.dependencies")
        require(bool(dependencies), f"worksheet generated leaf {destination}: dependencies must not be empty")
        require(len(dependencies) == len(set(dependencies)), f"worksheet generated leaf {destination}: duplicate dependency")
        for dependency in dependencies:
            dep = expect_nonempty_string(dependency, f"worksheet generated leaf {destination}.dependency")
            require(dep.startswith(dependency_prefixes), f"worksheet generated leaf {destination}: unsupported dependency syntax")
            dependency_type, dependency_target = dep.split(":", 1)
            require(bool(dependency_target), f"worksheet generated leaf {destination}: empty dependency target")
            if dependency_type == "mapping_row":
                require(dependency_target in rows_by_id, f"worksheet generated leaf {destination}: nonexistent mapping-row dependency")
            elif dependency_type == "scaffold":
                require(dependency_target in SCAFFOLD_DEPENDENCIES, f"worksheet generated leaf {destination}: nonexistent scaffold dependency")
            elif dependency_type == "generator":
                require(dependency_target in GENERATOR_IDS, f"worksheet generated leaf {destination}: unknown generator dependency")
            elif dependency_type == "pulse_leaf":
                require(dependency_target != destination, f"worksheet generated leaf {destination}: self dependency is prohibited")
                pulse_leaf_edges.setdefault(destination, []).append(dependency_target)
        transform = expect_nonempty_string(leaf.get("transform"), f"worksheet generated leaf {destination}.transform")
        ownership = leaf.get("ownership")
        require(ownership in {"candidate_owned", "open_mapping_decision"}, f"worksheet generated leaf {destination}: invalid ownership")
        provenance = leaf.get("provenance")
        allowed_provenance = {"vate-derived", "non-vate-scaffolding"}
        if not completed and ownership == "open_mapping_decision":
            allowed_provenance.add("open_mapping_decision")
        require(provenance in allowed_provenance, f"worksheet generated leaf {destination}: invalid provenance")
        if provenance == "open_mapping_decision":
            require(
                not completed and ownership == "open_mapping_decision" and "open_mapping_decision" in transform,
                f"worksheet generated leaf {destination}: provenance sentinel is template-only",
            )
        if completed:
            require(ownership == "candidate_owned", f"completed worksheet generated leaf {destination}: ownership must be candidate_owned")
        inventory_destinations.append(destination)
        inventory_by_destination[destination] = leaf
    require(
        tuple(inventory_destinations) == PULSE_PRIMITIVE_LEAF_PATHS,
        "worksheet generated inventory must exactly match the frozen sorted 142-leaf Pulse input contract",
    )
    require(sha256_value(inventory_destinations) == PULSE_LEAF_PATH_DIGEST, "worksheet generated leaf-path digest mismatch")

    for destination, dependency_targets in pulse_leaf_edges.items():
        for dependency_target in dependency_targets:
            require(
                dependency_target in inventory_by_destination,
                f"worksheet generated leaf {destination}: nonexistent pulse-leaf dependency",
            )
        leaf = inventory_by_destination[destination]
        if (
            leaf.get("source_document") == "pulse_case"
            and len(dependency_targets) == 1
            and "copy" in str(leaf.get("transform", "")).lower()
        ):
            dependency_leaf = inventory_by_destination[dependency_targets[0]]
            require(
                leaf.get("provenance") == dependency_leaf.get("provenance"),
                f"worksheet generated leaf {destination}: exact-copy provenance must propagate from its source leaf",
            )

    visit_state: dict[str, int] = {}

    def visit_pulse_leaf(destination: str) -> None:
        state = visit_state.get(destination, 0)
        require(state != 1, f"worksheet generated inventory: pulse-leaf dependency cycle at {destination}")
        if state == 2:
            return
        visit_state[destination] = 1
        for dependency_target in pulse_leaf_edges.get(destination, []):
            visit_pulse_leaf(dependency_target)
        visit_state[destination] = 2

    for destination in inventory_destinations:
        visit_pulse_leaf(destination)

    requirements = expect_array(at(worksheet, "completion_requirements"), "worksheet completion requirements")
    require(len(requirements) >= 7, "worksheet completion requirements are incomplete")
    normalized_requirements = " ".join(str(item) for item in requirements).lower()
    required_requirement_phrases = [
        "142 primitive pulse input leaves",
        "source_document",
        "vate /expected pointers",
        "unchanged pulse fixture",
        "raw json",
        "pulse reject/non-attenuate",
        "explicit mismatch",
    ]
    if not completed:
        required_requirement_phrases.append("every open_mapping_decision")
    for phrase in required_requirement_phrases:
        require(phrase in normalized_requirements, f"worksheet completion requirements lost boundary: {phrase}")


def expected_comparison_artifact_ref(selected_case: dict[str, Any]) -> dict[str, Any]:
    inputs = expect_array(selected_case.get("inputs"), "selected case inputs")
    receipts = [
        item
        for item in inputs
        if isinstance(item, dict) and item.get("artifact_key") == "admission_receipt"
    ]
    require(len(receipts) == 1, "selected case must contain one comparison-only admission receipt")
    receipt = receipts[0]
    return {
        "admission_receipt": {
            "uri": receipt["path"],
            "media_type": "application/json",
            "digest": {"alg": "sha-256", "value": receipt["raw_sha256"]},
        }
    }


def validate_comparison_artifact_ref(value: Any, selected_case: dict[str, Any], label: str) -> None:
    artifacts = expect_object(value, label)
    require(artifacts == expected_comparison_artifact_ref(selected_case), f"{label}: comparison-only receipt reference mismatch")


def validate_result_template(
    result: dict[str, Any],
    selected_by_id: dict[str, dict[str, Any]],
) -> None:
    require_exact_keys(
        result,
        {
            "version",
            "profile",
            "generated_at",
            "artifact_mode",
            "implementation",
            "corpus",
            "results",
            "external_run",
            "limitations",
        },
        "result template",
    )
    require(at(result, "version") == "vate-sut-results-2026-07", "result template version mismatch")
    require(at(result, "profile") == PROFILE, "result template profile mismatch")
    require(at(result, "artifact_mode") == "corpus-fixture-validation", "result template artifact mode mismatch")
    implementation = expect_object(at(result, "implementation"), "result template implementation")
    require_exact_keys(
        implementation,
        {"name", "type", "version", "language", "source", "commit", "environment", "upstream_verifier"},
        "result template implementation",
    )
    require(at(result, "implementation", "source") == "https://example.invalid/replace-with-candidate-controlled-mapping-repository", "result template mapping source sentinel mismatch")
    require(at(result, "implementation", "commit") == "replace-with-candidate-owned-mapping-commit", "result template mapping commit sentinel mismatch")
    implementation_environment = expect_nonempty_string(at(result, "implementation", "environment"), "result template implementation environment")
    require(PULSE_COMMIT in implementation_environment and "candidate-owned" in implementation_environment, "result template implementation environment lost verifier/mapping boundary")
    upstream = expect_object(at(result, "implementation", "upstream_verifier"), "result template upstream_verifier")
    require_exact_keys(upstream, {"source", "commit", "entry_point"}, "result template upstream_verifier")
    require(at(result, "implementation", "upstream_verifier", "commit") == PULSE_COMMIT, "result template Pulse pin mismatch")
    require(at(result, "implementation", "upstream_verifier", "entry_point") == "src/verifier.ts#verifyConformanceCase", "result template Pulse entry point mismatch")
    corpus = expect_object(at(result, "corpus"), "result template corpus")
    require_exact_keys(corpus, {"profile", "digest"}, "result template corpus")
    require_exact_keys(expect_object(corpus.get("digest"), "result template corpus.digest"), {"alg", "value"}, "result template corpus.digest")
    require(at(result, "corpus", "digest") == {"alg": "sha-256", "value": CORPUS_DIGEST}, "result template corpus digest mismatch")
    results = expect_array(at(result, "results"), "result template results")
    require(len(results) == 3, "result template must contain exactly three sentinels")
    for index, raw_entry in enumerate(results):
        entry = expect_object(raw_entry, f"result template results[{index}]")
        require_exact_keys(
            entry,
            {"case_id", "status", "outcome", "should_execute", "reason_codes", "artifacts", "limitations"},
            f"result template results[{index}]",
        )
        require(entry.get("case_id") == SELECTED_CASE_IDS[index], f"result template case order/identity mismatch at index {index}")
        require(entry.get("status") == "skipped", f"result template {SELECTED_CASE_IDS[index]} must remain skipped")
        require(entry.get("outcome") == "unmapped", f"result template {SELECTED_CASE_IDS[index]} must remain unmapped")
        require(entry.get("should_execute") is False, f"result template {SELECTED_CASE_IDS[index]} execution sentinel changed")
        require(entry.get("reason_codes") == ["PULSE_RESULT_NOT_RECORDED"], f"result template {SELECTED_CASE_IDS[index]} reason sentinel changed")
        validate_comparison_artifact_ref(
            entry.get("artifacts"),
            selected_by_id[SELECTED_CASE_IDS[index]],
            f"result template {SELECTED_CASE_IDS[index]}.artifacts",
        )
        expect_array(entry.get("limitations"), f"result template {SELECTED_CASE_IDS[index]}.limitations")

    external = expect_object(at(result, "external_run"), "result template external_run")
    require_exact_keys(
        external,
        {
            "record_version",
            "status",
            "evidence_class",
            "vate_source_commit",
            "pulse_verifier_commit",
            "source_policy",
            "comparison_contract",
            "attempt",
            "starter_manifest",
            "mapping_source",
            "worksheet",
            "eligible_input_manifest",
            "generated_records",
            "candidate_execution",
            "case_runs",
        },
        "result template external_run",
    )
    require(external.get("record_version") == RUN_RECORD_VERSION, "external run record version mismatch")
    require(external.get("status") == "template", "external run record must remain a template")
    require(external.get("evidence_class") == "unexecuted-template", "external run template evidence class mismatch")
    require(external.get("vate_source_commit") == VATE_COMMIT, "external run VATE pin mismatch")
    require(external.get("pulse_verifier_commit") == PULSE_COMMIT, "external run Pulse pin mismatch")
    source_policy = expect_object(external.get("source_policy"), "external run source_policy")
    require(
        source_policy == EXPECTED_SOURCE_POLICY,
        "external run source-policy boundary mismatch",
    )
    require(external.get("comparison_contract") == EXPECTED_COMPARISON_CONTRACT, "external run comparison contract mismatch")
    attempt = expect_object(external.get("attempt"), "external run attempt")
    require_exact_keys(
        attempt,
        {"stage", "reason_code", "details", "completed_case_ids", "incomplete_case_ids", "evidence"},
        "external run attempt",
    )
    require(
        attempt
        == {
            "stage": None,
            "reason_code": None,
            "details": None,
            "completed_case_ids": [],
            "incomplete_case_ids": list(SELECTED_CASE_IDS),
            "evidence": [],
        },
        "external run template attempt sentinel mismatch",
    )
    starter_ref = expect_object(external.get("starter_manifest"), "external run starter_manifest")
    require_exact_keys(starter_ref, {"path", "raw_sha256"}, "external run starter_manifest")
    require(starter_ref == {"path": None, "raw_sha256": None}, "external run starter manifest reference must remain unset")
    mapping_source = expect_object(external.get("mapping_source"), "external run mapping_source")
    require_exact_keys(
        mapping_source,
        {
            "owner",
            "repository",
            "locator_verification",
            "commit",
            "repository_path",
            "entrypoint",
            "command",
            "bundle_path",
            "raw_sha256",
        },
        "external run mapping_source",
    )
    require(mapping_source.get("owner") == "candidate_owned", "external run mapping source owner mismatch")
    require(
        mapping_source.get("locator_verification") == "local-git-origin-only-no-remote-fetch",
        "external run mapping locator boundary mismatch",
    )
    for field in ("repository", "commit", "repository_path", "entrypoint", "command", "bundle_path", "raw_sha256"):
        require(mapping_source.get(field) is None, f"external run mapping source {field} must remain unset")
    worksheet_ref = expect_object(external.get("worksheet"), "external run worksheet")
    require_exact_keys(worksheet_ref, {"path", "raw_sha256"}, "external run worksheet")
    require(worksheet_ref == {"path": None, "raw_sha256": None}, "external run worksheet reference must remain unset")
    for ref_name in ("eligible_input_manifest", "generated_records"):
        ref = expect_object(external.get(ref_name), f"external run {ref_name}")
        require_exact_keys(ref, {"path", "raw_sha256"}, f"external run {ref_name}")
        require(ref == {"path": None, "raw_sha256": None}, f"external run {ref_name} reference must remain unset")
    candidate_execution = expect_object(external.get("candidate_execution"), "external run candidate_execution")
    require_exact_keys(
        candidate_execution,
        {
            "interface_version",
            "command",
            "runtime",
            "commit_export",
            "map_request",
            "map_output",
            "projection_request",
            "projection_output",
            "sensitivity_contract",
        },
        "external run candidate_execution",
    )
    require(candidate_execution.get("interface_version") == CANDIDATE_INTERFACE_VERSION, "candidate interface version mismatch")
    require(candidate_execution.get("command") is None, "template candidate command must remain unset")
    runtime = expect_object(candidate_execution.get("runtime"), "template candidate runtime")
    require(runtime == CANDIDATE_RUNTIME_TEMPLATE_RECORD, "template candidate runtime must remain unset")
    require(
        candidate_execution.get("commit_export") == CANDIDATE_EXPORT_TEMPLATE_CONTRACT,
        "template candidate commit-export contract mismatch",
    )
    for ref_name in ("map_request", "map_output", "projection_request", "projection_output"):
        ref = expect_object(candidate_execution.get(ref_name), f"template candidate execution {ref_name}")
        require(ref == {"path": None, "raw_sha256": None}, f"template candidate execution {ref_name} must remain unset")
    require(
        candidate_execution.get("sensitivity_contract")
        == {
            "probe_dimensions": ["amount", "merchant", "evaluation_time", "replay_nonce"],
            "randomized_per_validation": True,
            "independent_recomputation": True,
            "tamper_proof_claim": False,
        },
        "template candidate sensitivity contract mismatch",
    )
    case_runs = expect_array(external.get("case_runs"), "external run case_runs")
    require(len(case_runs) == 3, "external run record must contain exactly three case sentinels")
    for index, raw_case_run in enumerate(case_runs):
        case_run = expect_object(raw_case_run, f"external run case_runs[{index}]")
        require_exact_keys(
            case_run,
            {"case_id", "vate_input_closure_sha256", "vate_inputs", "pulse_input", "raw_report", "projection"},
            f"external run case_runs[{index}]",
        )
        case_id = SELECTED_CASE_IDS[index]
        require(case_run.get("case_id") == case_id, f"external run case order/identity mismatch at index {index}")
        require(case_run.get("vate_input_closure_sha256") == EXPECTED_CLOSURE_DIGESTS[case_id], f"external run closure digest mismatch: {case_id}")
        vate_inputs = expect_array(case_run.get("vate_inputs"), f"external run {case_id}.vate_inputs")
        manifest_inputs = expect_array(selected_by_id[case_id]["inputs"], f"manifest inputs for {case_id}")
        require(len(vate_inputs) == 4, f"external run {case_id}: expected four VATE input refs")
        for input_index, (raw_ref, manifest_ref) in enumerate(zip(vate_inputs, manifest_inputs, strict=True)):
            ref = expect_object(raw_ref, f"external run {case_id}.vate_inputs[{input_index}]")
            require_exact_keys(
                ref,
                {"role", "artifact_key", "source_path", "source_raw_sha256", "bundle_path", "bundle_raw_sha256"},
                f"external run {case_id}.vate_inputs[{input_index}]",
            )
            require(ref.get("role") == manifest_ref["role"], f"external run {case_id}: VATE input role mismatch")
            require(ref.get("artifact_key") == manifest_ref["artifact_key"], f"external run {case_id}: VATE artifact key mismatch")
            require(ref.get("source_path") == manifest_ref["path"], f"external run {case_id}: VATE source path mismatch")
            require(ref.get("source_raw_sha256") == manifest_ref["raw_sha256"], f"external run {case_id}: VATE source hash mismatch")
            require(ref.get("bundle_path") is None and ref.get("bundle_raw_sha256") is None, f"external run {case_id}: VATE bundle ref must remain unset")
        pulse_input = expect_object(case_run.get("pulse_input"), f"external run {case_id}.pulse_input")
        require_exact_keys(pulse_input, {"path", "raw_sha256"}, f"external run {case_id}.pulse_input")
        require(pulse_input == {"path": None, "raw_sha256": None}, f"external run {case_id}: Pulse input ref must remain unset")
        raw_report = expect_object(case_run.get("raw_report"), f"external run {case_id}.raw_report")
        require_exact_keys(raw_report, {"path", "raw_sha256", "report_index"}, f"external run {case_id}.raw_report")
        require(raw_report == {"path": None, "raw_sha256": None, "report_index": index}, f"external run {case_id}: raw report ref sentinel mismatch")
        projection = expect_object(case_run.get("projection"), f"external run {case_id}.projection")
        require_exact_keys(
            projection,
            {
                "result_index",
                "source_document",
                "source_json_pointer",
                "observed_relation_to_vate",
                "pulse_outcome_class",
                "projected_vate_outcome",
                "projected_should_execute",
                "projected_reason_codes",
                "projected_checks",
            },
            f"external run {case_id}.projection",
        )
        require(projection.get("result_index") == index, f"external run {case_id}: result index mismatch")
        require(projection.get("source_document") == "raw_pulse_output", f"external run {case_id}: projection must source raw Pulse output")
        require(projection.get("source_json_pointer") == f"/reports/{index}", f"external run {case_id}: projection report pointer mismatch")
        for field in (
            "observed_relation_to_vate",
            "pulse_outcome_class",
            "projected_vate_outcome",
            "projected_should_execute",
            "projected_reason_codes",
            "projected_checks",
        ):
            require(projection.get(field) is None, f"external run {case_id}.projection.{field} must remain unset")
    limitations = " ".join(str(item) for item in expect_array(at(result, "limitations"), "result template limitations")).lower()
    for phrase in ("unexecuted template", "candidate owns", "must remain a mismatch", "not organic adoption", "issue #18", "security review"):
        require(phrase in limitations, f"result template limitation lost boundary: {phrase}")


def expected_pulse_case_id(case_id: str) -> str:
    require(case_id in SELECTED_CASE_IDS, "unknown selected VATE case")
    return f"vate-pulse-{CANDIDATE_WORK_ITEM_IDS[SELECTED_CASE_IDS.index(case_id)]}"


def validate_completed_pulse_input(value: Any, case_id: str, label: str) -> dict[str, Any]:
    pulse_input = expect_object(value, label)
    leaves = tuple(sorted(primitive_leaf_paths(pulse_input)))
    require(leaves == PULSE_PRIMITIVE_LEAF_PATHS, f"{label}: primitive leaf set must exactly match the frozen 142-leaf contract")
    require(sha256_value(list(leaves)) == PULSE_LEAF_PATH_DIGEST, f"{label}: primitive leaf-path digest mismatch")
    containers = tuple(sorted(container_paths(pulse_input)))
    require(containers == PULSE_CONTAINER_PATHS, f"{label}: container set must exactly match the frozen 42-container contract")
    require(sha256_value(list(containers)) == PULSE_CONTAINER_PATH_DIGEST, f"{label}: container-path digest mismatch")
    require(pulse_input.get("id") == expected_pulse_case_id(case_id), f"{label}: opaque Pulse work-item ID binding mismatch")
    require(pulse_input.get("caseVersion") == "ap2-x402-conformance/0.3", f"{label}: Pulse caseVersion mismatch")
    require(
        pulse_input.get("sourcePins")
        == {
            "ap2Commit": "e1ea56db72a6385bce3e5c1112b3a56ce60acb43",
            "x402Commit": "17d319fab5c17a6b4873eb41197894db924f59ed",
            "x402PackageVersion": "2.23.0",
        },
        f"{label}: Pulse sourcePins mismatch",
    )
    expected = expect_object(pulse_input.get("expected"), f"{label}.expected")
    require_exact_keys(expected, {"consistent", "failureCodes"}, f"{label}.expected")
    require(expected == {"consistent": True, "failureCodes": []}, f"{label}: expected must remain the neutral schema-only envelope")
    require(
        pulse_input.get("ap2", {}).get("closedMandate", {}).get("payment_instrument", {}).get("x402", {}).get("nonceBinding")
        == "base64url-decode-ap2-mandate-reference",
        f"{label}: x402 nonce binding mismatch",
    )
    require(
        pulse_input.get("x402", {}).get("payload", {}).get("x402Version") == 2,
        f"{label}: x402 payload version mismatch",
    )
    scan_json_for_credentials(pulse_input, label)
    return pulse_input


def validate_raw_pulse_report(value: Any, expected_case_id: str, label: str) -> dict[str, Any]:
    report = expect_object(value, label)
    require_exact_keys(report, {"caseId", "consistent", "computed", "failures"}, label)
    require(report.get("caseId") == expected_case_id, f"{label}: report caseId binding mismatch")
    require(isinstance(report.get("consistent"), bool), f"{label}.consistent: expected boolean")
    computed = expect_object(report.get("computed"), f"{label}.computed")
    allowed_computed = {
        "closedMandateClaimsHash",
        "openMandateClaimsHash",
        "closedMandateReference",
        "inputHash",
        "expectedNonce",
        "recoveredSigner",
    }
    required_computed = {
        "closedMandateClaimsHash",
        "openMandateClaimsHash",
        "closedMandateReference",
        "inputHash",
        "expectedNonce",
    }
    require(required_computed.issubset(computed), f"{label}.computed: missing required frozen-verifier field")
    require(set(computed).issubset(allowed_computed), f"{label}.computed: unknown field")
    for key, item in computed.items():
        expect_nonempty_string(item, f"{label}.computed.{key}")
    failures = expect_array(report.get("failures"), f"{label}.failures")
    failure_identities: set[tuple[Any, ...]] = set()
    for index, raw_failure in enumerate(failures):
        failure = expect_object(raw_failure, f"{label}.failures[{index}]")
        required = {"code", "path", "message"}
        allowed = required | {"expected", "actual"}
        require(required.issubset(failure), f"{label}.failures[{index}]: missing required field")
        require(set(failure).issubset(allowed), f"{label}.failures[{index}]: unknown field")
        code = expect_nonempty_string(failure.get("code"), f"{label}.failures[{index}].code")
        require(code in PULSE_FAILURE_CODES, f"{label}.failures[{index}]: unknown Pulse failure code")
        expect_nonempty_string(failure.get("path"), f"{label}.failures[{index}].path")
        expect_nonempty_string(failure.get("message"), f"{label}.failures[{index}].message")
        for optional in ("expected", "actual"):
            if optional in failure:
                require(
                    failure[optional] is None or isinstance(failure[optional], (str, int, float, bool)),
                    f"{label}.failures[{index}].{optional}: expected JSON primitive",
                )
        identity = tuple((key, canonical_json_bytes(failure[key])) for key in sorted(failure))
        require(identity not in failure_identities, f"{label}.failures[{index}]: duplicate failure")
        failure_identities.add(identity)
    require(bool(failures) is not report["consistent"], f"{label}: consistent must be true exactly when failures is empty")
    return report


def validate_raw_pulse_output(
    value: Any,
    pulse_inputs: list[tuple[str, str, str]],
    label: str,
) -> list[dict[str, Any]]:
    raw_output = expect_object(value, label)
    require_exact_keys(
        raw_output,
        {"recordVersion", "pulseVerifierCommit", "runtime", "execution", "inputs", "reports"},
        label,
    )
    require(raw_output.get("recordVersion") == RAW_OUTPUT_VERSION, f"{label}: raw recordVersion mismatch")
    require(raw_output.get("pulseVerifierCommit") == PULSE_COMMIT, f"{label}: raw Pulse verifier pin mismatch")
    runtime = expect_object(raw_output.get("runtime"), f"{label}.runtime")
    require_exact_keys(runtime, {"nodeVersion", "npmVersion", "pulsePackageVersion"}, f"{label}.runtime")
    require(NODE_VERSION_RE.fullmatch(str(runtime.get("nodeVersion", ""))) is not None, f"{label}: invalid Node.js version")
    require(NPM_VERSION_RE.fullmatch(str(runtime.get("npmVersion", ""))) is not None, f"{label}: invalid npm version")
    require(runtime.get("pulsePackageVersion") == "0.0.0", f"{label}: frozen Pulse package version mismatch")
    execution = expect_object(raw_output.get("execution"), f"{label}.execution")
    require_exact_keys(
        execution,
        {"workingDirectory", "entryPoint", "driverSha256", "command"},
        f"{label}.execution",
    )
    require(execution.get("workingDirectory") == "$PULSE_REPO", f"{label}: replay working-directory contract mismatch")
    require(execution.get("entryPoint") == "src/verifier.ts#verifyConformanceCase", f"{label}: replay entry point mismatch")
    require(execution.get("driverSha256") == PULSE_REPLAY_SCRIPT_SHA256, f"{label}: replay driver hash mismatch")
    expected_command = [
        "node",
        "--import",
        "tsx",
        "--input-type=module",
        "--eval",
        PULSE_REPLAY_SCRIPT,
        "--",
        *[f"$RUN_DIR/{path}" for _, path, _ in pulse_inputs],
    ]
    require(execution.get("command") == expected_command, f"{label}: exact replay command mismatch")
    inputs = expect_array(raw_output.get("inputs"), f"{label}.inputs")
    reports = expect_array(raw_output.get("reports"), f"{label}.reports")
    require(
        len(inputs) == len(pulse_inputs) and len(reports) == len(pulse_inputs) and 1 <= len(pulse_inputs) <= 3,
        f"{label}: input/report cardinality must equal the recorded completed-case set",
    )
    validated_reports: list[dict[str, Any]] = []
    for index, ((case_id, input_path, input_hash), raw_input_record, raw_report) in enumerate(
        zip(pulse_inputs, inputs, reports, strict=True)
    ):
        input_record = expect_object(raw_input_record, f"{label}.inputs[{index}]")
        require_exact_keys(
            input_record,
            {"vateCaseId", "pulseCaseId", "path", "rawSha256Before", "rawSha256After"},
            f"{label}.inputs[{index}]",
        )
        require(input_record.get("vateCaseId") == case_id, f"{label}.inputs[{index}]: VATE case binding mismatch")
        expected_pulse_id = expected_pulse_case_id(case_id)
        require(input_record.get("pulseCaseId") == expected_pulse_id, f"{label}.inputs[{index}]: Pulse case binding mismatch")
        require(validate_safe_repo_path(input_record.get("path"), f"{label}.inputs[{index}].path") == input_path, f"{label}.inputs[{index}]: Pulse input path mismatch")
        before = validate_sha256(input_record.get("rawSha256Before"), f"{label}.inputs[{index}].rawSha256Before")
        after = validate_sha256(input_record.get("rawSha256After"), f"{label}.inputs[{index}].rawSha256After")
        require(before == input_hash and after == input_hash, f"{label}.inputs[{index}]: input changed before/after verifier invocation")
        validated_reports.append(validate_raw_pulse_report(raw_report, expected_pulse_id, f"{label}.reports[{index}]"))
    scan_json_for_credentials(raw_output, label)
    return validated_reports


def corpus_case_ids(source: SourceSnapshot) -> tuple[str, ...]:
    cases = expect_array(source.corpus.get("cases"), "fixed corpus cases")
    return tuple(expect_nonempty_string(case.get("case_id"), "fixed corpus case ID") for case in cases)


def out_of_scope_case_ids(source: SourceSnapshot) -> tuple[str, ...]:
    return tuple(case_id for case_id in corpus_case_ids(source) if case_id not in SELECTED_CASE_IDS)


def validate_out_of_scope_result_entry(value: Any, case_id: str, label: str) -> None:
    entry = expect_object(value, label)
    require_exact_keys(
        entry,
        {"case_id", "status", "outcome", "should_execute", "reason_codes", "limitations"},
        label,
    )
    require(
        entry
        == {
            "case_id": case_id,
            "status": "skipped",
            "outcome": "out-of-scope",
            "should_execute": False,
            "reason_codes": ["OUT_OF_SCOPE"],
            "limitations": ["Outside the bounded three-case Pulse attempt; no SUT outcome is claimed."],
        },
        f"{label}: out-of-scope placeholder contract mismatch",
    )


def validate_completed_result_entry(
    value: Any,
    case_id: str,
    selected_case: dict[str, Any],
    label: str,
) -> dict[str, Any]:
    entry = expect_object(value, label)
    require_exact_keys(
        entry,
        {"case_id", "status", "outcome", "should_execute", "reason_codes", "checks", "artifacts", "limitations"},
        label,
    )
    require(entry.get("case_id") == case_id, f"{label}: case ID mismatch")
    require(entry.get("status") == "completed", f"{label}: status must be completed")
    expect_nonempty_string(entry.get("outcome"), f"{label}.outcome")
    require(isinstance(entry.get("should_execute"), bool), f"{label}.should_execute: expected boolean")
    reasons = expect_array(entry.get("reason_codes"), f"{label}.reason_codes")
    for index, reason in enumerate(reasons):
        expect_nonempty_string(reason, f"{label}.reason_codes[{index}]")
    checks = expect_array(entry.get("checks"), f"{label}.checks")
    check_names: set[str] = set()
    for index, raw_check in enumerate(checks):
        check = expect_object(raw_check, f"{label}.checks[{index}]")
        require_exact_keys(check, {"name", "pass", "details"}, f"{label}.checks[{index}]")
        name = expect_nonempty_string(check.get("name"), f"{label}.checks[{index}].name")
        require(name not in check_names, f"{label}.checks[{index}]: duplicate check name")
        check_names.add(name)
        require(isinstance(check.get("pass"), bool), f"{label}.checks[{index}].pass: expected boolean")
        expect_nonempty_string(check.get("details"), f"{label}.checks[{index}].details")
    limitations = expect_array(entry.get("limitations"), f"{label}.limitations")
    for index, limitation in enumerate(limitations):
        expect_nonempty_string(limitation, f"{label}.limitations[{index}]")
    validate_comparison_artifact_ref(entry.get("artifacts"), selected_case, f"{label}.artifacts")
    require_no_completion_sentinel(entry, label)
    return entry


def validate_rfc3339_timestamp(value: Any, label: str) -> str:
    timestamp = expect_nonempty_string(value, label)
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CheckFailure(f"{label}: invalid RFC 3339 timestamp") from exc
    require(parsed.tzinfo is not None, f"{label}: timezone is required")
    return timestamp


def validate_eligible_input_manifest(
    value: Any,
    bundle_root: Path,
    selected_by_id: dict[str, dict[str, Any]],
    source: SourceSnapshot,
    expected_case_ids: tuple[str, ...],
    label: str,
) -> dict[str, dict[str, tuple[str, str]]]:
    manifest = expect_object(value, label)
    require_exact_keys(
        manifest,
        {"recordVersion", "vateSourceCommit", "corpusDigest", "excludedSourceClasses", "cases"},
        label,
    )
    require(manifest.get("recordVersion") == ELIGIBLE_INPUT_VERSION, f"{label}: record version mismatch")
    require(manifest.get("vateSourceCommit") == VATE_COMMIT, f"{label}: VATE source pin mismatch")
    require(manifest.get("corpusDigest") == CORPUS_DIGEST, f"{label}: corpus digest mismatch")
    require(
        manifest.get("excludedSourceClasses")
        == ["vate-case-expected", "vate-admission-receipt", "vate-post-execution-receipt"],
        f"{label}: expected/receipt exclusion contract mismatch",
    )
    cases = expect_array(manifest.get("cases"), f"{label}.cases")
    require(len(cases) == len(expected_case_ids), f"{label}: case cardinality mismatch")
    validated: dict[str, dict[str, tuple[str, str]]] = {}
    seen_bundle_paths: set[str] = set()
    for index, (raw_case, expected_case_id) in enumerate(zip(cases, expected_case_ids, strict=True)):
        case = expect_object(raw_case, f"{label}.cases[{index}]")
        require_exact_keys(case, {"caseId", "inputs"}, f"{label}.cases[{index}]")
        require(case.get("caseId") == expected_case_id, f"{label}: case identity/order mismatch")
        selected_inputs = {
            item["artifact_key"]: item
            for item in expect_array(selected_by_id[expected_case_id]["inputs"], f"selected inputs {expected_case_id}")
        }
        inputs = expect_array(case.get("inputs"), f"{label}.{expected_case_id}.inputs")
        require(len(inputs) == 2, f"{label}.{expected_case_id}: exactly two mapper-eligible inputs are required")
        case_validated: dict[str, tuple[str, str]] = {}
        for input_index, (raw_input, artifact_key) in enumerate(
            zip(inputs, ("admission_request", "ap2_mandate"), strict=True)
        ):
            entry = expect_object(raw_input, f"{label}.{expected_case_id}.inputs[{input_index}]")
            require_exact_keys(
                entry,
                {"artifactKey", "sourcePath", "sourceRawSha256", "bundlePath", "bundleRawSha256"},
                f"{label}.{expected_case_id}.inputs[{input_index}]",
            )
            require(entry.get("artifactKey") == artifact_key, f"{label}.{expected_case_id}: eligible artifact order mismatch")
            fixed = selected_inputs[artifact_key]
            require(entry.get("sourcePath") == fixed["path"], f"{label}.{expected_case_id}: source path mismatch")
            require(entry.get("sourceRawSha256") == fixed["raw_sha256"], f"{label}.{expected_case_id}: source hash mismatch")
            local_path, local_raw, local_hash = validate_bundle_ref(
                bundle_root,
                {"path": entry.get("bundlePath"), "raw_sha256": entry.get("bundleRawSha256")},
                f"{label}.{expected_case_id}.{artifact_key}",
                expected_digest=fixed["raw_sha256"],
            )
            require(local_path not in seen_bundle_paths, f"{label}: duplicate mapper-input bundle path")
            seen_bundle_paths.add(local_path)
            require(local_raw == source.blobs[fixed["path"]], f"{label}.{expected_case_id}: mapper input differs from fixed Git bytes")
            parse_strict_json(local_raw, f"bundle:{local_path}")
            case_validated[artifact_key] = (local_path, local_hash)
        validated[expected_case_id] = case_validated
    scan_json_for_credentials(manifest, label)
    return validated


def validate_generated_records(
    value: Any,
    bundle_root: Path,
    completed_worksheet: dict[str, Any],
    pulse_inputs: dict[str, tuple[str, str, dict[str, Any]]],
    expected_case_ids: tuple[str, ...],
    label: str,
    *,
    worksheet_raw_sha256: str,
    candidate_map_output: tuple[str, str],
) -> None:
    record = expect_object(value, label)
    require_exact_keys(
        record,
        {
            "recordVersion",
            "machineCoverageScope",
            "privateMaterialRecorded",
            "worksheetRawSha256",
            "candidateMapOutputPath",
            "candidateMapOutputRawSha256",
            "cases",
        },
        label,
    )
    require(record.get("recordVersion") == GENERATED_RECORD_VERSION, f"{label}: record version mismatch")
    require(record.get("machineCoverageScope") == MACHINE_COVERAGE_SCOPE, f"{label}: machine coverage scope mismatch")
    require(record.get("privateMaterialRecorded") is False, f"{label}: private material must not be recorded")
    require(record.get("worksheetRawSha256") == worksheet_raw_sha256, f"{label}: worksheet hash-chain binding mismatch")
    require(record.get("candidateMapOutputPath") == candidate_map_output[0], f"{label}: candidate map-output path binding mismatch")
    require(record.get("candidateMapOutputRawSha256") == candidate_map_output[1], f"{label}: candidate map-output hash binding mismatch")
    inventory = expect_array(completed_worksheet.get("generated_field_inventory"), "completed worksheet generated inventory")
    cases = expect_array(record.get("cases"), f"{label}.cases")
    require(len(cases) == len(expected_case_ids), f"{label}: case cardinality mismatch")
    for case_index, (raw_case, case_id) in enumerate(zip(cases, expected_case_ids, strict=True)):
        case = expect_object(raw_case, f"{label}.cases[{case_index}]")
        require_exact_keys(
            case,
            {"caseId", "pulseInputPath", "pulseInputRawSha256", "leaves", "generatorRecords"},
            f"{label}.cases[{case_index}]",
        )
        require(case.get("caseId") == case_id, f"{label}: case identity/order mismatch")
        pulse_path, pulse_hash, pulse_value = pulse_inputs[case_id]
        require(case.get("pulseInputPath") == pulse_path, f"{label}.{case_id}: Pulse input path mismatch")
        require(case.get("pulseInputRawSha256") == pulse_hash, f"{label}.{case_id}: Pulse input hash mismatch")
        leaves = expect_array(case.get("leaves"), f"{label}.{case_id}.leaves")
        require(len(leaves) == 142, f"{label}.{case_id}: exact 142-leaf record required")
        expected_generator_destinations: dict[str, list[str]] = {generator: [] for generator in sorted(GENERATOR_IDS)}
        for leaf_index, (raw_leaf, worksheet_leaf) in enumerate(zip(leaves, inventory, strict=True)):
            leaf = expect_object(raw_leaf, f"{label}.{case_id}.leaves[{leaf_index}]")
            require_exact_keys(
                leaf,
                {
                    "pulseDestination",
                    "valueSha256",
                    "sourceDocument",
                    "sourceJsonPointer",
                    "dependencies",
                    "provenance",
                    "ownership",
                },
                f"{label}.{case_id}.leaves[{leaf_index}]",
            )
            destination = worksheet_leaf["pulse_destination"]
            require(leaf.get("pulseDestination") == destination, f"{label}.{case_id}: generated leaf order/destination mismatch")
            actual_value = json_pointer_value(pulse_value, destination, f"{label}.{case_id}.pulse_input")
            require(leaf.get("valueSha256") == sha256_value(actual_value), f"{label}.{case_id}: generated leaf value hash mismatch")
            require(leaf.get("sourceDocument") == worksheet_leaf["source_document"], f"{label}.{case_id}: source document mismatch")
            require(leaf.get("sourceJsonPointer") == worksheet_leaf["source_json_pointer"], f"{label}.{case_id}: source pointer mismatch")
            require(leaf.get("dependencies") == worksheet_leaf["dependencies"], f"{label}.{case_id}: dependency record mismatch")
            require(leaf.get("provenance") == worksheet_leaf["provenance"], f"{label}.{case_id}: provenance record mismatch")
            require(leaf.get("ownership") == "candidate_owned", f"{label}.{case_id}: generated leaf ownership mismatch")
            for dependency in worksheet_leaf["dependencies"]:
                if dependency.startswith("generator:"):
                    expected_generator_destinations[dependency.split(":", 1)[1]].append(destination)
        generator_records = expect_array(case.get("generatorRecords"), f"{label}.{case_id}.generatorRecords")
        require(len(generator_records) == len(GENERATOR_IDS), f"{label}.{case_id}: generator record closure mismatch")
        for generator_index, (raw_generator, generator_id) in enumerate(
            zip(generator_records, sorted(GENERATOR_IDS), strict=True)
        ):
            generator = expect_object(raw_generator, f"{label}.{case_id}.generatorRecords[{generator_index}]")
            require_exact_keys(
                generator,
                {"recordId", "kind", "pulseDestinations", "valueDigests", "publicMaterialOnly"},
                f"{label}.{case_id}.generatorRecords[{generator_index}]",
            )
            require(generator.get("recordId") == f"generator:{generator_id}", f"{label}.{case_id}: generator record ID mismatch")
            require(generator.get("kind") == generator_id, f"{label}.{case_id}: generator kind mismatch")
            destinations = expected_generator_destinations[generator_id]
            require(generator.get("pulseDestinations") == destinations, f"{label}.{case_id}: generator destination closure mismatch")
            expected_value_digests = [
                {
                    "pulseDestination": destination,
                    "valueSha256": sha256_value(
                        json_pointer_value(pulse_value, destination, f"{label}.{case_id}.pulse_input")
                    ),
                }
                for destination in destinations
            ]
            require(generator.get("valueDigests") == expected_value_digests, f"{label}.{case_id}: generator value digest mismatch")
            require(generator.get("publicMaterialOnly") is True, f"{label}.{case_id}: generator record must be public-only")
    scan_json_for_credentials(record, label)


def parse_exact_utc_epoch(value: Any, label: str) -> int:
    timestamp = expect_nonempty_string(value, label)
    require(
        re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", timestamp) is not None,
        f"{label}: exact whole-second UTC timestamp required",
    )
    try:
        parsed = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise CheckFailure(f"{label}: invalid UTC timestamp") from exc
    return int(parsed.timestamp())


def format_exact_utc(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_usd_decimal(value: Any, label: str) -> Decimal:
    text = expect_nonempty_string(value, label)
    require(re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]{1,2})?", text) is not None, f"{label}: exact nonnegative USD decimal required")
    try:
        amount = Decimal(text)
    except InvalidOperation as exc:
        raise CheckFailure(f"{label}: invalid USD decimal") from exc
    require(amount.is_finite() and amount >= 0, f"{label}: invalid USD decimal")
    return amount


def exact_integral_decimal(value: Decimal, label: str) -> int:
    require(value.is_finite() and value >= 0 and value == value.to_integral_value(), f"{label}: conversion is not an exact nonnegative integer")
    integer = int(value)
    require(integer < 2**256, f"{label}: uint256 overflow")
    return integer


def eligible_documents(
    bundle_root: Path,
    eligible_inputs: dict[str, dict[str, tuple[str, str]]],
    case_ids: tuple[str, ...],
    label: str,
) -> dict[str, tuple[dict[str, Any], dict[str, Any]]]:
    documents: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    for case_id in case_ids:
        admission_path = eligible_inputs[case_id]["admission_request"][0]
        mandate_path = eligible_inputs[case_id]["ap2_mandate"][0]
        admission = expect_object(
            parse_strict_json(read_bundle_file(bundle_root, admission_path, f"{label} admission request")[1], f"{label}:{admission_path}"),
            f"{label} admission request",
        )
        mandate = expect_object(
            parse_strict_json(read_bundle_file(bundle_root, mandate_path, f"{label} AP2 mandate")[1], f"{label}:{mandate_path}"),
            f"{label} AP2 mandate",
        )
        documents[case_id] = (admission, mandate)
    return documents


def candidate_map_request_value(
    documents: dict[str, tuple[dict[str, Any], dict[str, Any]]],
    case_ids: tuple[str, ...],
) -> dict[str, Any]:
    return {
        "interfaceVersion": CANDIDATE_INTERFACE_VERSION,
        "operation": "map",
        "items": [
            {
                "workItemId": CANDIDATE_WORK_ITEM_IDS[SELECTED_CASE_IDS.index(case_id)],
                "eligibleInput": {
                    "admissionRequest": copy.deepcopy(documents[case_id][0]),
                    "ap2Mandate": copy.deepcopy(documents[case_id][1]),
                },
            }
            for case_id in case_ids
        ],
    }


def candidate_projection_request_value(
    documents: dict[str, tuple[dict[str, Any], dict[str, Any]]],
    case_ids: tuple[str, ...],
    reports: list[dict[str, Any]],
) -> dict[str, Any]:
    require(len(reports) == len(case_ids), "candidate projection request report cardinality mismatch")
    return {
        "interfaceVersion": CANDIDATE_INTERFACE_VERSION,
        "operation": "project",
        "items": [
            {
                "workItemId": CANDIDATE_WORK_ITEM_IDS[SELECTED_CASE_IDS.index(case_id)],
                "eligibleInput": {
                    "admissionRequest": copy.deepcopy(documents[case_id][0]),
                    "ap2Mandate": copy.deepcopy(documents[case_id][1]),
                },
                "rawPulseReport": copy.deepcopy(report),
            }
            for case_id, report in zip(case_ids, reports, strict=True)
        ],
    }


def validate_candidate_map_output(
    raw: bytes,
    case_ids: tuple[str, ...],
    label: str,
) -> tuple[list[str], list[dict[str, Any]]]:
    output = expect_object(parse_strict_json(raw, label), label)
    require_exact_keys(output, {"interfaceVersion", "operation", "items"}, label)
    require(output.get("interfaceVersion") == CANDIDATE_INTERFACE_VERSION, f"{label}: interface version mismatch")
    require(output.get("operation") == "map", f"{label}: operation mismatch")
    items = expect_array(output.get("items"), f"{label}.items")
    require(len(items) == len(case_ids), f"{label}: item cardinality mismatch")
    pulse_raw_values: list[str] = []
    pulse_values: list[dict[str, Any]] = []
    for index, (raw_item, case_id) in enumerate(zip(items, case_ids, strict=True)):
        item = expect_object(raw_item, f"{label}.items[{index}]")
        require_exact_keys(item, {"workItemId", "pulseInputRaw"}, f"{label}.items[{index}]")
        expected_work_item = CANDIDATE_WORK_ITEM_IDS[SELECTED_CASE_IDS.index(case_id)]
        require(item.get("workItemId") == expected_work_item, f"{label}: opaque work-item binding mismatch")
        pulse_raw_text = expect_nonempty_string(item.get("pulseInputRaw"), f"{label}.items[{index}].pulseInputRaw")
        pulse_raw = pulse_raw_text.encode("utf-8")
        pulse_value = expect_object(parse_strict_json(pulse_raw, f"{label}.items[{index}].pulseInputRaw"), f"{label}.items[{index}].pulseInputRaw")
        validate_completed_pulse_input(pulse_value, case_id, f"{label}.items[{index}].pulseInputRaw")
        pulse_raw_values.append(pulse_raw_text)
        pulse_values.append(pulse_value)
    return pulse_raw_values, pulse_values


def classify_eligible_source(admission: dict[str, Any], mandate: dict[str, Any], label: str) -> str:
    request_amount = parse_usd_decimal(json_pointer_value(admission, "/constraints/max_amount/value", label), f"{label} request amount")
    limit_amount = parse_usd_decimal(json_pointer_value(mandate, "/constraints/max_amount/value", label), f"{label} mandate limit")
    evaluation_epoch = parse_exact_utc_epoch(json_pointer_value(admission, "/issued_at", label), f"{label} evaluation time")
    mandate_end = parse_exact_utc_epoch(json_pointer_value(mandate, "/constraints/execution_window/not_after", label), f"{label} mandate window end")
    overrun = request_amount > limit_amount
    stale = evaluation_epoch > mandate_end
    require(not (overrun and stale), f"{label}: combined overrun/stale source is outside this bounded contract")
    return "overrun" if overrun else "stale" if stale else "allow"


def independent_mapping_expectations(
    admission: dict[str, Any],
    mandate: dict[str, Any],
    worksheet: dict[str, Any],
    label: str,
) -> tuple[dict[str, Any], str]:
    request_currency = json_pointer_value(admission, "/constraints/max_amount/currency", label)
    mandate_currency = json_pointer_value(mandate, "/constraints/max_amount/currency", label)
    require(request_currency == "USD" and mandate_currency == "USD", f"{label}: only exact USD sources are supported")
    request_amount = parse_usd_decimal(json_pointer_value(admission, "/constraints/max_amount/value", label), f"{label} request amount")
    limit_amount = parse_usd_decimal(json_pointer_value(mandate, "/constraints/max_amount/value", label), f"{label} mandate limit")
    permitted_amount = min(request_amount, limit_amount)
    request_minor = exact_integral_decimal(request_amount * 100, f"{label} request minor amount")
    limit_minor = exact_integral_decimal(limit_amount * 100, f"{label} mandate minor amount")
    permitted_minor = exact_integral_decimal(permitted_amount * 100, f"{label} permitted minor amount")

    asset_profile = expect_object(at(worksheet, "scaffolding_inputs", "asset_profile"), f"{label} asset profile")
    decimals = asset_profile.get("decimals")
    require(isinstance(decimals, int) and not isinstance(decimals, bool) and 0 <= decimals <= 36, f"{label}: invalid asset decimals")
    conversion = expect_object(asset_profile.get("usd_to_asset_conversion"), f"{label} atomic conversion")
    units_text = expect_nonempty_string(conversion.get("asset_units_per_usd"), f"{label} asset units per USD")
    require(DECIMAL_RULE_RE.fullmatch(units_text) is not None, f"{label}: invalid asset units per USD")
    units_per_usd = Decimal(units_text)
    require(units_per_usd > 0, f"{label}: asset units per USD must be positive")
    scale = Decimal(10) ** decimals
    requested_atomic = exact_integral_decimal(request_amount * units_per_usd * scale, f"{label} requested atomic amount")
    permitted_atomic = exact_integral_decimal(permitted_amount * units_per_usd * scale, f"{label} permitted atomic amount")

    merchant = expect_nonempty_string(json_pointer_value(mandate, "/merchant", label), f"{label} merchant")
    require(re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", merchant) is not None, f"{label}: invalid Merchant.id source")
    admission_merchant = json_pointer_value(admission, "/constraints/payment/merchant", label)
    allowed_merchant = json_pointer_value(mandate, "/constraints/allowed_merchant", label)
    require(admission_merchant == merchant and allowed_merchant == merchant, f"{label}: merchant source records disagree")

    evaluation_text = expect_nonempty_string(json_pointer_value(admission, "/issued_at", label), f"{label} evaluation time")
    evaluation_epoch = parse_exact_utc_epoch(evaluation_text, f"{label} evaluation time")
    request_expiry = parse_exact_utc_epoch(json_pointer_value(admission, "/expires_at", label), f"{label} request expiry")
    mandate_iat = parse_exact_utc_epoch(json_pointer_value(mandate, "/issued_at", label), f"{label} mandate issued time")
    mandate_expiry = parse_exact_utc_epoch(json_pointer_value(mandate, "/expires_at", label), f"{label} mandate expiry")
    window_start = parse_exact_utc_epoch(json_pointer_value(mandate, "/constraints/execution_window/not_before", label), f"{label} mandate window start")
    window_end = parse_exact_utc_epoch(json_pointer_value(mandate, "/constraints/execution_window/not_after", label), f"{label} mandate window end")
    timeout = at(worksheet, "scaffolding_inputs", "x402_profile", "max_timeout_seconds")
    require(isinstance(timeout, int) and not isinstance(timeout, bool) and timeout > 0, f"{label}: invalid x402 timeout")
    closed_expiry = min(request_expiry, mandate_expiry, window_end)
    valid_before = min(request_expiry, mandate_expiry, window_end, evaluation_epoch + timeout)
    replay_nonce = expect_nonempty_string(json_pointer_value(mandate, "/constraints/replay_nonce", label), f"{label} replay nonce")

    expectations: dict[str, Any] = {
        "/nowEpochSeconds": evaluation_epoch,
        "/ap2/verification/verifiedAtEpochSeconds": evaluation_epoch,
        "/ap2/paymentReceipt/iat": evaluation_epoch,
        "/ap2/closedMandate/execution_date": evaluation_text,
        "/ap2/closedMandate/iat": evaluation_epoch,
        "/ap2/closedMandate/exp": closed_expiry,
        "/ap2/openMandate/iat": mandate_iat,
        "/ap2/openMandate/exp": min(mandate_expiry, window_end),
        "/x402/payload/payload/authorization/validAfter": str(window_start),
        "/x402/payload/payload/authorization/validBefore": str(valid_before),
        "/ap2/verification/cryptographicEvidence/expectedNonce": replay_nonce,
        "/ap2/closedMandate/payee/id": merchant,
        "/ap2/closedMandate/payment_instrument/x402/ap2PayeeId": merchant,
        "/ap2/openMandate/constraints/1/allowed/0/x402/ap2PayeeId": merchant,
        "/ap2/openMandate/constraints/3/allowed/0/id": merchant,
        "/ap2/closedMandate/payment_amount/amount": permitted_minor,
        "/ap2/closedMandate/payment_amount/currency": "USD",
        "/ap2/closedMandate/payment_instrument/x402/ap2PaymentAmount/amount": permitted_minor,
        "/ap2/closedMandate/payment_instrument/x402/ap2PaymentAmount/currency": "USD",
        "/ap2/openMandate/constraints/1/allowed/0/x402/ap2PaymentAmount/amount": permitted_minor,
        "/ap2/openMandate/constraints/1/allowed/0/x402/ap2PaymentAmount/currency": "USD",
        "/ap2/openMandate/constraints/2/max": limit_minor,
        "/ap2/openMandate/constraints/2/currency": "USD",
        "/ap2/closedMandate/payment_instrument/x402/amount": str(permitted_atomic),
        "/ap2/openMandate/constraints/1/allowed/0/x402/amount": str(permitted_atomic),
        "/x402/requirements/amount": str(requested_atomic),
        "/x402/payload/accepted/amount": str(requested_atomic),
        "/x402/payload/payload/authorization/value": str(requested_atomic),
    }
    return expectations, classify_eligible_source(admission, mandate, label)


def validate_independent_mapping(
    pulse_input: dict[str, Any],
    admission: dict[str, Any],
    mandate: dict[str, Any],
    worksheet: dict[str, Any],
    expected_source_class: str,
    label: str,
) -> dict[str, Any]:
    expectations, source_class = independent_mapping_expectations(admission, mandate, worksheet, label)
    require(source_class == expected_source_class, f"{label}: selected source classification mismatch")
    for pointer, expected in expectations.items():
        actual = json_pointer_value(pulse_input, pointer, f"{label} Pulse input")
        require(actual == expected, f"{label}: independent recomputation mismatch at {pointer}")
    lower_bound = json_pointer_value(pulse_input, "/ap2/openMandate/constraints/2/min", f"{label} Pulse input")
    require(isinstance(lower_bound, int) and not isinstance(lower_bound, bool) and 0 <= lower_bound <= expectations["/ap2/closedMandate/payment_amount/amount"], f"{label}: signed amount-range lower bound is invalid")
    reference = expect_nonempty_string(
        json_pointer_value(pulse_input, "/ap2/verification/closedMandateReference", f"{label} Pulse input"),
        f"{label} closed mandate reference",
    )
    require(re.fullmatch(r"[A-Za-z0-9_-]{43}", reference) is not None, f"{label}: closed mandate reference must be canonical unpadded base64url SHA-256")
    try:
        decoded = base64.urlsafe_b64decode(reference + "=")
    except ValueError as exc:
        raise CheckFailure(f"{label}: invalid closed mandate reference") from exc
    require(len(decoded) == 32, f"{label}: closed mandate reference must decode to 32 bytes")
    expected_eip_nonce = "0x" + decoded.hex()
    require(
        json_pointer_value(pulse_input, "/x402/payload/payload/authorization/nonce", f"{label} Pulse input") == expected_eip_nonce,
        f"{label}: replay nonce to closed-reference to EIP-3009 nonce chain mismatch",
    )
    return expectations


def projection_semantic_value(projection: dict[str, Any]) -> dict[str, Any]:
    return {
        "observed_relation_to_vate": projection.get("observed_relation_to_vate"),
        "pulse_outcome_class": projection.get("pulse_outcome_class"),
        "projected_vate_outcome": projection.get("projected_vate_outcome"),
        "projected_should_execute": projection.get("projected_should_execute"),
        "projected_reason_codes": projection.get("projected_reason_codes"),
        "projected_checks": projection.get("projected_checks"),
    }


def validate_candidate_projection_output(
    raw: bytes,
    case_ids: tuple[str, ...],
    projections: list[dict[str, Any]],
    label: str,
) -> None:
    output = expect_object(parse_strict_json(raw, label), label)
    require_exact_keys(output, {"interfaceVersion", "operation", "items"}, label)
    require(output.get("interfaceVersion") == CANDIDATE_INTERFACE_VERSION, f"{label}: interface version mismatch")
    require(output.get("operation") == "project", f"{label}: operation mismatch")
    items = expect_array(output.get("items"), f"{label}.items")
    require(len(items) == len(case_ids), f"{label}: item cardinality mismatch")
    for index, (raw_item, case_id, projection) in enumerate(zip(items, case_ids, projections, strict=True)):
        item = expect_object(raw_item, f"{label}.items[{index}]")
        require_exact_keys(item, {"workItemId", "projection"}, f"{label}.items[{index}]")
        require(item.get("workItemId") == CANDIDATE_WORK_ITEM_IDS[SELECTED_CASE_IDS.index(case_id)], f"{label}: opaque work-item binding mismatch")
        candidate_projection = expect_object(item.get("projection"), f"{label}.items[{index}].projection")
        require_exact_keys(candidate_projection, set(projection_semantic_value(projection)), f"{label}.items[{index}].projection")
        require(candidate_projection == projection_semantic_value(projection), f"{label}: candidate projection differs from the recorded result projection")


def validate_closed_projection_contract(
    case_id: str,
    admission: dict[str, Any],
    mandate: dict[str, Any],
    report: dict[str, Any],
    projection: dict[str, Any],
    label: str,
) -> None:
    source_class = classify_eligible_source(admission, mandate, label)
    expected_class = {
        SELECTED_CASE_IDS[0]: "allow",
        SELECTED_CASE_IDS[1]: "overrun",
        SELECTED_CASE_IDS[2]: "stale",
    }[case_id]
    require(source_class == expected_class, f"{label}: fixed eligible source classification changed")
    outcome_class = projection.get("pulse_outcome_class")
    relation = projection.get("observed_relation_to_vate")
    require(outcome_class not in {"error", "unsupported"}, f"{label}: completed case cannot use error/unsupported outcome class")
    failure_codes = [failure["code"] for failure in report["failures"]]
    if source_class == "allow":
        require(report["consistent"] is True and not failure_codes, f"{label}: allow requires a consistent raw Pulse report")
        require(outcome_class == "accept" and relation == "match", f"{label}: allow projection class/relation mismatch")
        require(projection.get("projected_vate_outcome") == "allow" and projection.get("projected_should_execute") is True, f"{label}: allow projection outcome mismatch")
        require(projection.get("projected_reason_codes") == ["EVIDENCE_VERIFIED", "POLICY_MATCH"], f"{label}: allow projection reasons mismatch")
    elif source_class == "overrun":
        require(report["consistent"] is False, f"{label}: overrun must be rejected by Pulse")
        require(failure_codes == ["AP2_X402_AMOUNT_MISMATCH"], f"{label}: overrun must preserve the exact Pulse amount-mismatch failure")
        require(outcome_class == "non-attenuate" and relation == "mismatch", f"{label}: overrun projection must remain non-attenuate/mismatch")
        require(projection.get("projected_vate_outcome") == "deny" and projection.get("projected_should_execute") is False, f"{label}: overrun projection outcome mismatch")
        require(projection.get("projected_reason_codes") == ["AP2_X402_AMOUNT_MISMATCH"], f"{label}: overrun projection must retain the raw Pulse reason")
    else:
        require(report["consistent"] is False, f"{label}: stale source must be rejected by Pulse")
        require("EIP3009_VALID_BEFORE_EXPIRED" in failure_codes, f"{label}: stale projection requires the Pulse expiry failure")
        require(set(failure_codes).issubset({"AP2_MANDATE_TIME_INVALID", "EIP3009_VALID_BEFORE_EXPIRED"}), f"{label}: stale projection contains an unrelated Pulse failure")
        require(outcome_class == "reject" and relation == "match", f"{label}: stale projection class/relation mismatch")
        require(projection.get("projected_vate_outcome") == "deny" and projection.get("projected_should_execute") is False, f"{label}: stale projection outcome mismatch")
        require(projection.get("projected_reason_codes") == ["PERMIT_EXPIRED", "FAIL_CLOSED"], f"{label}: stale projection reasons mismatch")


def validate_candidate_execution_record(
    value: Any,
    bundle_root: Path,
    mapping_repo: Path,
    mapping_commit: str,
    command: list[str],
    runtime: CandidateRuntime,
    export_contract: dict[str, Any],
    eligible_inputs: dict[str, dict[str, tuple[str, str]]],
    pulse_inputs: dict[str, tuple[str, str, dict[str, Any]]],
    reports: list[dict[str, Any]],
    projections: list[dict[str, Any]],
    case_ids: tuple[str, ...],
    worksheet: dict[str, Any],
    *,
    allow_self_test: bool,
    label: str,
) -> tuple[str, str]:
    execution = expect_object(value, label)
    require_exact_keys(
        execution,
        {
            "interface_version",
            "command",
            "runtime",
            "commit_export",
            "map_request",
            "map_output",
            "projection_request",
            "projection_output",
            "sensitivity_contract",
        },
        label,
    )
    require(execution.get("interface_version") == CANDIDATE_INTERFACE_VERSION, f"{label}: interface version mismatch")
    require(execution.get("command") == command, f"{label}: recorded command differs from the commit-bound candidate contract")
    require(execution.get("runtime") == candidate_runtime_record(runtime), f"{label}: recorded candidate runtime differs from the execution environment")
    require(execution.get("commit_export") == export_contract, f"{label}: recorded commit-export closure differs from the candidate commit")
    require(
        execution.get("sensitivity_contract")
        == {
            "probe_dimensions": ["amount", "merchant", "evaluation_time", "replay_nonce"],
            "randomized_per_validation": True,
            "independent_recomputation": True,
            "tamper_proof_claim": False,
        },
        f"{label}: sensitivity contract mismatch",
    )
    documents = eligible_documents(bundle_root, eligible_inputs, case_ids, label)
    expected_map_request = candidate_map_request_value(documents, case_ids)
    map_request_path, map_request_raw, _ = validate_bundle_ref(bundle_root, execution.get("map_request"), f"{label}.map_request")
    require(map_request_raw == canonical_json_bytes(expected_map_request), f"{label}: map request is not the exact eligible-input-only canonical request")
    map_output_path, map_output_raw, map_output_hash = validate_bundle_ref(bundle_root, execution.get("map_output"), f"{label}.map_output")
    replayed_map_raw = run_candidate_executable(
        mapping_repo,
        mapping_commit,
        command,
        runtime,
        map_request_raw,
        f"{label} map execution",
        expected_export_contract=export_contract,
    )
    require(replayed_map_raw == map_output_raw, f"{label}: recorded map output is not byte-exact candidate stdout")
    mapped_raw_values, mapped_values = validate_candidate_map_output(map_output_raw, case_ids, f"{label}.map_output")
    for case_id, mapped_raw, mapped_value in zip(case_ids, mapped_raw_values, mapped_values, strict=True):
        pulse_path, pulse_hash, pulse_value = pulse_inputs[case_id]
        pulse_file_raw = read_bundle_file(bundle_root, pulse_path, f"{label} Pulse input")[1]
        require(mapped_raw.encode("utf-8") == pulse_file_raw, f"{label}: candidate map output is not byte-exact with the replayed Pulse input")
        require(sha256_bytes(pulse_file_raw) == pulse_hash, f"{label}: candidate map output/Pulse input hash binding mismatch")
        require(mapped_value == pulse_value, f"{label}: candidate map output/Pulse input value mismatch")

    if not allow_self_test:
        for case_id, pulse_value in zip(case_ids, mapped_values, strict=True):
            admission, mandate = documents[case_id]
            expected_class = {
                SELECTED_CASE_IDS[0]: "allow",
                SELECTED_CASE_IDS[1]: "overrun",
                SELECTED_CASE_IDS[2]: "stale",
            }[case_id]
            validate_independent_mapping(pulse_value, admission, mandate, worksheet, expected_class, f"{label} {case_id}")
        run_sensitivity_probes(
            mapping_repo,
            mapping_commit,
            command,
            runtime,
            export_contract,
            expected_map_request,
            mapped_raw_values,
            worksheet,
            case_ids,
            label,
        )

    expected_projection_request = candidate_projection_request_value(documents, case_ids, reports)
    _, projection_request_raw, _ = validate_bundle_ref(bundle_root, execution.get("projection_request"), f"{label}.projection_request")
    require(projection_request_raw == canonical_json_bytes(expected_projection_request), f"{label}: projection request is not exact eligible-input-plus-raw-report canonical JSON")
    _, projection_output_raw, _ = validate_bundle_ref(bundle_root, execution.get("projection_output"), f"{label}.projection_output")
    replayed_projection_raw = run_candidate_executable(
        mapping_repo,
        mapping_commit,
        command,
        runtime,
        projection_request_raw,
        f"{label} projection execution",
        expected_export_contract=export_contract,
    )
    require(replayed_projection_raw == projection_output_raw, f"{label}: recorded projection output is not byte-exact candidate stdout")
    validate_candidate_projection_output(projection_output_raw, case_ids, projections, f"{label}.projection_output")
    for case_id, report, projection in zip(case_ids, reports, projections, strict=True):
        admission, mandate = documents[case_id]
        validate_closed_projection_contract(case_id, admission, mandate, report, projection, f"{label} {case_id}")
    verify_candidate_runtime_unchanged(runtime, mapping_repo, f"{label} after all candidate executions")
    return map_output_path, map_output_hash


def run_sensitivity_probes(
    mapping_repo: Path,
    mapping_commit: str,
    command: list[str],
    runtime: CandidateRuntime,
    export_contract: dict[str, Any],
    baseline_request: dict[str, Any],
    baseline_raw_outputs: list[str],
    worksheet: dict[str, Any],
    case_ids: tuple[str, ...],
    label: str,
) -> None:
    require(bool(case_ids), f"{label}: sensitivity probes require at least one completed case")
    dimensions = {
        "amount": "/x402/requirements/amount",
        "merchant": "/ap2/closedMandate/payee/id",
        "evaluation_time": "/nowEpochSeconds",
        "replay_nonce": "/ap2/verification/cryptographicEvidence/expectedNonce",
    }
    for target_index, case_id in enumerate(case_ids):
        baseline_eligible = baseline_request["items"][target_index]["eligibleInput"]
        baseline_admission = baseline_eligible["admissionRequest"]
        baseline_mandate = baseline_eligible["ap2Mandate"]
        expected_source_class = classify_eligible_source(
            baseline_admission,
            baseline_mandate,
            f"{label} {case_id} sensitivity baseline",
        )
        baseline_value = expect_object(
            parse_strict_json(
                baseline_raw_outputs[target_index].encode("utf-8"),
                f"{label} {case_id} baseline Pulse input",
            ),
            f"{label} {case_id} baseline Pulse input",
        )
        for dimension, changed_pointer in dimensions.items():
            request = copy.deepcopy(baseline_request)
            eligible = request["items"][target_index]["eligibleInput"]
            admission = eligible["admissionRequest"]
            mandate = eligible["ap2Mandate"]
            if dimension == "amount":
                cents = 11 + secrets.randbelow(78)
                whole = 120 if expected_source_class == "overrun" else 41
                admission["constraints"]["max_amount"]["value"] = f"{whole}.{cents:02d}"
            elif dimension == "merchant":
                merchant = f"probe-{secrets.token_hex(6)}.example"
                admission["constraints"]["payment"]["merchant"] = merchant
                mandate["merchant"] = merchant
                mandate["constraints"]["allowed_merchant"] = merchant
            elif dimension == "evaluation_time":
                delta = 17 + secrets.randbelow(73)
                issued = parse_exact_utc_epoch(admission["issued_at"], f"{label} probe issued_at") + delta
                expires = parse_exact_utc_epoch(admission["expires_at"], f"{label} probe expires_at") + delta
                admission["issued_at"] = format_exact_utc(issued)
                admission["expires_at"] = format_exact_utc(expires)
            else:
                mandate["constraints"]["replay_nonce"] = f"probe-nonce-{secrets.token_urlsafe(12)}"
            probe_raw = run_candidate_executable(
                mapping_repo,
                mapping_commit,
                command,
                runtime,
                canonical_json_bytes(request),
                f"{label} {case_id} {dimension} sensitivity probe",
                expected_export_contract=export_contract,
            )
            probe_raw_outputs, probe_values = validate_candidate_map_output(
                probe_raw,
                case_ids,
                f"{label} {case_id} {dimension} sensitivity output",
            )
            for index in range(len(case_ids)):
                if index != target_index:
                    require(
                        probe_raw_outputs[index] == baseline_raw_outputs[index],
                        f"{label}: {case_id} {dimension} probe changed an unrelated work item",
                    )
            probe_value = probe_values[target_index]
            validate_sensitivity_provenance_diff(
                baseline_value,
                probe_value,
                worksheet,
                f"{label} {case_id} {dimension} sensitivity provenance",
            )
            validate_independent_mapping(
                probe_value,
                admission,
                mandate,
                worksheet,
                expected_source_class,
                f"{label} {case_id} {dimension} sensitivity",
            )
            require(
                canonical_json_bytes(
                    json_pointer_value(probe_value, changed_pointer, f"{label} {case_id} {dimension} probe")
                )
                != canonical_json_bytes(
                    json_pointer_value(baseline_value, changed_pointer, f"{label} {case_id} baseline")
                ),
                f"{label}: {case_id} {dimension} sensitivity probe did not change its decision-relevant destination",
            )
            if dimension == "replay_nonce":
                require(
                    json_pointer_value(
                        probe_value,
                        "/x402/payload/payload/authorization/nonce",
                        f"{label} {case_id} nonce probe",
                    )
                    != json_pointer_value(
                        baseline_value,
                        "/x402/payload/payload/authorization/nonce",
                        f"{label} {case_id} baseline nonce",
                    ),
                    f"{label}: {case_id} replay-nonce sensitivity did not propagate through the generated closed reference to EIP-3009 nonce",
                )


def validate_sensitivity_provenance_diff(
    baseline_value: dict[str, Any],
    probe_value: dict[str, Any],
    worksheet: dict[str, Any],
    label: str,
) -> tuple[str, ...]:
    """Reject a completed leaf declaration contradicted by a VATE-input replay."""

    require(worksheet.get("status") == "completed", f"{label}: sensitivity provenance requires a completed worksheet")
    baseline_paths = tuple(sorted(primitive_leaf_paths(baseline_value)))
    probe_paths = tuple(sorted(primitive_leaf_paths(probe_value)))
    require(baseline_paths == PULSE_PRIMITIVE_LEAF_PATHS, f"{label}: baseline must retain all 142 primitive leaves")
    require(probe_paths == PULSE_PRIMITIVE_LEAF_PATHS, f"{label}: probe must retain all 142 primitive leaves")
    changed_paths = tuple(
        path
        for path in PULSE_PRIMITIVE_LEAF_PATHS
        if canonical_json_bytes(json_pointer_value(baseline_value, path, f"{label} baseline"))
        != canonical_json_bytes(json_pointer_value(probe_value, path, f"{label} probe"))
    )
    inventory = expect_array(worksheet.get("generated_field_inventory"), f"{label} worksheet inventory")
    inventory_by_destination = {
        expect_nonempty_string(leaf.get("pulse_destination"), f"{label} worksheet destination"): leaf
        for leaf in (expect_object(item, f"{label} worksheet leaf") for item in inventory)
    }
    require(set(inventory_by_destination) == set(PULSE_PRIMITIVE_LEAF_PATHS), f"{label}: worksheet must retain all 142 primitive leaves")
    for destination in changed_paths:
        leaf = inventory_by_destination[destination]
        declared_worksheet_origin = (
            leaf.get("source_document") == "worksheet"
            and leaf.get("provenance") == "non-vate-scaffolding"
        )
        require(
            not declared_worksheet_origin,
            f"{label}: VATE input probe changed {destination}, but the completed worksheet declares worksheet/non-vate-scaffolding direct origin",
        )
    return changed_paths


def validate_attempt_contract(
    value: Any,
    status: str,
    bundle_root: Path,
    label: str,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    attempt = expect_object(value, label)
    require_exact_keys(
        attempt,
        {"stage", "reason_code", "details", "completed_case_ids", "incomplete_case_ids", "evidence"},
        label,
    )
    stage = expect_nonempty_string(attempt.get("stage"), f"{label}.stage")
    reason_code = expect_nonempty_string(attempt.get("reason_code"), f"{label}.reason_code")
    expect_nonempty_string(attempt.get("details"), f"{label}.details")
    require(stage in ATTEMPT_STAGES, f"{label}: unknown attempt stage")
    require(reason_code in ATTEMPT_REASON_CODES, f"{label}: unknown stable reason code")
    completed = tuple(expect_array(attempt.get("completed_case_ids"), f"{label}.completed_case_ids"))
    incomplete = tuple(expect_array(attempt.get("incomplete_case_ids"), f"{label}.incomplete_case_ids"))
    require(len(completed) == len(set(completed)), f"{label}: duplicate completed case")
    require(len(incomplete) == len(set(incomplete)), f"{label}: duplicate incomplete case")
    require(not (set(completed) & set(incomplete)), f"{label}: completed and incomplete case sets overlap")
    require(set(completed) | set(incomplete) == set(SELECTED_CASE_IDS), f"{label}: selected-case partition is incomplete")
    require(completed == tuple(case_id for case_id in SELECTED_CASE_IDS if case_id in completed), f"{label}: completed case order mismatch")
    require(incomplete == tuple(case_id for case_id in SELECTED_CASE_IDS if case_id in incomplete), f"{label}: incomplete case order mismatch")
    if status == "completed":
        require(stage == "complete" and reason_code == "COMPLETED", f"{label}: completed attempt stage/reason mismatch")
        require(completed == SELECTED_CASE_IDS and not incomplete, f"{label}: completed attempt must close all selected cases")
    elif status == "partial":
        require(1 <= len(completed) <= 2 and bool(incomplete), f"{label}: partial attempt must complete one or two selected cases")
        require(stage != "complete" and reason_code != "COMPLETED", f"{label}: partial attempt cannot claim completion")
    elif status == "blocked":
        require(len(completed) <= 2 and bool(incomplete), f"{label}: blocked attempt must retain an incomplete case")
        require(stage != "complete" and reason_code != "COMPLETED", f"{label}: blocked attempt cannot claim completion")
    else:
        raise CheckFailure(f"{label}: unsupported attempt status")

    evidence = expect_array(attempt.get("evidence"), f"{label}.evidence")
    require(bool(evidence), f"{label}: at least one hash-bound evidence record is required")
    evidence_keys: set[tuple[Any, ...]] = set()
    completed_evidence_kinds: dict[str, set[str]] = {case_id: set() for case_id in completed}
    global_evidence_kinds: set[str] = set()
    allowed_kinds = {
        "starter-manifest",
        "mapping-source",
        "worksheet",
        "eligible-input-manifest",
        "generated-records",
        "pulse-input",
        "raw-pulse-output",
        "candidate-map-request",
        "candidate-map-output",
        "candidate-projection-request",
        "candidate-projection-output",
        "blocker-record",
    }
    for index, raw_evidence in enumerate(evidence):
        item = expect_object(raw_evidence, f"{label}.evidence[{index}]")
        require_exact_keys(item, {"case_id", "kind", "path", "raw_sha256"}, f"{label}.evidence[{index}]")
        case_id = item.get("case_id")
        require(case_id is None or case_id in SELECTED_CASE_IDS, f"{label}.evidence[{index}]: unknown case ID")
        kind = expect_nonempty_string(item.get("kind"), f"{label}.evidence[{index}].kind")
        require(kind in allowed_kinds, f"{label}.evidence[{index}]: unknown evidence kind")
        path, _, digest = validate_bundle_ref(
            bundle_root,
            {"path": item.get("path"), "raw_sha256": item.get("raw_sha256")},
            f"{label}.evidence[{index}]",
        )
        key = (case_id, kind, path, digest)
        require(key not in evidence_keys, f"{label}.evidence[{index}]: duplicate evidence record")
        evidence_keys.add(key)
        if case_id in completed_evidence_kinds:
            completed_evidence_kinds[case_id].add(kind)
        if case_id is None:
            global_evidence_kinds.add(kind)
        if case_id in incomplete:
            require(kind == "blocker-record", f"{label}: incomplete case cannot claim generated or replay evidence")
    for case_id, kinds in completed_evidence_kinds.items():
        require(
            {"pulse-input", "raw-pulse-output"}.issubset(kinds),
            f"{label}: completed case lacks Pulse input/raw output evidence",
        )
    if completed:
        require(
            {
                "mapping-source",
                "worksheet",
                "eligible-input-manifest",
                "generated-records",
                "candidate-map-request",
                "candidate-map-output",
                "candidate-projection-request",
                "candidate-projection-output",
            }.issubset(global_evidence_kinds),
            f"{label}: completed-case execution evidence closure is incomplete",
        )
    return completed, incomplete


def validate_incomplete_selected_result_entry(
    value: Any,
    case_id: str,
    selected_case: dict[str, Any],
    label: str,
) -> None:
    entry = expect_object(value, label)
    require_exact_keys(
        entry,
        {"case_id", "status", "outcome", "should_execute", "reason_codes", "artifacts", "limitations"},
        label,
    )
    require(entry.get("case_id") == case_id, f"{label}: case ID mismatch")
    require(entry.get("status") == "skipped", f"{label}: incomplete case must be skipped")
    require(entry.get("outcome") == "unmapped", f"{label}: incomplete case outcome must remain unmapped")
    require(entry.get("should_execute") is False, f"{label}: incomplete execution sentinel mismatch")
    require(entry.get("reason_codes") == ["PULSE_RESULT_NOT_RECORDED"], f"{label}: incomplete reason sentinel mismatch")
    validate_comparison_artifact_ref(entry.get("artifacts"), selected_case, f"{label}.artifacts")
    limitations = expect_array(entry.get("limitations"), f"{label}.limitations")
    require(bool(limitations), f"{label}: incomplete case limitation is required")


def validate_partial_or_blocked_bundle(
    run_result: dict[str, Any],
    index_path: Path,
    manifest: dict[str, Any],
    source: SourceSnapshot,
    selected_by_id: dict[str, dict[str, Any]],
    *,
    mapping_repo: Path | None,
    pulse_repo: Path | None,
    candidate_python_runtime: Path | None,
    candidate_node_runtime: Path | None,
    allow_self_test: bool,
) -> None:
    external = expect_object(run_result.get("external_run"), "attempt external_run")
    require_exact_keys(
        external,
        {
            "record_version",
            "status",
            "evidence_class",
            "vate_source_commit",
            "pulse_verifier_commit",
            "source_policy",
            "comparison_contract",
            "attempt",
            "starter_manifest",
            "mapping_source",
            "worksheet",
            "eligible_input_manifest",
            "generated_records",
            "candidate_execution",
            "case_runs",
        },
        "attempt external_run",
    )
    status = external.get("status")
    require(status in {"partial", "blocked"}, "attempt status must be partial or blocked")
    bundle_root = index_path.parent
    require(external.get("record_version") == RUN_RECORD_VERSION, "attempt record version mismatch")
    require(external.get("vate_source_commit") == VATE_COMMIT, "attempt VATE pin mismatch")
    require(external.get("pulse_verifier_commit") == PULSE_COMMIT, "attempt Pulse pin mismatch")
    require(external.get("comparison_contract") == EXPECTED_COMPARISON_CONTRACT, "attempt comparison contract mismatch")
    completed_case_ids, incomplete_case_ids = validate_attempt_contract(
        external.get("attempt"), status, bundle_root, "attempt progress record"
    )
    expected_attempt_source_policy = SELF_TEST_FIXTURE_SOURCE_POLICY if allow_self_test and completed_case_ids else EXPECTED_SOURCE_POLICY
    require(external.get("source_policy") == expected_attempt_source_policy, "attempt source policy mismatch")
    expected_evidence_class = (
        "validator-self-test"
        if allow_self_test
        else "candidate-executed-subset"
        if completed_case_ids
        else "unverified-recorded"
    )
    require(external.get("evidence_class") == expected_evidence_class, "attempt evidence class mismatch")
    if completed_case_ids:
        require(mapping_repo is not None, "partial/blocked run with completed cases requires --mapping-repo")
        require(pulse_repo is not None, "partial/blocked run with completed cases requires --pulse-repo")

    implementation = expect_object(run_result.get("implementation"), "attempt implementation")
    require_exact_keys(
        implementation,
        {"name", "type", "version", "language", "source", "commit", "environment", "upstream_verifier"},
        "attempt implementation",
    )
    require(implementation.get("type") == f"external-verifier-projection-{status}", "attempt implementation type mismatch")
    for field in ("name", "version", "language", "source", "commit", "environment"):
        expect_nonempty_string(implementation.get(field), f"attempt implementation.{field}")
    require(
        implementation.get("upstream_verifier")
        == {
            "source": "https://github.com/shibutatsu/pulse-ap2-x402-conformance",
            "commit": PULSE_COMMIT,
            "entry_point": "src/verifier.ts#verifyConformanceCase",
        },
        "attempt frozen upstream verifier identity mismatch",
    )

    results = expect_array(run_result.get("results"), "attempt results")
    require(len(results) == 75, "attempt result set must contain three selected entries and 72 explicit out-of-scope entries")
    for index, case_id in enumerate(SELECTED_CASE_IDS):
        if case_id in completed_case_ids:
            validate_completed_result_entry(results[index], case_id, selected_by_id[case_id], f"attempt results[{index}]")
        else:
            validate_incomplete_selected_result_entry(results[index], case_id, selected_by_id[case_id], f"attempt results[{index}]")
    for offset, case_id in enumerate(out_of_scope_case_ids(source), start=3):
        validate_out_of_scope_result_entry(results[offset], case_id, f"attempt results[{offset}]")

    starter_path, starter_raw, _ = validate_bundle_ref(
        bundle_root,
        external.get("starter_manifest"),
        "attempt starter_manifest",
        expected_digest=sha256_bytes(read_regular_nonempty(MANIFEST_PATH)),
    )
    require(
        expect_object(parse_strict_json(starter_raw, f"bundle:{starter_path}"), "attempt copied starter") == manifest,
        "attempt starter manifest copy differs from the validated starter",
    )

    for optional_name in ("mapping_source", "worksheet", "eligible_input_manifest", "generated_records"):
        item = expect_object(external.get(optional_name), f"attempt {optional_name}")
        if optional_name == "mapping_source":
            require_exact_keys(
                item,
                {
                    "owner",
                    "repository",
                    "locator_verification",
                    "commit",
                    "repository_path",
                    "entrypoint",
                    "command",
                    "bundle_path",
                    "raw_sha256",
                },
                "attempt mapping_source",
            )
            require(item.get("locator_verification") == "local-git-origin-only-no-remote-fetch", "attempt mapping locator boundary mismatch")
            values = [item.get(field) for field in ("repository", "commit", "repository_path", "entrypoint", "command", "bundle_path", "raw_sha256")]
            require(all(value is None for value in values) or all(value is not None for value in values), "attempt mapping source must be wholly absent or wholly recorded")
            if all(value is not None for value in values):
                _, mapping_raw, _ = validate_bundle_ref(
                    bundle_root,
                    {"path": item["bundle_path"], "raw_sha256": item["raw_sha256"]},
                    "attempt mapping source copy",
                )
                scan_text_for_credentials(mapping_raw.decode("utf-8", errors="strict"), "attempt mapping source copy")
        else:
            require_exact_keys(item, {"path", "raw_sha256"}, f"attempt {optional_name}")
            require(
                (item.get("path") is None) == (item.get("raw_sha256") is None),
                f"attempt {optional_name}: path/hash must be both set or both null",
            )
            if item.get("path") is not None:
                validate_bundle_ref(bundle_root, item, f"attempt {optional_name}")

    case_runs = expect_array(external.get("case_runs"), "attempt case_runs")
    require(len(case_runs) == 3, "attempt must retain exactly three selected case records")
    pulse_input_records: list[tuple[str, str, str]] = []
    pulse_inputs_by_id: dict[str, tuple[str, str, dict[str, Any]]] = {}
    raw_output_refs: list[tuple[str, str]] = []
    completed_projections: list[dict[str, Any]] = []
    for index, case_id in enumerate(SELECTED_CASE_IDS):
        case_run = expect_object(case_runs[index], f"attempt case_runs[{index}]")
        require_exact_keys(
            case_run,
            {"case_id", "vate_input_closure_sha256", "vate_inputs", "pulse_input", "raw_report", "projection"},
            f"attempt case_runs[{index}]",
        )
        require(case_run.get("case_id") == case_id, f"attempt case identity mismatch: {case_id}")
        require(case_run.get("vate_input_closure_sha256") == EXPECTED_CLOSURE_DIGESTS[case_id], f"attempt closure digest mismatch: {case_id}")
        fixed_inputs = expect_array(selected_by_id[case_id]["inputs"], f"selected inputs {case_id}")
        vate_inputs = expect_array(case_run.get("vate_inputs"), f"attempt {case_id}.vate_inputs")
        require(len(vate_inputs) == 4, f"attempt {case_id}: four VATE closure records required")
        for input_index, (raw_ref, fixed) in enumerate(zip(vate_inputs, fixed_inputs, strict=True)):
            ref = expect_object(raw_ref, f"attempt {case_id}.vate_inputs[{input_index}]")
            require_exact_keys(
                ref,
                {"role", "artifact_key", "source_path", "source_raw_sha256", "bundle_path", "bundle_raw_sha256"},
                f"attempt {case_id}.vate_inputs[{input_index}]",
            )
            require(ref.get("role") == fixed["role"], f"attempt {case_id}: VATE input role mismatch")
            require(ref.get("artifact_key") == fixed["artifact_key"], f"attempt {case_id}: VATE artifact key mismatch")
            require(ref.get("source_path") == fixed["path"], f"attempt {case_id}: VATE source path mismatch")
            require(ref.get("source_raw_sha256") == fixed["raw_sha256"], f"attempt {case_id}: VATE source hash mismatch")
            if case_id in completed_case_ids:
                _, local_raw, _ = validate_bundle_ref(
                    bundle_root,
                    {"path": ref.get("bundle_path"), "raw_sha256": ref.get("bundle_raw_sha256")},
                    f"attempt {case_id}.vate_inputs[{input_index}]",
                    expected_digest=fixed["raw_sha256"],
                )
                require(local_raw == source.blobs[fixed["path"]], f"attempt {case_id}: VATE bundle copy differs from fixed Git bytes")
            else:
                require(
                    ref.get("bundle_path") is None and ref.get("bundle_raw_sha256") is None,
                    f"attempt incomplete case has a VATE bundle-copy claim: {case_id}",
                )
        projection = expect_object(case_run.get("projection"), f"attempt {case_id}.projection")
        require_exact_keys(
            projection,
            {
                "result_index",
                "source_document",
                "source_json_pointer",
                "observed_relation_to_vate",
                "pulse_outcome_class",
                "projected_vate_outcome",
                "projected_should_execute",
                "projected_reason_codes",
                "projected_checks",
            },
            f"attempt {case_id}.projection",
        )
        require(projection.get("result_index") == index, f"attempt {case_id}: projection result index mismatch")
        require(projection.get("source_document") == "raw_pulse_output", f"attempt {case_id}: projection source mismatch")
        if case_id not in completed_case_ids:
            require(case_run.get("pulse_input") == {"path": None, "raw_sha256": None}, f"attempt incomplete case has a Pulse input claim: {case_id}")
            require(
                case_run.get("raw_report") == {"path": None, "raw_sha256": None, "report_index": index},
                f"attempt incomplete case has a raw report claim: {case_id}",
            )
            require(projection.get("source_json_pointer") == f"/reports/{index}", f"attempt incomplete projection pointer mismatch: {case_id}")
            for field in (
                "observed_relation_to_vate",
                "pulse_outcome_class",
                "projected_vate_outcome",
                "projected_should_execute",
                "projected_reason_codes",
                "projected_checks",
            ):
                require(projection.get(field) is None, f"attempt incomplete projection must remain unset: {case_id}")
            continue
        pulse_path, pulse_raw, pulse_hash = validate_bundle_ref(
            bundle_root, case_run.get("pulse_input"), f"attempt {case_id}.pulse_input"
        )
        pulse_value = expect_object(parse_strict_json(pulse_raw, f"bundle:{pulse_path}"), f"attempt {case_id}.pulse_input")
        validate_completed_pulse_input(pulse_value, case_id, f"attempt {case_id}.pulse_input")
        pulse_input_records.append((case_id, pulse_path, pulse_hash))
        pulse_inputs_by_id[case_id] = (pulse_path, pulse_hash, pulse_value)
        raw_ref = expect_object(case_run.get("raw_report"), f"attempt {case_id}.raw_report")
        require_exact_keys(raw_ref, {"path", "raw_sha256", "report_index"}, f"attempt {case_id}.raw_report")
        require(raw_ref.get("report_index") == len(raw_output_refs), f"attempt {case_id}: raw report index mismatch")
        raw_path, _, raw_hash = validate_bundle_ref(
            bundle_root,
            {"path": raw_ref.get("path"), "raw_sha256": raw_ref.get("raw_sha256")},
            f"attempt {case_id}.raw_report",
        )
        raw_output_refs.append((raw_path, raw_hash))
        result_entry = expect_object(results[index], f"attempt results[{index}]")
        require(
            projection.get("source_json_pointer") == f"/reports/{len(raw_output_refs) - 1}",
            f"attempt {case_id}: projection report pointer mismatch",
        )
        require(projection.get("projected_vate_outcome") == result_entry.get("outcome"), f"attempt {case_id}: projected outcome mismatch")
        require(projection.get("projected_should_execute") == result_entry.get("should_execute"), f"attempt {case_id}: projected execution mismatch")
        require(projection.get("projected_reason_codes") == result_entry.get("reason_codes"), f"attempt {case_id}: projected reasons mismatch")
        require(projection.get("projected_checks") == result_entry.get("checks"), f"attempt {case_id}: projected checks mismatch")
        completed_projections.append(projection)

    if completed_case_ids:
        assert mapping_repo is not None and pulse_repo is not None
        require(len(set(raw_output_refs)) == 1, "attempt completed cases must bind one raw Pulse output file")
        raw_path, raw_hash = raw_output_refs[0]
        raw_bytes = read_bundle_file(bundle_root, raw_path, "attempt raw Pulse output")[1]
        require(sha256_bytes(raw_bytes) == raw_hash, "attempt raw Pulse output hash mismatch")
        raw_output_value = expect_object(parse_strict_json(raw_bytes, f"bundle:{raw_path}"), "attempt raw Pulse output")
        reports = validate_raw_pulse_output(
            raw_output_value,
            pulse_input_records,
            "attempt raw Pulse output",
        )
        validate_pulse_checkout(pulse_repo, manifest)
        replayed_reports, actual_pulse_runtime = replay_pulse_reports(pulse_repo, bundle_root, pulse_input_records)
        require(raw_output_value.get("runtime") == actual_pulse_runtime, "attempt recorded Pulse runtime does not match replay")
        require(reports == replayed_reports, "attempt raw reports do not exactly match frozen Pulse replay")

        mapping_source = expect_object(external.get("mapping_source"), "attempt mapping_source")
        _, mapping_raw, _ = validate_bundle_ref(
            bundle_root,
            {"path": mapping_source.get("bundle_path"), "raw_sha256": mapping_source.get("raw_sha256")},
            "attempt mapping source copy",
        )
        candidate_command, candidate_runtime, candidate_export_contract = validate_mapping_checkout(
            mapping_repo,
            mapping_source,
            mapping_raw,
            selected_by_id,
            candidate_python_runtime=candidate_python_runtime,
            candidate_node_runtime=candidate_node_runtime,
            allow_self_test=allow_self_test,
        )
        require(implementation.get("source") == mapping_source.get("repository"), "attempt implementation source must equal mapping locator")
        require(implementation.get("commit") == mapping_source.get("commit"), "attempt implementation commit must equal mapping commit")

        eligible_ref = expect_object(external.get("eligible_input_manifest"), "attempt eligible_input_manifest")
        eligible_path, eligible_raw, _ = validate_bundle_ref(bundle_root, eligible_ref, "attempt eligible_input_manifest")
        eligible_inputs = validate_eligible_input_manifest(
            parse_strict_json(eligible_raw, f"bundle:{eligible_path}"),
            bundle_root,
            selected_by_id,
            source,
            completed_case_ids,
            "attempt eligible input manifest",
        )
        generated_ref = expect_object(external.get("generated_records"), "attempt generated_records")
        generated_path, generated_raw, _ = validate_bundle_ref(bundle_root, generated_ref, "attempt generated_records")
        worksheet_ref = expect_object(external.get("worksheet"), "attempt worksheet")
        worksheet_path, worksheet_raw, _ = validate_bundle_ref(bundle_root, worksheet_ref, "attempt worksheet")
        worksheet = expect_object(parse_strict_json(worksheet_raw, f"bundle:{worksheet_path}"), "attempt worksheet")
        validate_worksheet(worksheet, selected_by_id, source=source, completed=True)
        map_output_binding = validate_candidate_execution_record(
            external.get("candidate_execution"),
            bundle_root,
            mapping_repo,
            expect_nonempty_string(mapping_source.get("commit"), "attempt mapping commit"),
            candidate_command,
            candidate_runtime,
            candidate_export_contract,
            eligible_inputs,
            pulse_inputs_by_id,
            reports,
            completed_projections,
            completed_case_ids,
            worksheet,
            allow_self_test=allow_self_test,
            label="attempt candidate execution",
        )
        validate_generated_records(
            parse_strict_json(generated_raw, f"bundle:{generated_path}"),
            bundle_root,
            worksheet,
            pulse_inputs_by_id,
            completed_case_ids,
            "attempt generated records",
            worksheet_raw_sha256=sha256_bytes(worksheet_raw),
            candidate_map_output=map_output_binding,
        )
    else:
        require(candidate_python_runtime is None and candidate_node_runtime is None, "unverified attempt must not select a candidate runtime")
        candidate_execution = expect_object(external.get("candidate_execution"), "unverified attempt candidate_execution")
        require_exact_keys(
            candidate_execution,
            {
                "interface_version",
                "command",
                "runtime",
                "commit_export",
                "map_request",
                "map_output",
                "projection_request",
                "projection_output",
                "sensitivity_contract",
            },
            "unverified attempt candidate_execution",
        )
        require(candidate_execution.get("interface_version") == CANDIDATE_INTERFACE_VERSION, "unverified attempt candidate interface version mismatch")
        require(candidate_execution.get("command") is None, "unverified attempt cannot claim candidate execution")
        require(candidate_execution.get("runtime") == CANDIDATE_RUNTIME_TEMPLATE_RECORD, "unverified attempt cannot claim candidate runtime")
        require(
            candidate_execution.get("commit_export") == CANDIDATE_EXPORT_TEMPLATE_CONTRACT,
            "unverified attempt candidate commit-export contract mismatch",
        )
        for ref_name in ("map_request", "map_output", "projection_request", "projection_output"):
            require(candidate_execution.get(ref_name) == {"path": None, "raw_sha256": None}, f"unverified attempt cannot claim {ref_name}")
        require(
            candidate_execution.get("sensitivity_contract")
            == {
                "probe_dimensions": ["amount", "merchant", "evaluation_time", "replay_nonce"],
                "randomized_per_validation": True,
                "independent_recomputation": True,
                "tamper_proof_claim": False,
            },
            "unverified attempt sensitivity contract mismatch",
        )

    scan_json_for_credentials(run_result, "partial/blocked run bundle index")


def validate_run_bundle(
    run_bundle_path: Path,
    manifest: dict[str, Any],
    source: SourceSnapshot,
    selected_by_id: dict[str, dict[str, Any]],
    *,
    mapping_repo: Path | None = None,
    pulse_repo: Path | None = None,
    candidate_python_runtime: Path | None = None,
    candidate_node_runtime: Path | None = None,
    allow_self_test: bool = False,
) -> None:
    index_path = run_bundle_path.absolute()
    run_result = expect_object(
        parse_strict_json(read_regular_nonempty(index_path), str(index_path)),
        "completed run bundle index",
    )
    scan_json_for_credentials(run_result, "completed run bundle index")
    require_exact_keys(
        run_result,
        {
            "version",
            "profile",
            "generated_at",
            "artifact_mode",
            "implementation",
            "corpus",
            "results",
            "external_run",
            "limitations",
        },
        "completed run bundle index",
    )
    require(run_result.get("version") == "vate-sut-results-2026-07", "completed run: result version mismatch")
    require(run_result.get("profile") == PROFILE, "completed run: profile mismatch")
    validate_rfc3339_timestamp(run_result.get("generated_at"), "completed run generated_at")
    require(run_result.get("artifact_mode") == "corpus-fixture-validation", "completed run: artifact_mode mismatch")
    corpus = expect_object(run_result.get("corpus"), "completed run corpus")
    require_exact_keys(corpus, {"profile", "digest"}, "completed run corpus")
    require(corpus.get("profile") == PROFILE, "completed run: corpus profile mismatch")
    digest = expect_object(corpus.get("digest"), "completed run corpus.digest")
    require_exact_keys(digest, {"alg", "value"}, "completed run corpus.digest")
    require(digest == {"alg": "sha-256", "value": CORPUS_DIGEST}, "completed run: corpus digest mismatch")

    external_status = expect_object(run_result.get("external_run"), "run external_run").get("status")
    if external_status in {"partial", "blocked"}:
        validate_partial_or_blocked_bundle(
            run_result,
            index_path,
            manifest,
            source,
            selected_by_id,
            mapping_repo=mapping_repo,
            pulse_repo=pulse_repo,
            candidate_python_runtime=candidate_python_runtime,
            candidate_node_runtime=candidate_node_runtime,
            allow_self_test=allow_self_test,
        )
        return
    require(external_status == "completed", "run bundle status must be completed, partial, or blocked")
    require(mapping_repo is not None, "completed run requires --mapping-repo")
    require(pulse_repo is not None, "completed run requires --pulse-repo")

    implementation = expect_object(run_result.get("implementation"), "completed run implementation")
    require_exact_keys(
        implementation,
        {"name", "type", "version", "language", "source", "commit", "environment", "upstream_verifier"},
        "completed run implementation",
    )
    for field in ("name", "version", "language", "source", "commit", "environment"):
        expect_nonempty_string(implementation.get(field), f"completed run implementation.{field}")
    require(implementation.get("type") == "external-verifier-projection", "completed run implementation.type mismatch")
    environment = str(implementation.get("environment"))
    require(PULSE_COMMIT in environment and "candidate-owned" in environment, "completed run implementation environment lost verifier/mapping boundary")
    upstream = expect_object(implementation.get("upstream_verifier"), "completed run upstream_verifier")
    require_exact_keys(upstream, {"source", "commit", "entry_point"}, "completed run upstream_verifier")
    require(
        upstream
        == {
            "source": "https://github.com/shibutatsu/pulse-ap2-x402-conformance",
            "commit": PULSE_COMMIT,
            "entry_point": "src/verifier.ts#verifyConformanceCase",
        },
        "completed run frozen upstream verifier identity mismatch",
    )

    results = expect_array(run_result.get("results"), "completed run results")
    require(
        len(results) == 75,
        "completed run must contain three selected results and 72 explicit out-of-scope skipped entries",
    )
    completed_results = [
        validate_completed_result_entry(
            results[index],
            SELECTED_CASE_IDS[index],
            selected_by_id[SELECTED_CASE_IDS[index]],
            f"completed run results[{index}]",
        )
        for index in range(3)
    ]
    for offset, case_id in enumerate(out_of_scope_case_ids(source), start=3):
        validate_out_of_scope_result_entry(results[offset], case_id, f"completed run results[{offset}]")
    limitations = expect_array(run_result.get("limitations"), "completed run limitations")
    for index, limitation in enumerate(limitations):
        expect_nonempty_string(limitation, f"completed run limitations[{index}]")

    external = expect_object(run_result.get("external_run"), "completed run external_run")
    require_exact_keys(
        external,
        {
            "record_version",
            "status",
            "evidence_class",
            "vate_source_commit",
            "pulse_verifier_commit",
            "source_policy",
            "comparison_contract",
            "attempt",
            "starter_manifest",
            "mapping_source",
            "worksheet",
            "eligible_input_manifest",
            "generated_records",
            "candidate_execution",
            "case_runs",
        },
        "completed run external_run",
    )
    require(external.get("record_version") == RUN_RECORD_VERSION, "completed run record version mismatch")
    require(external.get("status") == "completed", "completed run status must be completed")
    expected_evidence_class = "validator-self-test" if allow_self_test else "candidate-executed"
    require(external.get("evidence_class") == expected_evidence_class, "completed run evidence class mismatch")
    require(external.get("vate_source_commit") == VATE_COMMIT, "completed run VATE pin mismatch")
    require(external.get("pulse_verifier_commit") == PULSE_COMMIT, "completed run Pulse pin mismatch")
    source_policy = expect_object(external.get("source_policy"), "completed run source_policy")
    expected_completed_source_policy = SELF_TEST_FIXTURE_SOURCE_POLICY if allow_self_test else EXPECTED_SOURCE_POLICY
    require(
        source_policy == expected_completed_source_policy,
        "completed run source policy must explicitly retain every negative boundary",
    )
    require(external.get("comparison_contract") == EXPECTED_COMPARISON_CONTRACT, "completed run comparison contract mismatch")

    bundle_root = index_path.parent
    validate_attempt_contract(external.get("attempt"), "completed", bundle_root, "completed run attempt")
    claimed_unique_paths: set[str] = set()

    def register_unique(path: str, label: str) -> None:
        require(path != index_path.name, f"{label}: run index cannot reference itself")
        require(path not in claimed_unique_paths, f"{label}: duplicate bundle path {path}")
        claimed_unique_paths.add(path)

    starter_path, starter_raw, _ = validate_bundle_ref(
        bundle_root,
        external.get("starter_manifest"),
        "completed run starter_manifest",
        expected_digest=sha256_bytes(read_regular_nonempty(MANIFEST_PATH)),
    )
    register_unique(starter_path, "completed run starter_manifest")
    copied_manifest = expect_object(parse_strict_json(starter_raw, f"bundle:{starter_path}"), "completed run copied starter manifest")
    require(copied_manifest == manifest, "completed run starter manifest copy differs from the validated starter")

    mapping_source = expect_object(external.get("mapping_source"), "completed run mapping_source")
    require_exact_keys(
        mapping_source,
        {
            "owner",
            "repository",
            "locator_verification",
            "commit",
            "repository_path",
            "entrypoint",
            "command",
            "bundle_path",
            "raw_sha256",
        },
        "completed run mapping_source",
    )
    require(mapping_source.get("owner") == "candidate_owned", "completed run mapping source owner mismatch")
    repository = expect_nonempty_string(mapping_source.get("repository"), "completed run mapping_source.repository")
    require("example.invalid" not in repository.lower(), "completed run mapping repository sentinel is prohibited")
    mapping_commit = expect_nonempty_string(mapping_source.get("commit"), "completed run mapping_source.commit")
    require(COMMIT_RE.fullmatch(mapping_commit) is not None, "completed run mapping commit must be exact lowercase 40- or 64-hex")
    validate_safe_repo_path(mapping_source.get("repository_path"), "completed run mapping_source.repository_path")
    mapping_path, mapping_raw, _ = validate_bundle_ref(
        bundle_root,
        {"path": mapping_source.get("bundle_path"), "raw_sha256": mapping_source.get("raw_sha256")},
        "completed run mapping_source.bundle_copy",
    )
    register_unique(mapping_path, "completed run mapping source")
    try:
        mapping_text = mapping_raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CheckFailure("completed run mapping source copy must be UTF-8") from exc
    scan_text_for_credentials(mapping_text, "completed run mapping source copy")
    candidate_command, candidate_runtime, candidate_export_contract = validate_mapping_checkout(
        mapping_repo,
        mapping_source,
        mapping_raw,
        selected_by_id,
        candidate_python_runtime=candidate_python_runtime,
        candidate_node_runtime=candidate_node_runtime,
        allow_self_test=allow_self_test,
    )
    require(implementation.get("source") == repository, "completed run implementation source must equal mapping repository")
    require(implementation.get("commit") == mapping_commit, "completed run implementation commit must equal mapping commit")

    worksheet_path, worksheet_raw, _ = validate_bundle_ref(
        bundle_root,
        external.get("worksheet"),
        "completed run worksheet",
    )
    register_unique(worksheet_path, "completed run worksheet")
    completed_worksheet = expect_object(
        parse_strict_json(worksheet_raw, f"bundle:{worksheet_path}"),
        "completed run worksheet",
    )
    scan_json_for_credentials(completed_worksheet, "completed run worksheet")
    validate_worksheet(completed_worksheet, selected_by_id, source=source, completed=True)

    eligible_path, eligible_raw, _ = validate_bundle_ref(
        bundle_root,
        external.get("eligible_input_manifest"),
        "completed run eligible_input_manifest",
    )
    register_unique(eligible_path, "completed run eligible input manifest")
    eligible_inputs = validate_eligible_input_manifest(
        parse_strict_json(eligible_raw, f"bundle:{eligible_path}"),
        bundle_root,
        selected_by_id,
        source,
        SELECTED_CASE_IDS,
        "completed run eligible input manifest",
    )
    generated_path, generated_raw, _ = validate_bundle_ref(
        bundle_root,
        external.get("generated_records"),
        "completed run generated_records",
    )
    register_unique(generated_path, "completed run generated records")
    generated_record_value = parse_strict_json(generated_raw, f"bundle:{generated_path}")

    case_runs = expect_array(external.get("case_runs"), "completed run case_runs")
    require(len(case_runs) == 3, "completed run must contain exactly three case runs")
    pulse_input_records: list[tuple[str, str, str]] = []
    pulse_input_values: list[dict[str, Any]] = []
    pulse_inputs_by_id: dict[str, tuple[str, str, dict[str, Any]]] = {}
    raw_output_refs: list[tuple[str, str]] = []
    projections: list[dict[str, Any]] = []
    vate_hashes: set[str] = set()
    critical_generated_values: dict[str, list[Any]] = {
        pointer: []
        for pointer in (
            "/ap2/closedMandate/transaction_id",
            "/ap2/verification/cryptographicEvidence/expectedNonce",
            "/ap2/verification/cryptographicEvidence/mandateChain",
            "/ap2/verification/cryptographicEvidence/paymentReceiptJwt",
            "/inputHash",
            "/x402/payload/payload/authorization/nonce",
            "/x402/payload/payload/signature",
        )
    }
    for index, raw_case_run in enumerate(case_runs):
        case_run = expect_object(raw_case_run, f"completed run case_runs[{index}]")
        require_exact_keys(
            case_run,
            {"case_id", "vate_input_closure_sha256", "vate_inputs", "pulse_input", "raw_report", "projection"},
            f"completed run case_runs[{index}]",
        )
        case_id = SELECTED_CASE_IDS[index]
        require(case_run.get("case_id") == case_id, f"completed run case index {index}: case ID mismatch")
        require(case_run.get("vate_input_closure_sha256") == EXPECTED_CLOSURE_DIGESTS[case_id], f"completed run {case_id}: closure digest mismatch")
        manifest_inputs = expect_array(selected_by_id[case_id]["inputs"], f"manifest inputs for {case_id}")
        vate_inputs = expect_array(case_run.get("vate_inputs"), f"completed run {case_id}.vate_inputs")
        require(len(vate_inputs) == 4, f"completed run {case_id}: four VATE input refs required")
        closure_entries: list[dict[str, str]] = []
        for input_index, (raw_ref, manifest_ref) in enumerate(zip(vate_inputs, manifest_inputs, strict=True)):
            ref = expect_object(raw_ref, f"completed run {case_id}.vate_inputs[{input_index}]")
            require_exact_keys(
                ref,
                {"role", "artifact_key", "source_path", "source_raw_sha256", "bundle_path", "bundle_raw_sha256"},
                f"completed run {case_id}.vate_inputs[{input_index}]",
            )
            require(ref.get("role") == manifest_ref["role"], f"completed run {case_id}: VATE input role mismatch")
            require(ref.get("artifact_key") == manifest_ref["artifact_key"], f"completed run {case_id}: VATE artifact key mismatch")
            source_path = validate_safe_repo_path(ref.get("source_path"), f"completed run {case_id}.source_path")
            require(source_path == manifest_ref["path"], f"completed run {case_id}: VATE source path mismatch")
            source_hash = validate_sha256(ref.get("source_raw_sha256"), f"completed run {case_id}.source_raw_sha256")
            require(source_hash == manifest_ref["raw_sha256"], f"completed run {case_id}: VATE source hash mismatch")
            local_path, local_raw, local_hash = validate_bundle_ref(
                bundle_root,
                {"path": ref.get("bundle_path"), "raw_sha256": ref.get("bundle_raw_sha256")},
                f"completed run {case_id}.vate_inputs[{input_index}].bundle_copy",
                expected_digest=source_hash,
            )
            register_unique(local_path, f"completed run {case_id} VATE input")
            require(local_raw == source.blobs[source_path], f"completed run {case_id}: copied VATE bytes differ from fixed Git object")
            parse_strict_json(local_raw, f"bundle:{local_path}")
            if ref.get("artifact_key") in {"admission_request", "ap2_mandate"}:
                require(
                    eligible_inputs[case_id][ref["artifact_key"]] == (local_path, local_hash),
                    f"completed run {case_id}: mapper-eligible input does not bind the case-run source copy",
                )
            vate_hashes.add(local_hash)
            closure_entries.append({"path": source_path, "sha256": source_hash})
        require(
            sha256_value(sorted(closure_entries, key=lambda item: item["path"])) == EXPECTED_CLOSURE_DIGESTS[case_id],
            f"completed run {case_id}: local VATE input closure digest mismatch",
        )

        pulse_path, pulse_raw, pulse_hash = validate_bundle_ref(
            bundle_root,
            case_run.get("pulse_input"),
            f"completed run {case_id}.pulse_input",
        )
        register_unique(pulse_path, f"completed run {case_id} Pulse input")
        require(pulse_hash not in vate_hashes, f"completed run {case_id}: Pulse input cannot be an unchanged VATE source artifact")
        pulse_value = parse_strict_json(pulse_raw, f"bundle:{pulse_path}")
        validate_completed_pulse_input(pulse_value, case_id, f"completed run {case_id}.pulse_input")
        for pointer, values in critical_generated_values.items():
            values.append(json_pointer_value(pulse_value, pointer, f"completed run {case_id}.pulse_input"))
        pulse_input_records.append((case_id, pulse_path, pulse_hash))
        pulse_input_object = expect_object(pulse_value, f"completed run {case_id}.pulse_input")
        pulse_input_values.append(pulse_input_object)
        pulse_inputs_by_id[case_id] = (pulse_path, pulse_hash, pulse_input_object)

        raw_report_ref = expect_object(case_run.get("raw_report"), f"completed run {case_id}.raw_report")
        require_exact_keys(raw_report_ref, {"path", "raw_sha256", "report_index"}, f"completed run {case_id}.raw_report")
        require(raw_report_ref.get("report_index") == index, f"completed run {case_id}: raw report index mismatch")
        raw_path, _, raw_hash = validate_bundle_ref(
            bundle_root,
            {"path": raw_report_ref.get("path"), "raw_sha256": raw_report_ref.get("raw_sha256")},
            f"completed run {case_id}.raw_report",
        )
        raw_output_refs.append((raw_path, raw_hash))

        projection = expect_object(case_run.get("projection"), f"completed run {case_id}.projection")
        require_exact_keys(
            projection,
            {
                "result_index",
                "source_document",
                "source_json_pointer",
                "observed_relation_to_vate",
                "pulse_outcome_class",
                "projected_vate_outcome",
                "projected_should_execute",
                "projected_reason_codes",
                "projected_checks",
            },
            f"completed run {case_id}.projection",
        )
        require(projection.get("result_index") == index, f"completed run {case_id}: projection result index mismatch")
        require(projection.get("source_document") == "raw_pulse_output", f"completed run {case_id}: projection source must be raw Pulse output")
        require(projection.get("source_json_pointer") == f"/reports/{index}", f"completed run {case_id}: projection report pointer mismatch")
        relation = projection.get("observed_relation_to_vate")
        require(relation in {"match", "mismatch", "partial", "unsupported"}, f"completed run {case_id}: invalid observed relation")
        outcome_class = projection.get("pulse_outcome_class")
        require(outcome_class in {"accept", "reject", "non-attenuate", "error", "unsupported"}, f"completed run {case_id}: invalid Pulse outcome class")
        projected_outcome = expect_nonempty_string(projection.get("projected_vate_outcome"), f"completed run {case_id}.projected_vate_outcome")
        projected_execute = projection.get("projected_should_execute")
        require(isinstance(projected_execute, bool), f"completed run {case_id}.projected_should_execute: expected boolean")
        projected_reasons = expect_array(projection.get("projected_reason_codes"), f"completed run {case_id}.projected_reason_codes")
        for reason_index, reason in enumerate(projected_reasons):
            expect_nonempty_string(reason, f"completed run {case_id}.projected_reason_codes[{reason_index}]")
        projected_checks = expect_array(projection.get("projected_checks"), f"completed run {case_id}.projected_checks")
        result_entry = completed_results[index]
        require(result_entry["outcome"] == projected_outcome, f"completed run {case_id}: projected outcome/result mismatch")
        require(result_entry["should_execute"] == projected_execute, f"completed run {case_id}: projected execution/result mismatch")
        require(result_entry["reason_codes"] == projected_reasons, f"completed run {case_id}: projected reasons/result mismatch")
        require(result_entry["checks"] == projected_checks, f"completed run {case_id}: projected checks/result mismatch")
        projections.append(projection)

    require(len({path for _, path, _ in pulse_input_records}) == 3, "completed run Pulse input paths must be one-to-one")
    require(len({digest for _, _, digest in pulse_input_records}) == 3, "completed run Pulse input bytes must differ across the three cases")
    require(
        not ({digest for _, _, digest in pulse_input_records} & vate_hashes),
        "completed run Pulse input cannot be byte-identical to any fixed VATE source artifact",
    )
    if not allow_self_test:
        for pointer, values in critical_generated_values.items():
            require(len({canonical_json_bytes(value) for value in values}) == 3, f"completed run critical generated value must be case-specific: {pointer}")
    require(len(set(raw_output_refs)) == 1, "completed run case records must bind to one identical raw Pulse output file/hash")
    raw_output_path, raw_output_hash = raw_output_refs[0]
    require(raw_output_path not in claimed_unique_paths, "completed run raw output path collides with another bundle artifact")
    raw_output_raw = read_bundle_file(bundle_root, raw_output_path, "completed run raw Pulse output")[1]
    require(sha256_bytes(raw_output_raw) == raw_output_hash, "completed run raw Pulse output hash changed during validation")
    raw_output = parse_strict_json(raw_output_raw, f"bundle:{raw_output_path}")
    reports = validate_raw_pulse_output(raw_output, pulse_input_records, "completed run raw Pulse output")
    validate_pulse_checkout(pulse_repo, manifest)
    replayed_reports, actual_runtime = replay_pulse_reports(pulse_repo, bundle_root, pulse_input_records)
    require(raw_output.get("runtime") == actual_runtime, "completed run recorded runtime does not match the replay environment")
    require(reports == replayed_reports, "completed run raw reports do not exactly match frozen Pulse replay")
    if not allow_self_test:
        fixture_cores = pulse_fixture_core_digests(pulse_repo)
        for case_id, pulse_input in zip(SELECTED_CASE_IDS, pulse_input_values, strict=True):
            require(
                pulse_input_core_digest(pulse_input) not in fixture_cores,
                f"completed run {case_id}: Pulse fixture core reuse is prohibited for candidate evidence",
            )

    map_output_binding = validate_candidate_execution_record(
        external.get("candidate_execution"),
        bundle_root,
        mapping_repo,
        mapping_commit,
        candidate_command,
        candidate_runtime,
        candidate_export_contract,
        eligible_inputs,
        pulse_inputs_by_id,
        reports,
        projections,
        SELECTED_CASE_IDS,
        completed_worksheet,
        allow_self_test=allow_self_test,
        label="completed run candidate execution",
    )
    validate_generated_records(
        generated_record_value,
        bundle_root,
        completed_worksheet,
        pulse_inputs_by_id,
        SELECTED_CASE_IDS,
        "completed run generated records",
        worksheet_raw_sha256=sha256_bytes(worksheet_raw),
        candidate_map_output=map_output_binding,
    )

    for index, (case_id, pulse_input, report, projection) in enumerate(
        zip(SELECTED_CASE_IDS, pulse_input_values, reports, projections, strict=True)
    ):
        computed_bindings = {
            "closedMandateClaimsHash": "/ap2/verification/closedMandateClaimsHash",
            "openMandateClaimsHash": "/ap2/verification/openMandateClaimsHash",
            "closedMandateReference": "/ap2/verification/closedMandateReference",
            "inputHash": "/inputHash",
            "expectedNonce": "/x402/payload/payload/authorization/nonce",
        }
        for computed_key, input_pointer in computed_bindings.items():
            require(
                report["computed"][computed_key]
                == json_pointer_value(pulse_input, input_pointer, f"completed run {case_id}.pulse_input"),
                f"completed run {case_id}: raw computed.{computed_key} is not bound to the Pulse input",
            )
        if "recoveredSigner" in report["computed"]:
            require(
                str(report["computed"]["recoveredSigner"]).lower()
                == str(json_pointer_value(pulse_input, "/x402/payload/payload/authorization/from", f"completed run {case_id}.pulse_input")).lower(),
                f"completed run {case_id}: recovered signer is not bound to the Pulse input payer",
            )
        require(
            all(failure["code"] != "INPUT_SCHEMA_INVALID" for failure in report["failures"]),
            f"completed run {case_id}: Pulse input schema failure cannot be claimed as a completed valid-input run",
        )
        outcome_class = projection["pulse_outcome_class"]
        if outcome_class == "accept":
            require(report["consistent"] is True and not report["failures"], f"completed run {case_id}: accept class contradicts raw report")
        if outcome_class in {"reject", "non-attenuate"}:
            require(report["consistent"] is False and bool(report["failures"]), f"completed run {case_id}: reject/non-attenuate class contradicts raw report")
        if case_id in MATCHED_SELECTED_RESULT_CONTRACTS:
            expected_match = MATCHED_SELECTED_RESULT_CONTRACTS[case_id]
            result_entry = completed_results[index]
            require(projection["observed_relation_to_vate"] == "match", f"completed run {case_id}: selected relation must be a match")
            require(result_entry["outcome"] == expected_match["outcome"], f"completed run {case_id}: compare outcome contract mismatch")
            require(result_entry["should_execute"] is expected_match["should_execute"], f"completed run {case_id}: compare execution contract mismatch")
            require(result_entry["reason_codes"] == expected_match["reason_codes"], f"completed run {case_id}: compare reason-code contract mismatch")
            checks_by_name = {check["name"]: check for check in result_entry["checks"]}
            require(
                expected_match["required_checks"].issubset(checks_by_name),
                f"completed run {case_id}: compare-required checks are missing",
            )
            require(
                all(checks_by_name[name]["pass"] is True for name in expected_match["required_checks"]),
                f"completed run {case_id}: compare-required check did not pass",
            )
        if case_id == "attenuate-ap2-hnp-amount-overrun":
            require(projection["observed_relation_to_vate"] == "mismatch", "amount-overrun must preserve an explicit VATE/Pulse mismatch")
            require(outcome_class in {"reject", "non-attenuate"}, "amount-overrun Pulse class must remain reject/non-attenuate")
            require(completed_results[index]["outcome"] != "attenuate", "amount-overrun must not normalize Pulse output to VATE attenuate")

    require_no_completion_sentinel(run_result, "completed run bundle index")


def validate_pulse_checkout(pulse_repo: Path, manifest: dict[str, Any]) -> None:
    require_commit(pulse_repo, PULSE_COMMIT, "Pulse verifier pin")
    head = run_git(pulse_repo, ["rev-parse", "HEAD"]).decode("ascii").strip()
    require(head == PULSE_COMMIT, "Pulse checkout HEAD is not the frozen verifier pin")
    tracked_status = run_git(pulse_repo, ["status", "--porcelain", "--untracked-files=no"])
    require(not tracked_status.strip(), "Pulse checkout has tracked changes; frozen verifier invocation is not assured")
    reviewed = {
        entry["path"]: entry["raw_sha256"]
        for entry in expect_array(at(manifest, "target", "reviewed_surface"), "Pulse reviewed surface")
    }
    for path, expected_digest in reviewed.items():
        committed = git_blob(pulse_repo, PULSE_COMMIT, path, f"Pulse frozen source {path}")
        require(sha256_bytes(committed) == expected_digest, f"Pulse committed raw hash mismatch: {path}")
        current_path = pulse_repo / path
        current = read_regular_nonempty(current_path)
        require(sha256_bytes(current) == expected_digest, f"Pulse working-tree raw hash mismatch: {path}")
    fixture_bundle = expect_object(
        parse_strict_json(
            read_regular_nonempty(pulse_repo / "fixtures" / "v0.3" / "cases.json"),
            "frozen Pulse fixtures/v0.3/cases.json",
        ),
        "frozen Pulse fixture bundle",
    )
    fixture_cases = expect_array(fixture_bundle.get("cases"), "frozen Pulse fixture cases")
    matching = [case for case in fixture_cases if isinstance(case, dict) and case.get("id") == PULSE_REFERENCE_CASE_ID]
    require(len(matching) == 1, "frozen Pulse reference case must occur exactly once")
    reference_case = expect_object(matching[0], "frozen Pulse reference case")
    paths = tuple(sorted(primitive_leaf_paths(reference_case)))
    require(paths == PULSE_PRIMITIVE_LEAF_PATHS, "frozen Pulse reference-case primitive leaf set mismatch")
    require(sha256_value(list(paths)) == PULSE_LEAF_PATH_DIGEST, "frozen Pulse reference-case leaf digest mismatch")
    containers = tuple(sorted(container_paths(reference_case)))
    require(containers == PULSE_CONTAINER_PATHS, "frozen Pulse reference-case container set mismatch")
    require(sha256_value(list(containers)) == PULSE_CONTAINER_PATH_DIGEST, "frozen Pulse reference-case container digest mismatch")
    for pointer in PULSE_REQUIRED_EMPTY_CONTAINERS:
        require(json_pointer_value(reference_case, pointer, "frozen Pulse required container") == [], f"frozen Pulse required empty container changed: {pointer}")


def candidate_commit_files(mapping_repo: Path, commit: str) -> tuple[tuple[CandidateCommitFile, ...], dict[str, Any]]:
    listing = run_git(mapping_repo, ["ls-tree", "-r", "-z", "--full-tree", commit])
    entries = [entry for entry in listing.split(b"\0") if entry]
    require(bool(entries), "candidate mapping commit export is empty")
    require(len(entries) <= CANDIDATE_EXPORT_MAX_FILES, "candidate mapping commit export exceeds the file-count limit")
    files: list[CandidateCommitFile] = []
    seen: set[str] = set()
    total_bytes = 0
    for index, entry in enumerate(entries):
        metadata, separator, raw_path = entry.partition(b"\t")
        require(separator == b"\t", f"candidate mapping commit entry[{index}] is malformed")
        try:
            mode, object_type, object_id = metadata.decode("ascii").split()
            path = raw_path.decode("utf-8", errors="strict")
        except (UnicodeDecodeError, ValueError) as exc:
            raise CheckFailure(f"candidate mapping commit entry[{index}] is not canonical UTF-8 Git metadata") from exc
        path = validate_safe_repo_path(path, f"candidate mapping commit entry[{index}].path")
        parts = PurePosixPath(path).parts
        require(path not in seen, "candidate mapping commit contains a duplicate path")
        require(
            not (set(parts) & CANDIDATE_FORBIDDEN_EXPORT_COMPONENTS),
            f"candidate mapping commit path uses a prohibited runtime/build directory: {path}",
        )
        require(
            PurePosixPath(path).suffix.lower() not in CANDIDATE_FORBIDDEN_EXPORT_SUFFIXES,
            f"candidate mapping commit path uses a prohibited compiled runtime artifact: {path}",
        )
        require(
            object_type == "blob" and mode in {"100644", "100755"},
            f"candidate mapping commit entry is not a tracked regular file: {path}",
        )
        raw = run_git(mapping_repo, ["cat-file", "blob", object_id])
        total_bytes += len(raw)
        require(total_bytes <= CANDIDATE_EXPORT_MAX_BYTES, "candidate mapping commit export exceeds the byte limit")
        seen.add(path)
        files.append(
            CandidateCommitFile(
                path=path,
                git_mode=mode,
                raw_sha256=sha256_bytes(raw),
                raw=raw,
            )
        )
    require([item.path for item in files] == sorted(item.path for item in files), "candidate mapping commit paths are not sorted")
    inventory = [
        {
            "path": item.path,
            "file_type": "regular",
            "git_mode": item.git_mode,
            "raw_sha256": item.raw_sha256,
            "size": len(item.raw),
        }
        for item in files
    ]
    contract = {
        "mode": "fresh-tracked-regular-commit-export-per-invocation",
        "working_tree_scope": "identity-and-cleanliness-check-only-never-executed",
        "file_count": len(files),
        "total_bytes": total_bytes,
        "file_inventory_sha256": sha256_value(inventory),
        "inventory_basis": "sorted canonical JSON [{path,file_type,git_mode,raw_sha256,size}]",
        "fresh_per_invocation": True,
        "regular_files_only": True,
        "live_checkout_executed": False,
        "external_packages_available": False,
        "runtime_network_allowed": False,
        "export_write_allowed": False,
    }
    return tuple(files), contract


def validate_python_dependency_policy(files: tuple[CandidateCommitFile, ...]) -> None:
    python_files = [item for item in files if PurePosixPath(item.path).suffix == ".py"]
    local_modules: set[str] = set()
    for item in python_files:
        pure = PurePosixPath(item.path)
        local_modules.add(pure.stem)
        local_modules.update(part for part in pure.parts[:-1] if part.isidentifier())
    stdlib_modules = set(getattr(sys, "stdlib_module_names", ()))
    for item in python_files:
        try:
            source_text = item.raw.decode("utf-8", errors="strict")
            tree = ast.parse(source_text, filename=item.path)
        except (UnicodeDecodeError, SyntaxError) as exc:
            raise CheckFailure(f"candidate tracked Python source is invalid UTF-8/Python: {item.path}") from exc
        for node in ast.walk(tree):
            imported: str | None = None
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported = alias.name.split(".", 1)[0]
                    require(imported not in PYTHON_FORBIDDEN_RUNTIME_MODULES, f"candidate Python source imports a prohibited runtime module: {item.path}")
                    require(imported in stdlib_modules or imported in local_modules, f"candidate Python source imports an external package: {item.path}")
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imported = node.module.split(".", 1)[0]
                require(imported not in PYTHON_FORBIDDEN_RUNTIME_MODULES, f"candidate Python source imports a prohibited runtime module: {item.path}")
                require(imported in stdlib_modules or imported in local_modules, f"candidate Python source imports an external package: {item.path}")
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                require(node.func.id not in {"__import__", "compile", "eval", "exec"}, f"candidate Python source uses prohibited dynamic code/import execution: {item.path}")
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                    method = node.func.attr
                    require(
                        method not in {"fork", "popen", "posix_spawn", "posix_spawnp", "system"}
                        and not method.startswith("exec")
                        and not method.startswith("spawn"),
                        f"candidate Python source uses prohibited child-process execution: {item.path}",
                    )


def validate_node_dependency_policy(files: tuple[CandidateCommitFile, ...]) -> None:
    source_suffixes = {".cjs", ".js", ".mjs"}
    tracked_paths = {item.path for item in files}
    for item in files:
        if PurePosixPath(item.path).suffix not in source_suffixes:
            continue
        try:
            source_text = item.raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise CheckFailure(f"candidate tracked Node source is not UTF-8: {item.path}") from exc
        dynamic_calls = re.finditer(r"\b(?:import|require)\s*\(\s*([^\s'\"])", source_text)
        require(next(dynamic_calls, None) is None, f"candidate Node source uses a non-literal dynamic import: {item.path}")
        specifiers: list[str] = []
        for pattern in (
            r"\b(?:import|export)\s+(?:[^;]*?\s+from\s+)?['\"]([^'\"]+)['\"]",
            r"\brequire\s*\(\s*['\"]([^'\"]+)['\"]\s*\)",
            r"\bimport\s*\(\s*['\"]([^'\"]+)['\"]\s*\)",
        ):
            specifiers.extend(match.group(1) for match in re.finditer(pattern, source_text))
        for specifier in specifiers:
            if specifier.startswith("node:"):
                builtin = specifier[5:].split("/", 1)[0]
                require(builtin not in NODE_FORBIDDEN_BUILTINS, f"candidate Node source imports a prohibited runtime builtin: {item.path}")
                continue
            require(specifier.startswith("./") or specifier.startswith("../"), f"candidate Node source imports an external package or non-node builtin: {item.path}")
            base = PurePosixPath(item.path).parent.as_posix()
            normalized = posixpath.normpath(posixpath.join(base, specifier))
            resolved = validate_safe_repo_path(normalized, f"candidate Node relative import in {item.path}")
            require(resolved in tracked_paths, f"candidate Node relative import is not an explicit tracked file: {item.path}")


def validate_candidate_dependency_policy(
    files: tuple[CandidateCommitFile, ...],
    launcher: str,
    entrypoint: str,
) -> None:
    paths = {item.path: item for item in files}
    require(entrypoint in paths, "candidate mapping entrypoint is absent from the commit export closure")
    require(bool(paths[entrypoint].raw), "candidate mapping entrypoint is zero-byte")
    suffix = PurePosixPath(entrypoint).suffix.lower()
    if launcher == "python3":
        require(suffix == ".py", "python3 candidate entrypoint must be tracked Python source")
        validate_python_dependency_policy(files)
    else:
        require(suffix in {".cjs", ".js", ".mjs"}, "node candidate entrypoint must be tracked JavaScript source")
        validate_node_dependency_policy(files)


def path_is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def runtime_path_type(mode: int) -> str:
    if stat.S_ISREG(mode):
        return "regular"
    if stat.S_ISLNK(mode):
        return "symlink"
    return "other"


def runtime_path_is_forbidden(path: Path) -> bool:
    return bool(set(path.parts) & CANDIDATE_FORBIDDEN_EXPORT_COMPONENTS) or any(
        part.startswith("vate-pulse-candidate-export-") for part in path.parts
    )


def inspect_candidate_runtime_identity(
    requested_runtime: Path,
    mapping_repo: Path,
    label: str,
) -> CandidateRuntimeIdentity:
    requested_text = str(requested_runtime)
    require(bool(requested_text) and "\x00" not in requested_text, f"{label}: runtime path is invalid")
    require(requested_runtime.is_absolute(), f"{label}: runtime path must be absolute")
    normalized_text = os.path.normpath(requested_text)
    require(normalized_text == requested_text, f"{label}: runtime path must be normalized")
    requested_path = Path(normalized_text)
    mapping_absolute = Path(os.path.abspath(str(mapping_repo)))
    try:
        mapping_real = mapping_repo.resolve(strict=True)
    except OSError as exc:
        raise CheckFailure(f"{label}: candidate mapping repository path is unavailable") from exc
    require(
        not path_is_within(requested_path, mapping_absolute),
        f"{label}: runtime path must not be inside the candidate mapping repository",
    )
    require(not runtime_path_is_forbidden(requested_path), f"{label}: runtime path uses a prohibited candidate/build directory")
    try:
        requested_stat = requested_path.lstat()
    except OSError as exc:
        raise CheckFailure(f"{label}: requested runtime path is missing or unreadable") from exc
    requested_type = runtime_path_type(requested_stat.st_mode)
    require(requested_type in {"regular", "symlink"}, f"{label}: requested runtime path must be a regular file or symlink")
    requested_link_target = os.readlink(requested_path) if requested_type == "symlink" else None
    try:
        realpath = requested_path.resolve(strict=True)
    except OSError as exc:
        raise CheckFailure(f"{label}: runtime realpath is missing or unreadable") from exc
    require(not path_is_within(realpath, mapping_real), f"{label}: runtime realpath must not be inside the candidate mapping repository")
    require(not runtime_path_is_forbidden(realpath), f"{label}: runtime realpath uses a prohibited candidate/build directory")

    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(realpath, flags)
    except OSError as exc:
        raise CheckFailure(f"{label}: runtime realpath cannot be opened as a regular file") from exc
    digest = hashlib.sha256()
    try:
        real_stat = os.fstat(descriptor)
        require(stat.S_ISREG(real_stat.st_mode), f"{label}: runtime realpath must be a regular file")
        require(bool(real_stat.st_mode & 0o111), f"{label}: runtime realpath is not executable")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(descriptor)
    try:
        post_hash_stat = realpath.lstat()
    except OSError as exc:
        raise CheckFailure(f"{label}: runtime realpath disappeared during hashing") from exc
    require(
        stat.S_ISREG(post_hash_stat.st_mode)
        and post_hash_stat.st_dev == real_stat.st_dev
        and post_hash_stat.st_ino == real_stat.st_ino
        and post_hash_stat.st_mode == real_stat.st_mode
        and post_hash_stat.st_size == real_stat.st_size,
        f"{label}: runtime realpath changed during hashing",
    )
    require(os.access(realpath, os.X_OK), f"{label}: runtime realpath is not executable by the operator")
    return CandidateRuntimeIdentity(
        requested_absolute_path=requested_text,
        requested_file_type=requested_type,
        requested_link_target=requested_link_target,
        requested_device=requested_stat.st_dev,
        requested_inode=requested_stat.st_ino,
        requested_mode=requested_stat.st_mode,
        requested_size=requested_stat.st_size,
        realpath=str(realpath),
        realpath_file_type="regular",
        realpath_device=real_stat.st_dev,
        realpath_inode=real_stat.st_ino,
        realpath_mode=real_stat.st_mode,
        realpath_size=real_stat.st_size,
        raw_sha256=digest.hexdigest(),
    )


def candidate_runtime_record(runtime: CandidateRuntime) -> dict[str, str]:
    identity = runtime.identity
    return {
        "logical_name": runtime.logical_name,
        "requested_absolute_path": identity.requested_absolute_path,
        "requested_file_type": identity.requested_file_type,
        "realpath": identity.realpath,
        "realpath_file_type": identity.realpath_file_type,
        "raw_sha256": identity.raw_sha256,
        "version": runtime.version,
    }


def verify_candidate_runtime_unchanged(
    runtime: CandidateRuntime,
    mapping_repo: Path,
    label: str,
) -> None:
    observed = inspect_candidate_runtime_identity(
        Path(runtime.identity.requested_absolute_path),
        mapping_repo,
        label,
    )
    require(observed == runtime.identity, f"{label}: candidate runtime path, realpath, type, or hash changed after preflight")


def preflight_candidate_runtime(
    logical_name: str,
    candidate_python_runtime: Path | None,
    candidate_node_runtime: Path | None,
    mapping_repo: Path,
    label: str,
) -> CandidateRuntime:
    require(logical_name in {"python3", "node"}, f"{label}: unsupported logical runtime")
    if logical_name == "python3":
        require(candidate_python_runtime is not None, f"{label}: python3 command requires --candidate-python-runtime")
        require(candidate_node_runtime is None, f"{label}: python3 command must not receive --candidate-node-runtime")
        requested_runtime = candidate_python_runtime
    else:
        require(candidate_node_runtime is not None, f"{label}: node command requires --candidate-node-runtime")
        require(candidate_python_runtime is None, f"{label}: node command must not receive --candidate-python-runtime")
        requested_runtime = candidate_node_runtime
    identity = inspect_candidate_runtime_identity(requested_runtime, mapping_repo, f"{label} preflight")
    with tempfile.TemporaryDirectory(prefix="vate-pulse-runtime-preflight-") as version_temp:
        version_root = Path(version_temp)
        (version_root / "home").mkdir()
        (version_root / "tmp").mkdir()
        returncode, stdout, stderr = run_bounded_process(
            [identity.realpath, "--version"],
            cwd=version_root,
            request_raw=b"\n",
            environment=candidate_subprocess_env(version_root),
            label=f"{label} version",
            timeout_seconds=10.0,
            stdout_limit=64 * 1024,
            stderr_limit=64 * 1024,
        )
    require(returncode == 0, f"{label}: candidate runtime version command failed")
    try:
        version_text = (stdout + stderr).decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise CheckFailure(f"{label}: candidate runtime version is not UTF-8") from exc
    expect_nonempty_string(version_text, f"{label} runtime version")
    if logical_name == "python3":
        require(version_text.startswith("Python "), f"{label}: selected Python runtime returned an unexpected version shape")
    else:
        require(re.fullmatch(r"v[0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z.-]+)?", version_text) is not None, f"{label}: selected Node runtime returned an unexpected version shape")
    runtime = CandidateRuntime(logical_name=logical_name, identity=identity, version=version_text)
    verify_candidate_runtime_unchanged(runtime, mapping_repo, f"{label} post-version preflight")
    return runtime


def validate_mapping_checkout(
    mapping_repo: Path,
    mapping_source: dict[str, Any],
    mapping_bundle_raw: bytes,
    selected_by_id: dict[str, dict[str, Any]],
    *,
    candidate_python_runtime: Path | None,
    candidate_node_runtime: Path | None,
    allow_self_test: bool,
) -> tuple[list[str], CandidateRuntime, dict[str, Any]]:
    require(mapping_repo.is_dir(), "candidate mapping repository directory is unavailable")
    inside = run_git(mapping_repo, ["rev-parse", "--is-inside-work-tree"]).decode("ascii").strip()
    require(inside == "true", "candidate mapping path is not a Git work tree")
    recorded_commit = expect_nonempty_string(mapping_source.get("commit"), "candidate mapping commit")
    require_commit(mapping_repo, recorded_commit, "candidate mapping commit")
    head = run_git(mapping_repo, ["rev-parse", "HEAD"]).decode("ascii").strip()
    require(head == recorded_commit, "candidate mapping repository HEAD does not equal the recorded commit")
    require_candidate_repo_clean(mapping_repo, "candidate mapping repository")

    repository = expect_nonempty_string(mapping_source.get("repository"), "candidate mapping self-reported repository locator")
    require(
        mapping_source.get("locator_verification") == "local-git-origin-only-no-remote-fetch",
        "candidate mapping repository locator verification boundary mismatch",
    )
    origin_result = subprocess.run(
        ["git", "-C", str(mapping_repo), "config", "--get", "remote.origin.url"],
        capture_output=True,
        check=False,
    )
    require(origin_result.returncode == 0, "candidate mapping repository must record remote.origin.url")
    origin = origin_result.stdout.decode("utf-8", errors="strict").strip()
    require(origin == repository, "candidate mapping repository origin does not equal the recorded self-reported locator")
    if not allow_self_test:
        require(".invalid" not in repository.lower(), "candidate mapping repository uses a self-test or placeholder origin")

    repository_path = validate_safe_repo_path(
        mapping_source.get("repository_path"),
        "candidate mapping repository path",
    )
    entrypoint = validate_safe_repo_path(mapping_source.get("entrypoint"), "candidate mapping executable entrypoint")
    require(entrypoint == repository_path, "candidate mapping entrypoint must equal the byte-copied repository path")
    raw_command = expect_array(mapping_source.get("command"), "candidate mapping executable command")
    command: list[str] = []
    for index, raw_argument in enumerate(raw_command):
        argument = expect_nonempty_string(raw_argument, f"candidate mapping executable command[{index}]")
        require("\x00" not in argument and len(argument) <= 512, "candidate mapping executable command contains an unsafe argument")
        command.append(argument)
    require(command[0] in {"python3", "node"}, "candidate mapping executable must use the standard python3 or node launcher")
    expected_command = (
        ["python3", "-I", "-S", "-B", entrypoint]
        if command[0] == "python3"
        else ["node", "--no-addons", "--no-global-search-paths", entrypoint]
    )
    require(command == expected_command, "candidate mapping executable command must use the exact isolated launcher flags and tracked entrypoint")
    tracked = subprocess.run(
        ["git", "-C", str(mapping_repo), "ls-files", "--error-unmatch", "--", repository_path],
        capture_output=True,
        check=False,
    )
    require(tracked.returncode == 0, "candidate mapping entry path is not tracked")
    committed_raw = git_blob(mapping_repo, recorded_commit, repository_path, "candidate mapping committed blob")
    require(committed_raw == mapping_bundle_raw, "candidate mapping bundle copy differs from the committed Git blob")
    working_path = mapping_repo / repository_path
    working_raw = read_regular_nonempty(working_path)
    require(working_raw == committed_raw, "candidate mapping working-tree bytes differ from the recorded commit")

    commit_files, export_contract = candidate_commit_files(mapping_repo, recorded_commit)
    validate_candidate_dependency_policy(commit_files, command[0], entrypoint)
    dynamic_forbidden = list(FORBIDDEN_MAPPING_SOURCE_TOKENS)
    for case_id in SELECTED_CASE_IDS:
        for raw_input in expect_array(selected_by_id[case_id]["inputs"], f"selected inputs for {case_id}"):
            if not isinstance(raw_input, dict):
                continue
            if raw_input.get("role") in {"case", "comparison-only"}:
                dynamic_forbidden.extend(
                    [str(raw_input.get("path", "")), str(raw_input.get("raw_sha256", ""))]
                )
    for item in commit_files:
        if PurePosixPath(item.path).suffix.lower() not in {".cjs", ".js", ".mjs", ".py"}:
            continue
        try:
            mapping_text = item.raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise CheckFailure(f"candidate mapping source must be UTF-8: {item.path}") from exc
        scan_text_for_credentials(mapping_text, f"candidate mapping committed source {item.path}")
        normalized = mapping_text.lower()
        for token in dynamic_forbidden:
            require(
                not token or token.lower() not in normalized,
                "candidate mapping source contains a prohibited expected/receipt/precomputed reference",
            )

    runtime = preflight_candidate_runtime(
        command[0],
        candidate_python_runtime,
        candidate_node_runtime,
        mapping_repo,
        "candidate mapping runtime",
    )
    return command, runtime, export_contract


def candidate_subprocess_env(sandbox_root: Path) -> dict[str, str]:
    """Return a deliberately small, non-secret environment for candidate code."""

    home = sandbox_root / "home"
    runtime_tmp = sandbox_root / "tmp"
    return {
        "PATH": "",
        "HOME": str(home),
        "TMPDIR": str(runtime_tmp),
        "TMP": str(runtime_tmp),
        "TEMP": str(runtime_tmp),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "NODE_ENV": "production",
    }


def require_candidate_repo_clean(mapping_repo: Path, label: str) -> None:
    clean_status = run_git(mapping_repo, ["status", "--porcelain"])
    require(
        not clean_status.strip(),
        f"{label} has tracked or untracked non-ignored changes",
    )


def execution_tree_snapshot(root: Path, label: str) -> tuple[tuple[Any, ...], ...]:
    require(root.is_dir(), f"{label}: execution root is unavailable")
    pending = [root]
    records: list[tuple[Any, ...]] = []
    while pending:
        path = pending.pop()
        try:
            mode = path.lstat().st_mode
        except OSError as exc:
            raise CheckFailure(f"{label}: execution path disappeared") from exc
        relative = "." if path == root else path.relative_to(root).as_posix()
        permissions = stat.S_IMODE(mode)
        if stat.S_ISDIR(mode):
            records.append((relative, "directory", permissions, None, None))
            try:
                children = sorted(path.iterdir(), key=lambda item: item.name, reverse=True)
            except OSError as exc:
                raise CheckFailure(f"{label}: execution directory is unreadable") from exc
            pending.extend(children)
        elif stat.S_ISREG(mode):
            try:
                raw = path.read_bytes()
            except OSError as exc:
                raise CheckFailure(f"{label}: execution file is unreadable") from exc
            records.append((relative, "regular", permissions, len(raw), sha256_bytes(raw)))
        else:
            raise CheckFailure(f"{label}: symlink or special file appeared in the execution tree")
    return tuple(sorted(records))


def materialize_candidate_export(
    sandbox_root: Path,
    files: tuple[CandidateCommitFile, ...],
) -> Path:
    export_root = sandbox_root / "export"
    export_root.mkdir()
    (sandbox_root / "home").mkdir()
    (sandbox_root / "tmp").mkdir()
    for item in files:
        destination = export_root / item.path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(item.raw)
        destination.chmod(0o555 if item.git_mode == "100755" else 0o444)
    return export_root


def terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    elif process.poll() is None:
        process.kill()


def run_bounded_process(
    command: list[str],
    *,
    cwd: Path,
    request_raw: bytes,
    environment: dict[str, str],
    label: str,
    timeout_seconds: float = CANDIDATE_EXECUTION_TIMEOUT_SECONDS,
    stdout_limit: int = CANDIDATE_STDOUT_MAX_BYTES,
    stderr_limit: int = CANDIDATE_STDERR_MAX_BYTES,
) -> tuple[int, bytes, bytes]:
    require(os.name == "posix", f"{label}: bounded candidate execution currently requires POSIX process groups")
    require(0 < timeout_seconds <= CANDIDATE_EXECUTION_TIMEOUT_SECONDS, f"{label}: invalid execution timeout")
    require(bool(request_raw) and len(request_raw) <= CANDIDATE_STDOUT_MAX_BYTES, f"{label}: invalid or oversized stdin")
    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        env=environment,
        start_new_session=True,
    )
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    for stream in (process.stdin, process.stdout, process.stderr):
        os.set_blocking(stream.fileno(), False)
    selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    stdin_offset = 0
    stdout = bytearray()
    stderr = bytearray()
    deadline = time.monotonic() + timeout_seconds
    exit_observed_at: float | None = None
    failure: str | None = None
    try:
        while selector.get_map():
            now = time.monotonic()
            if now >= deadline:
                failure = "candidate executable timed out"
                break
            returncode = process.poll()
            if returncode is not None and exit_observed_at is None:
                exit_observed_at = now
            if exit_observed_at is not None and now - exit_observed_at > 0.25:
                failure = "candidate descendant retained an output pipe after the entrypoint exited"
                break
            events = selector.select(min(0.05, max(0.0, deadline - now)))
            for key, _ in events:
                stream = key.fileobj
                kind = key.data
                if kind == "stdin":
                    try:
                        written = os.write(stream.fileno(), request_raw[stdin_offset : stdin_offset + 65536])
                    except BrokenPipeError:
                        written = 0
                        stdin_offset = len(request_raw)
                    stdin_offset += written
                    if stdin_offset >= len(request_raw):
                        selector.unregister(stream)
                        stream.close()
                    continue
                try:
                    chunk = os.read(stream.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                destination = stdout if kind == "stdout" else stderr
                limit = stdout_limit if kind == "stdout" else stderr_limit
                if len(destination) + len(chunk) > limit:
                    failure = f"candidate {kind} exceeded its byte limit"
                    break
                destination.extend(chunk)
            if failure is not None:
                break
        if failure is None and process.poll() is None:
            remaining = max(0.0, deadline - time.monotonic())
            try:
                process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                failure = "candidate executable timed out"
    finally:
        terminate_process_group(process)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        selector.close()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()
    if failure is not None:
        raise CheckFailure(f"{label}: {failure}")
    return process.returncode, bytes(stdout), bytes(stderr)


def run_candidate_executable(
    mapping_repo: Path,
    mapping_commit: str,
    command: list[str],
    runtime: CandidateRuntime,
    request_raw: bytes,
    label: str,
    *,
    expected_export_contract: dict[str, Any] | None = None,
    timeout_seconds: float = CANDIDATE_EXECUTION_TIMEOUT_SECONDS,
    stdout_limit: int = CANDIDATE_STDOUT_MAX_BYTES,
    stderr_limit: int = CANDIDATE_STDERR_MAX_BYTES,
) -> bytes:
    require(bool(request_raw), f"{label}: zero-byte request is prohibited")
    require(runtime.logical_name == command[0], f"{label}: selected runtime does not match the logical command")
    files, export_contract = candidate_commit_files(mapping_repo, mapping_commit)
    if expected_export_contract is not None:
        require(export_contract == expected_export_contract, f"{label}: candidate commit export closure changed")
    validate_candidate_dependency_policy(files, command[0], command[-1])
    process_error: CheckFailure | None = None
    returncode = -1
    stdout = b""
    stderr = b""
    with tempfile.TemporaryDirectory(prefix="vate-pulse-candidate-export-") as export_temp:
        sandbox_root = Path(export_temp)
        export_root = materialize_candidate_export(sandbox_root, files)
        before = execution_tree_snapshot(sandbox_root, f"{label} pre-execution export")
        verify_candidate_runtime_unchanged(runtime, mapping_repo, f"{label} immediately before execution")
        actual_command = [runtime.identity.realpath, *command[1:]]
        try:
            returncode, stdout, stderr = run_bounded_process(
                actual_command,
                cwd=export_root,
                request_raw=request_raw,
                environment=candidate_subprocess_env(sandbox_root),
                label=label,
                timeout_seconds=timeout_seconds,
                stdout_limit=stdout_limit,
                stderr_limit=stderr_limit,
            )
        except CheckFailure as exc:
            process_error = exc
        verify_candidate_runtime_unchanged(runtime, mapping_repo, f"{label} immediately after execution")
        after = execution_tree_snapshot(sandbox_root, f"{label} post-execution export")
        require(before == after, f"{label}: candidate modified the fresh commit-export execution tree")
    if process_error is not None:
        raise process_error
    require(returncode == 0, f"{label}: candidate executable failed")
    require(not stderr, f"{label}: candidate executable wrote to stderr")
    require(bool(stdout), f"{label}: candidate executable returned zero bytes")
    parse_strict_json(stdout, f"{label} stdout")
    return stdout


def pulse_runtime(pulse_repo: Path) -> dict[str, str]:
    def command_version(command: list[str], label: str) -> str:
        completed = subprocess.run(command, cwd=pulse_repo, capture_output=True, check=False, timeout=30)
        require(completed.returncode == 0, f"unable to read {label} version from the Pulse execution environment")
        return completed.stdout.decode("utf-8", errors="strict").strip()

    package = expect_object(
        parse_strict_json(read_regular_nonempty(pulse_repo / "package.json"), "frozen Pulse package.json"),
        "frozen Pulse package.json",
    )
    version = expect_nonempty_string(package.get("version"), "frozen Pulse package version")
    return {
        "nodeVersion": command_version(["node", "--version"], "Node.js"),
        "npmVersion": command_version(["npm", "--version"], "npm"),
        "pulsePackageVersion": version,
    }


def pulse_fixture_core_digests(pulse_repo: Path) -> set[str]:
    bundle = expect_object(
        parse_strict_json(
            read_regular_nonempty(pulse_repo / "fixtures" / "v0.3" / "cases.json"),
            "frozen Pulse fixture bundle for core-reuse check",
        ),
        "frozen Pulse fixture bundle for core-reuse check",
    )
    digests: set[str] = set()
    for raw_case in expect_array(bundle.get("cases"), "frozen Pulse fixture cases for core-reuse check"):
        case = copy.deepcopy(expect_object(raw_case, "frozen Pulse fixture case for core-reuse check"))
        for key in ("id", "description", "expected"):
            case.pop(key, None)
        digests.add(sha256_value(case))
    return digests


def pulse_input_core_digest(pulse_input: dict[str, Any]) -> str:
    core = copy.deepcopy(pulse_input)
    for key in ("id", "description", "expected"):
        core.pop(key, None)
    return sha256_value(core)


def replay_pulse_reports(
    pulse_repo: Path,
    bundle_root: Path,
    pulse_inputs: list[tuple[str, str, str]],
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    absolute_inputs: list[str] = []
    for case_id, relative_path, expected_hash in pulse_inputs:
        path = bundle_root / relative_path
        raw = read_regular_nonempty(path)
        require(sha256_bytes(raw) == expected_hash, f"Pulse replay input changed before invocation: {case_id}")
        absolute_inputs.append(str(path))
    command = [
        "node",
        "--import",
        "tsx",
        "--input-type=module",
        "--eval",
        PULSE_REPLAY_SCRIPT,
        "--",
        *absolute_inputs,
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=pulse_repo,
            capture_output=True,
            check=False,
            timeout=60,
            env=os.environ.copy(),
        )
    except subprocess.TimeoutExpired as exc:
        raise CheckFailure("frozen Pulse verifier replay timed out") from exc
    require(completed.returncode == 0, "frozen Pulse verifyConformanceCase replay failed")
    try:
        decoded = completed.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise CheckFailure("frozen Pulse replay output is not UTF-8") from exc
    reports_value = parse_strict_json(decoded.encode("utf-8"), "frozen Pulse replay output")
    reports = expect_array(reports_value, "frozen Pulse replay output")
    require(len(reports) == len(pulse_inputs), "frozen Pulse replay report cardinality mismatch")
    validated: list[dict[str, Any]] = []
    for index, ((case_id, relative_path, expected_hash), raw_report) in enumerate(
        zip(pulse_inputs, reports, strict=True)
    ):
        path = bundle_root / relative_path
        require(
            sha256_bytes(read_regular_nonempty(path)) == expected_hash,
            f"Pulse replay input changed after invocation: {case_id}",
        )
        validated.append(
            validate_raw_pulse_report(raw_report, expected_pulse_case_id(case_id), f"replayed Pulse report[{index}]")
        )
    return validated, pulse_runtime(pulse_repo)


def validate_kit_file_set() -> dict[str, bytes]:
    try:
        entries = list(KIT_ROOT.iterdir())
    except OSError as exc:
        raise CheckFailure(f"starter kit directory is missing or unreadable: {KIT_ROOT}") from exc
    names = {entry.name for entry in entries}
    require(names == EXPECTED_KIT_FILES, f"starter kit file set mismatch: expected {sorted(EXPECTED_KIT_FILES)}, got {sorted(names)}")
    raw_files: dict[str, bytes] = {}
    for name in sorted(EXPECTED_KIT_FILES):
        raw = read_regular_nonempty(KIT_ROOT / name)
        raw_files[name] = raw
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CheckFailure(f"public starter file must be UTF-8: {name}") from exc
        scan_text_for_credentials(text, f"starter file {name}")
    return raw_files


def validate_all(
    source_repo: Path,
    pulse_repo: Path | None,
    strict_json_paths: list[Path],
    *,
    archive_safe: bool = False,
) -> tuple[dict[str, Any], SourceSnapshot, dict[str, dict[str, Any]]]:
    raw_files = validate_kit_file_set()
    manifest = expect_object(parse_strict_json(raw_files["manifest.json"], str(MANIFEST_PATH)), "starter manifest")
    worksheet = expect_object(parse_strict_json(raw_files["mapping-worksheet.template.json"], str(WORKSHEET_PATH)), "mapping worksheet")
    result = expect_object(parse_strict_json(raw_files["pulse-sut-result.template.json"], str(RESULT_TEMPLATE_PATH)), "result template")
    for label, value in (("starter manifest", manifest), ("mapping worksheet", worksheet), ("result template", result)):
        scan_json_for_credentials(value, label)
    source = (
        load_archive_source_snapshot(source_repo, manifest)
        if archive_safe
        else load_source_snapshot(source_repo)
    )
    selected_by_id = validate_manifest(manifest, source)
    validate_worksheet(worksheet, selected_by_id, source=source)
    validate_result_template(result, selected_by_id)
    if pulse_repo is not None:
        validate_pulse_checkout(pulse_repo, manifest)
    for path in strict_json_paths:
        value = parse_strict_json(read_regular_nonempty(path), str(path))
        scan_json_for_credentials(value, str(path))
    return manifest, source, selected_by_id


def expect_failure(label: str, operation: Callable[[], None], required_text: str | None = None) -> None:
    try:
        operation()
    except CheckFailure as exc:
        if required_text is not None and required_text not in str(exc):
            raise CheckFailure(f"self-test {label}: wrong failure: {exc}") from exc
        return
    raise CheckFailure(f"self-test {label}: invalid input unexpectedly passed")


def write_self_test_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def set_json_pointer_value(root: dict[str, Any], pointer: str, value: Any) -> None:
    parts = pointer[1:].split("/")
    current: Any = root
    for index, raw_part in enumerate(parts):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        last = index == len(parts) - 1
        next_is_index = not last and parts[index + 1].isdigit()
        if isinstance(current, dict):
            if last:
                current[part] = value
            else:
                current = current.setdefault(part, [] if next_is_index else {})
        elif isinstance(current, list):
            require(part.isdigit(), f"self-test pointer builder: invalid array index in {pointer}")
            array_index = int(part)
            while len(current) <= array_index:
                current.append(None)
            if last:
                current[array_index] = value
            else:
                if current[array_index] is None:
                    current[array_index] = [] if next_is_index else {}
                current = current[array_index]
        else:
            raise CheckFailure(f"self-test pointer builder: primitive traversal in {pointer}")


def synthetic_pulse_leaf_value(path: str) -> Any:
    fixed: dict[str, Any] = {
        "/caseVersion": "ap2-x402-conformance/0.3",
        "/sourcePins/ap2Commit": "e1ea56db72a6385bce3e5c1112b3a56ce60acb43",
        "/sourcePins/x402Commit": "17d319fab5c17a6b4873eb41197894db924f59ed",
        "/sourcePins/x402PackageVersion": "2.23.0",
        "/expected/consistent": True,
        "/ap2/closedMandate/vct": "mandate.payment.1",
        "/ap2/openMandate/vct": "mandate.payment.open.1",
        "/ap2/openMandate/constraints/0/type": "payment.reference",
        "/ap2/openMandate/constraints/1/type": "payment.allowed_payment_instruments",
        "/ap2/openMandate/constraints/1/allowed/0/type": "x402",
        "/ap2/openMandate/constraints/2/type": "payment.amount_range",
        "/ap2/openMandate/constraints/3/type": "payment.allowed_payees",
        "/ap2/closedMandate/payment_instrument/type": "x402",
        "/ap2/closedMandate/payment_instrument/x402/version": 2,
        "/ap2/closedMandate/payment_instrument/x402/scheme": "exact",
        "/ap2/closedMandate/payment_instrument/x402/nonceBinding": "base64url-decode-ap2-mandate-reference",
        "/x402/payload/x402Version": 2,
        "/x402/requirements/scheme": "exact",
        "/x402/payload/accepted/scheme": "exact",
        "/x402/requirements/extra/assetTransferMethod": "eip3009",
        "/x402/payload/accepted/extra/assetTransferMethod": "eip3009",
        "/x402/requirements/extra/ap2NonceDerivation": "base64url-decode-ap2-mandate-reference",
        "/x402/payload/accepted/extra/ap2NonceDerivation": "base64url-decode-ap2-mandate-reference",
        "/ap2/paymentReceipt/error": None,
        "/ap2/paymentReceipt/error_description": None,
        "/ap2/paymentReceipt/status": "Success",
        "/x402/settlement/success": True,
    }
    if path in fixed:
        return fixed[path]
    if path.endswith("/alg"):
        return "ES256"
    if path.endswith("/crv"):
        return "P-256"
    if path.endswith("/kty"):
        return "EC"
    if path.endswith("/currency"):
        return "USD"
    if path.endswith("/network"):
        return "eip155:31337"
    if path.endswith("/asset"):
        return "0x" + "1" * 40
    if path.endswith("/payer") or path.endswith("/from"):
        return "0x" + "2" * 40
    if path.endswith("/payTo") or path.endswith("/to"):
        return "0x" + "3" * 40
    if path.endswith("/nonce") and "/authorization/" in path:
        return "0x" + "4" * 64
    if path.endswith("/signature"):
        return "0x" + "5" * 130
    if path.endswith("/x") or path.endswith("/y"):
        return "A" * 43
    if path.endswith("/website") or path.endswith("/url"):
        return "https://synthetic.invalid/resource"
    if path.endswith("/transaction") or path.endswith("network_confirmation_id"):
        return "0x" + "6" * 64
    if path in {
        "/ap2/closedMandate/payment_amount/amount",
        "/ap2/closedMandate/payment_instrument/x402/ap2PaymentAmount/amount",
        "/ap2/openMandate/constraints/1/allowed/0/x402/ap2PaymentAmount/amount",
        "/ap2/openMandate/constraints/2/max",
        "/ap2/openMandate/constraints/2/min",
        "/ap2/closedMandate/iat",
        "/ap2/closedMandate/exp",
        "/ap2/openMandate/iat",
        "/ap2/openMandate/exp",
        "/ap2/paymentReceipt/iat",
        "/ap2/verification/verifiedAtEpochSeconds",
        "/ap2/verification/clockSkewSeconds",
        "/nowEpochSeconds",
        "/ap2/closedMandate/payment_instrument/x402/maxTimeoutSeconds",
        "/ap2/openMandate/constraints/1/allowed/0/x402/maxTimeoutSeconds",
        "/x402/requirements/maxTimeoutSeconds",
        "/x402/payload/accepted/maxTimeoutSeconds",
    }:
        return 1
    if path.endswith("/amount") or path.endswith("/value") or path.endswith("/validAfter") or path.endswith("/validBefore"):
        return "1"
    if path in {
        "/ap2/closedMandate/transaction_id",
        "/ap2/openMandate/constraints/0/conditional_transaction_id",
        "/ap2/paymentReceipt/reference",
        "/ap2/verification/closedMandateClaimsHash",
        "/ap2/verification/closedMandateReference",
        "/ap2/verification/openCheckoutReference",
        "/ap2/verification/openMandateClaimsHash",
        "/inputHash",
        "/x402/requirements/extra/ap2MandateReference",
        "/x402/payload/accepted/extra/ap2MandateReference",
    }:
        return "B" * 43
    if path.endswith("execution_date"):
        return "2026-08-28T00:00:00Z"
    return "synthetic-value"


def build_synthetic_pulse_input(case_id: str) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for path in PULSE_PRIMITIVE_LEAF_PATHS:
        set_json_pointer_value(value, path, synthetic_pulse_leaf_value(path))
    set_json_pointer_value(value, "/expected/failureCodes", [])
    value["id"] = expected_pulse_case_id(case_id)
    value["description"] = f"Synthetic validator fixture for {case_id}."
    digest = hashlib.sha256(case_id.encode("utf-8")).hexdigest()
    checkout_reference = digest[:43]
    mandate_reference = digest[::-1][:43]
    for pointer in (
        "/ap2/closedMandate/transaction_id",
        "/ap2/openMandate/constraints/0/conditional_transaction_id",
        "/ap2/verification/openCheckoutReference",
    ):
        set_json_pointer_value(value, pointer, checkout_reference)
    for pointer in (
        "/ap2/paymentReceipt/reference",
        "/ap2/verification/closedMandateReference",
        "/x402/requirements/extra/ap2MandateReference",
        "/x402/payload/accepted/extra/ap2MandateReference",
    ):
        set_json_pointer_value(value, pointer, mandate_reference)
    set_json_pointer_value(value, "/ap2/verification/cryptographicEvidence/expectedNonce", f"nonce-{case_id}")
    set_json_pointer_value(value, "/ap2/verification/cryptographicEvidence/mandateChain", f"synthetic-chain-{case_id}")
    set_json_pointer_value(value, "/ap2/verification/cryptographicEvidence/paymentReceiptJwt", f"synthetic-receipt-jwt-{case_id}")
    set_json_pointer_value(value, "/inputHash", digest[:43])
    set_json_pointer_value(value, "/x402/payload/payload/authorization/nonce", "0x" + digest)
    set_json_pointer_value(value, "/x402/payload/payload/signature", "0x" + (digest * 3)[:130])
    return value


def completed_self_test_worksheet(template: dict[str, Any]) -> dict[str, Any]:
    worksheet = copy.deepcopy(template)
    worksheet["status"] = "completed"
    worksheet["ownership"]["instructions"] = "Candidate completed and pinned every mapping, generation, and projection decision."
    open_sections = (
        "asset_profile",
        "evm_participants",
        "merchant_profile",
        "instrument_profile",
        "x402_profile",
        "ap2_generation_profile",
        "resource_profile",
        "settlement_profile",
        "fixture_key_handling",
    )
    address_fields = {"asset", "payer", "pay_to"}
    integer_fields = {"decimals", "max_timeout_seconds", "clock_skew_seconds"}
    for section_name in open_sections:
        section = worksheet["scaffolding_inputs"][section_name]
        section["ownership"] = "candidate_owned"
        section["status"] = "completed"
        for key, item in list(section.items()):
            if item is not None:
                continue
            if key == "network":
                section[key] = "eip155:31337"
            elif key in address_fields:
                section[key] = "0x" + "7" * 40
            elif key in integer_fields:
                section[key] = 6 if key == "decimals" else 0 if key == "clock_skew_seconds" else 300
            elif key == "success":
                section[key] = True
            else:
                section[key] = "synthetic-resolved"
    worksheet["scaffolding_inputs"]["asset_profile"]["usd_to_asset_conversion"]["asset_units_per_usd"] = "1"
    for row in worksheet["mapping_rows"]:
        row["ownership"] = "candidate_owned"
        row["transform"] = row["transform"].replace("open_mapping_decision:", "Candidate resolved:")
    for leaf in worksheet["generated_field_inventory"]:
        leaf["ownership"] = "candidate_owned"
        leaf["transform"] = leaf["transform"].replace("open_mapping_decision:", "Candidate resolved:")
    inventory_by_destination = {
        leaf["pulse_destination"]: leaf for leaf in worksheet["generated_field_inventory"]
    }
    execution_date = inventory_by_destination["/ap2/closedMandate/execution_date"]
    execution_date.update(
        {
            "source_document": "vate_admission_request",
            "source_json_pointer": "/issued_at",
            "dependencies": ["mapping_row:evaluation-time"],
            "transform": "Copy the exact VATE admission request issued_at timestamp.",
            "provenance": "vate-derived",
        }
    )
    for destination in (
        "/ap2/closedMandate/payee/name",
        "/ap2/closedMandate/payee/website",
        "/ap2/openMandate/constraints/3/allowed/0/name",
        "/ap2/openMandate/constraints/3/allowed/0/website",
    ):
        inventory_by_destination[destination].update(
            {
                "transform": "Use fixed candidate-owned merchant display metadata.",
                "provenance": "non-vate-scaffolding",
            }
        )
    worksheet["completion_requirements"] = [
        item.replace("open_mapping_decision", "candidate decision")
        for item in worksheet["completion_requirements"]
    ]
    return worksheet


def create_self_test_mapping_repo(
    repository_root: Path,
    pulse_input_raw_by_work_item: dict[str, str],
    projection_by_work_item: dict[str, dict[str, Any]],
) -> tuple[Path, str, str]:
    mapping_repo = repository_root / "mapping-repo"
    mapping_path = mapping_repo / "src" / "mapper.py"
    fixture_path = mapping_repo / "src" / "self_test_fixtures.json"
    mapping_path.parent.mkdir(parents=True, exist_ok=True)
    mapping_path.write_text(
        "import json\n"
        "import pathlib\n"
        "import sys\n"
        "\n"
        "request = json.load(sys.stdin)\n"
        "data = json.loads((pathlib.Path(__file__).parent / 'self_test_fixtures.json').read_text())\n"
        "operation = request['operation']\n"
        "items = []\n"
        "for item in request['items']:\n"
        "    work_item = item['workItemId']\n"
        "    if operation == 'map':\n"
        "        items.append({'workItemId': work_item, 'pulseInputRaw': data['pulseInputs'][work_item]})\n"
        "    elif operation == 'project':\n"
        "        items.append({'workItemId': work_item, 'projection': data['projections'][work_item]})\n"
        "    else:\n"
        "        raise SystemExit(2)\n"
        "json.dump({'interfaceVersion': request['interfaceVersion'], 'operation': operation, 'items': items}, sys.stdout, sort_keys=True, separators=(',', ':'))\n",
        encoding="utf-8",
    )
    write_self_test_json(
        fixture_path,
        {"pulseInputs": pulse_input_raw_by_work_item, "projections": projection_by_work_item},
    )
    commands = (
        ["git", "init", "--quiet", str(mapping_repo)],
        ["git", "-C", str(mapping_repo), "config", "user.name", "VATE validator self-test"],
        ["git", "-C", str(mapping_repo), "config", "user.email", "validator-self-test@example.invalid"],
        ["git", "-C", str(mapping_repo), "add", "src/mapper.py", "src/self_test_fixtures.json"],
        ["git", "-C", str(mapping_repo), "commit", "--quiet", "-m", "validator self-test mapper"],
        [
            "git",
            "-C",
            str(mapping_repo),
            "remote",
            "add",
            "origin",
            "https://validator-self-test.invalid/mapping.git",
        ],
    )
    for command in commands:
        subprocess.run(command, check=True, capture_output=True)
    commit = run_git(mapping_repo, ["rev-parse", "HEAD"]).decode("ascii").strip()
    return mapping_repo, commit, "https://validator-self-test.invalid/mapping.git"


def commit_self_test_repository(mapping_repo: Path, tracked_paths: list[str], message: str) -> str:
    commands = (
        ["git", "init", "--quiet", str(mapping_repo)],
        ["git", "-C", str(mapping_repo), "config", "user.name", "VATE validator self-test"],
        ["git", "-C", str(mapping_repo), "config", "user.email", "validator-self-test@example.invalid"],
        ["git", "-C", str(mapping_repo), "add", *tracked_paths],
        ["git", "-C", str(mapping_repo), "commit", "--quiet", "-m", message],
    )
    for command in commands:
        subprocess.run(command, check=True, capture_output=True)
    return run_git(mapping_repo, ["rev-parse", "HEAD"]).decode("ascii").strip()


def sensitivity_self_test_mapper_source() -> str:
    return (
        "import base64\n"
        "import copy\n"
        "import datetime\n"
        "import decimal\n"
        "import hashlib\n"
        "import json\n"
        "import pathlib\n"
        "import sys\n"
        "\n"
        "def epoch(value):\n"
        "    return int(datetime.datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc).timestamp())\n"
        "\n"
        "request = json.load(sys.stdin)\n"
        "fixtures = json.loads((pathlib.Path(__file__).parent / 'fixtures.json').read_text())\n"
        "items = []\n"
        "for item in request['items']:\n"
        "    work_item = item['workItemId']\n"
        "    admission = item['eligibleInput']['admissionRequest']\n"
        "    mandate = item['eligibleInput']['ap2Mandate']\n"
        "    value = copy.deepcopy(fixtures[work_item])\n"
        "    requested = decimal.Decimal(admission['constraints']['max_amount']['value'])\n"
        "    limit = decimal.Decimal(mandate['constraints']['max_amount']['value'])\n"
        "    permitted = min(requested, limit)\n"
        "    request_minor = int(requested * 100)\n"
        "    limit_minor = int(limit * 100)\n"
        "    permitted_minor = int(permitted * 100)\n"
        "    requested_atomic = str(int(requested * 1000000))\n"
        "    permitted_atomic = str(int(permitted * 1000000))\n"
        "    merchant = mandate['merchant']\n"
        "    evaluation = epoch(admission['issued_at'])\n"
        "    request_expiry = epoch(admission['expires_at'])\n"
        "    mandate_iat = epoch(mandate['issued_at'])\n"
        "    mandate_expiry = epoch(mandate['expires_at'])\n"
        "    window_start = epoch(mandate['constraints']['execution_window']['not_before'])\n"
        "    window_end = epoch(mandate['constraints']['execution_window']['not_after'])\n"
        "    closed_expiry = min(request_expiry, mandate_expiry, window_end)\n"
        "    valid_before = min(request_expiry, mandate_expiry, window_end, evaluation + 300)\n"
        "    replay_nonce = mandate['constraints']['replay_nonce']\n"
        "    reference_bytes = hashlib.sha256(replay_nonce.encode('utf-8')).digest()\n"
        "    reference = base64.urlsafe_b64encode(reference_bytes).rstrip(b'=').decode('ascii')\n"
        "    value['nowEpochSeconds'] = evaluation\n"
        "    value['ap2']['verification']['verifiedAtEpochSeconds'] = evaluation\n"
        "    value['ap2']['paymentReceipt']['iat'] = evaluation\n"
        "    value['ap2']['closedMandate']['execution_date'] = admission['issued_at']\n"
        "    value['ap2']['closedMandate']['iat'] = evaluation\n"
        "    value['ap2']['closedMandate']['exp'] = closed_expiry\n"
        "    value['ap2']['openMandate']['iat'] = mandate_iat\n"
        "    value['ap2']['openMandate']['exp'] = min(mandate_expiry, window_end)\n"
        "    value['x402']['payload']['payload']['authorization']['validAfter'] = str(window_start)\n"
        "    value['x402']['payload']['payload']['authorization']['validBefore'] = str(valid_before)\n"
        "    value['ap2']['verification']['cryptographicEvidence']['expectedNonce'] = replay_nonce\n"
        "    value['ap2']['verification']['closedMandateReference'] = reference\n"
        "    value['x402']['payload']['payload']['authorization']['nonce'] = '0x' + reference_bytes.hex()\n"
        "    value['ap2']['closedMandate']['payee']['id'] = merchant\n"
        "    value['ap2']['closedMandate']['payment_instrument']['x402']['ap2PayeeId'] = merchant\n"
        "    value['ap2']['openMandate']['constraints'][1]['allowed'][0]['x402']['ap2PayeeId'] = merchant\n"
        "    value['ap2']['openMandate']['constraints'][3]['allowed'][0]['id'] = merchant\n"
        "    value['ap2']['closedMandate']['payment_amount'] = {'amount': permitted_minor, 'currency': 'USD'}\n"
        "    value['ap2']['closedMandate']['payment_instrument']['x402']['ap2PaymentAmount'] = {'amount': permitted_minor, 'currency': 'USD'}\n"
        "    value['ap2']['openMandate']['constraints'][1]['allowed'][0]['x402']['ap2PaymentAmount'] = {'amount': permitted_minor, 'currency': 'USD'}\n"
        "    value['ap2']['openMandate']['constraints'][2]['max'] = limit_minor\n"
        "    value['ap2']['openMandate']['constraints'][2]['currency'] = 'USD'\n"
        "    value['ap2']['closedMandate']['payment_instrument']['x402']['amount'] = permitted_atomic\n"
        "    value['ap2']['openMandate']['constraints'][1]['allowed'][0]['x402']['amount'] = permitted_atomic\n"
        "    value['x402']['requirements']['amount'] = requested_atomic\n"
        "    value['x402']['payload']['accepted']['amount'] = requested_atomic\n"
        "    value['x402']['payload']['payload']['authorization']['value'] = requested_atomic\n"
        "    raw = json.dumps(value, sort_keys=True, separators=(',', ':'))\n"
        "    items.append({'workItemId': work_item, 'pulseInputRaw': raw})\n"
        "json.dump({'interfaceVersion': request['interfaceVersion'], 'operation': 'map', 'items': items}, sys.stdout, sort_keys=True, separators=(',', ':'))\n"
    )


def self_test_result_spec(case_id: str) -> dict[str, Any]:
    if case_id == "allow-ap2-hnp-preauthorized-mandate":
        checks = [
            {"name": name, "pass": True, "details": "Validator self-test projection record."}
            for name in sorted(MATCHED_SELECTED_RESULT_CONTRACTS[case_id]["required_checks"])
        ]
        return {
            "outcome": "allow",
            "should_execute": True,
            "reason_codes": ["EVIDENCE_VERIFIED", "POLICY_MATCH"],
            "checks": checks,
            "relation": "match",
            "outcome_class": "accept",
        }
    if case_id == "attenuate-ap2-hnp-amount-overrun":
        return {
            "outcome": "deny",
            "should_execute": False,
            "reason_codes": ["AP2_X402_AMOUNT_MISMATCH"],
            "checks": [],
            "relation": "mismatch",
            "outcome_class": "non-attenuate",
        }
    checks = [
        {"name": name, "pass": True, "details": "Validator self-test projection record."}
        for name in sorted(MATCHED_SELECTED_RESULT_CONTRACTS[case_id]["required_checks"])
    ]
    return {
        "outcome": "deny",
        "should_execute": False,
        "reason_codes": ["PERMIT_EXPIRED", "FAIL_CLOSED"],
        "checks": checks,
        "relation": "match",
        "outcome_class": "reject",
    }


def out_of_scope_result_entries(source: SourceSnapshot) -> list[dict[str, Any]]:
    return [
        {
            "case_id": case_id,
            "status": "skipped",
            "outcome": "out-of-scope",
            "should_execute": False,
            "reason_codes": ["OUT_OF_SCOPE"],
            "limitations": ["Outside the bounded three-case Pulse attempt; no SUT outcome is claimed."],
        }
        for case_id in out_of_scope_case_ids(source)
    ]


def load_self_test_pulse_input(pulse_repo: Path, fixture_case_id: str, case_id: str) -> dict[str, Any]:
    bundle = expect_object(
        parse_strict_json(
            read_regular_nonempty(pulse_repo / "fixtures" / "v0.3" / "cases.json"),
            "self-test frozen Pulse fixture bundle",
        ),
        "self-test frozen Pulse fixture bundle",
    )
    matches = [
        case
        for case in expect_array(bundle.get("cases"), "self-test frozen Pulse fixture cases")
        if isinstance(case, dict) and case.get("id") == fixture_case_id
    ]
    require(len(matches) == 1, "self-test Pulse fixture selector mismatch")
    value = copy.deepcopy(matches[0])
    value["id"] = expected_pulse_case_id(case_id)
    value["description"] = "VATE-authored validator self-test input; never candidate evidence."
    value["expected"] = {"consistent": True, "failureCodes": []}
    return value


def synthetic_report_for_input(case_id: str, pulse_input_value: dict[str, Any], consistent: bool) -> dict[str, Any]:
    failures = [] if consistent else [
        {
            "code": "AP2_X402_AMOUNT_MISMATCH",
            "path": "ap2.closedMandate.payment_instrument.x402.amount",
            "message": "Validator self-test failure record.",
        }
    ]
    return {
        "caseId": expected_pulse_case_id(case_id),
        "consistent": consistent,
        "computed": {
            "closedMandateClaimsHash": json_pointer_value(pulse_input_value, "/ap2/verification/closedMandateClaimsHash", "synthetic Pulse input"),
            "openMandateClaimsHash": json_pointer_value(pulse_input_value, "/ap2/verification/openMandateClaimsHash", "synthetic Pulse input"),
            "closedMandateReference": json_pointer_value(pulse_input_value, "/ap2/verification/closedMandateReference", "synthetic Pulse input"),
            "inputHash": json_pointer_value(pulse_input_value, "/inputHash", "synthetic Pulse input"),
            "expectedNonce": json_pointer_value(pulse_input_value, "/x402/payload/payload/authorization/nonce", "synthetic Pulse input"),
        },
        "failures": failures,
    }


def build_eligible_input_record(
    bundle_root: Path,
    completed_case_ids: tuple[str, ...],
    external: dict[str, Any],
) -> dict[str, Any]:
    cases: list[dict[str, Any]] = []
    for case_id in completed_case_ids:
        case_run = external["case_runs"][SELECTED_CASE_IDS.index(case_id)]
        eligible = []
        for ref in case_run["vate_inputs"]:
            if ref["artifact_key"] not in {"admission_request", "ap2_mandate"}:
                continue
            eligible.append(
                {
                    "artifactKey": ref["artifact_key"],
                    "sourcePath": ref["source_path"],
                    "sourceRawSha256": ref["source_raw_sha256"],
                    "bundlePath": ref["bundle_path"],
                    "bundleRawSha256": ref["bundle_raw_sha256"],
                }
            )
        cases.append({"caseId": case_id, "inputs": eligible})
    return {
        "recordVersion": ELIGIBLE_INPUT_VERSION,
        "vateSourceCommit": VATE_COMMIT,
        "corpusDigest": CORPUS_DIGEST,
        "excludedSourceClasses": [
            "vate-case-expected",
            "vate-admission-receipt",
            "vate-post-execution-receipt",
        ],
        "cases": cases,
    }


def build_generated_record(
    completed_case_ids: tuple[str, ...],
    completed_worksheet: dict[str, Any],
    pulse_values: dict[str, tuple[str, str, dict[str, Any]]],
    *,
    worksheet_raw_sha256: str,
    candidate_map_output: tuple[str, str],
) -> dict[str, Any]:
    inventory = completed_worksheet["generated_field_inventory"]
    cases: list[dict[str, Any]] = []
    for case_id in completed_case_ids:
        pulse_path, pulse_hash, pulse_value = pulse_values[case_id]
        leaves = []
        generator_destinations: dict[str, list[str]] = {generator: [] for generator in sorted(GENERATOR_IDS)}
        for worksheet_leaf in inventory:
            destination = worksheet_leaf["pulse_destination"]
            value_digest = sha256_value(json_pointer_value(pulse_value, destination, "self-test generated record"))
            leaves.append(
                {
                    "pulseDestination": destination,
                    "valueSha256": value_digest,
                    "sourceDocument": worksheet_leaf["source_document"],
                    "sourceJsonPointer": worksheet_leaf["source_json_pointer"],
                    "dependencies": worksheet_leaf["dependencies"],
                    "provenance": worksheet_leaf["provenance"],
                    "ownership": "candidate_owned",
                }
            )
            for dependency in worksheet_leaf["dependencies"]:
                if dependency.startswith("generator:"):
                    generator_destinations[dependency.split(":", 1)[1]].append(destination)
        generators = []
        for generator_id in sorted(GENERATOR_IDS):
            destinations = generator_destinations[generator_id]
            generators.append(
                {
                    "recordId": f"generator:{generator_id}",
                    "kind": generator_id,
                    "pulseDestinations": destinations,
                    "valueDigests": [
                        {
                            "pulseDestination": destination,
                            "valueSha256": sha256_value(
                                json_pointer_value(pulse_value, destination, "self-test generator record")
                            ),
                        }
                        for destination in destinations
                    ],
                    "publicMaterialOnly": True,
                }
            )
        cases.append(
            {
                "caseId": case_id,
                "pulseInputPath": pulse_path,
                "pulseInputRawSha256": pulse_hash,
                "leaves": leaves,
                "generatorRecords": generators,
            }
        )
    return {
        "recordVersion": GENERATED_RECORD_VERSION,
        "machineCoverageScope": MACHINE_COVERAGE_SCOPE,
        "privateMaterialRecorded": False,
        "worksheetRawSha256": worksheet_raw_sha256,
        "candidateMapOutputPath": candidate_map_output[0],
        "candidateMapOutputRawSha256": candidate_map_output[1],
        "cases": cases,
    }


def build_synthetic_run_bundle(
    bundle_root: Path,
    manifest: dict[str, Any],
    worksheet_template: dict[str, Any],
    result_template: dict[str, Any],
    source: SourceSnapshot,
    *,
    status: str,
    completed_count: int,
    pulse_repo: Path | None,
    candidate_python_runtime: Path | None,
) -> tuple[Path, Path]:
    require(status in {"completed", "partial", "blocked"}, "self-test status is unsupported")
    if status == "completed":
        require(completed_count == 3 and pulse_repo is not None, "completed self-test requires frozen Pulse replay")
    if status == "partial":
        require(1 <= completed_count <= 2, "partial self-test case count mismatch")
    if status == "blocked":
        require(0 <= completed_count <= 2, "blocked self-test case count mismatch")
    completed_case_ids = SELECTED_CASE_IDS[:completed_count]
    incomplete_case_ids = SELECTED_CASE_IDS[completed_count:]
    if completed_case_ids:
        require(pulse_repo is not None, "self-test completed-case evidence requires frozen Pulse replay")
        require(candidate_python_runtime is not None, "self-test completed-case evidence requires an explicit Python runtime")

    fixture_ids = (
        "valid-base-sepolia-01",
        "invalid-ap2-x402-amount-mismatch-01",
        "invalid-eip3009-valid-before-expired-01",
    )
    prebuilt_pulse_values: dict[str, dict[str, Any]] = {}
    pulse_raw_by_work_item: dict[str, str] = {}
    projection_by_work_item: dict[str, dict[str, Any]] = {}
    if completed_case_ids:
        assert pulse_repo is not None
        for case_id in completed_case_ids:
            index = SELECTED_CASE_IDS.index(case_id)
            pulse_value = load_self_test_pulse_input(pulse_repo, fixture_ids[index], case_id)
            prebuilt_pulse_values[case_id] = pulse_value
            work_item = CANDIDATE_WORK_ITEM_IDS[index]
            pulse_raw_by_work_item[work_item] = canonical_json_bytes(pulse_value).decode("utf-8")
            projection_by_work_item[work_item] = projection_semantic_value(
                {
                    "observed_relation_to_vate": self_test_result_spec(case_id)["relation"],
                    "pulse_outcome_class": self_test_result_spec(case_id)["outcome_class"],
                    "projected_vate_outcome": self_test_result_spec(case_id)["outcome"],
                    "projected_should_execute": self_test_result_spec(case_id)["should_execute"],
                    "projected_reason_codes": self_test_result_spec(case_id)["reason_codes"],
                    "projected_checks": self_test_result_spec(case_id)["checks"],
                }
            )

    bundle_root.mkdir(parents=True, exist_ok=True)
    starter_path = bundle_root / "starter-manifest.json"
    starter_path.write_bytes(read_regular_nonempty(MANIFEST_PATH))
    mapping_repo = bundle_root.parent / f"{bundle_root.name}-repo" / "mapping-repo"
    mapping_commit = ""
    mapping_origin = ""
    mapping_path: Path | None = None
    if completed_case_ids:
        mapping_repo, mapping_commit, mapping_origin = create_self_test_mapping_repo(
            bundle_root.parent / f"{bundle_root.name}-repo",
            pulse_raw_by_work_item,
            projection_by_work_item,
        )
        mapping_repo_path = mapping_repo / "src" / "mapper.py"
        mapping_path = bundle_root / "mapping" / "mapper.py"
        mapping_path.parent.mkdir(parents=True, exist_ok=True)
        mapping_path.write_bytes(read_regular_nonempty(mapping_repo_path))
    completed_worksheet = completed_self_test_worksheet(worksheet_template)
    worksheet_path = bundle_root / "mapping-worksheet.json"
    write_self_test_json(worksheet_path, completed_worksheet)

    result = copy.deepcopy(result_template)
    result["generated_at"] = "2026-08-28T00:00:00Z"
    result["implementation"].update(
        {
            "type": "external-verifier-projection" if status == "completed" else f"external-verifier-projection-{status}",
            "version": "validator-self-test-2",
            "source": mapping_origin,
            "commit": mapping_commit,
            "environment": f"Non-elevatable validator self-test of candidate-owned mapping mechanics using frozen Pulse {PULSE_COMMIT}",
        }
    )
    external = result["external_run"]
    external["status"] = status
    external["evidence_class"] = "validator-self-test"
    external["source_policy"] = SELF_TEST_FIXTURE_SOURCE_POLICY if completed_case_ids else EXPECTED_SOURCE_POLICY
    external["starter_manifest"] = {
        "path": starter_path.relative_to(bundle_root).as_posix(),
        "raw_sha256": sha256_bytes(starter_path.read_bytes()),
    }
    if completed_case_ids:
        assert mapping_path is not None
        external["mapping_source"] = {
            "owner": "candidate_owned",
            "repository": mapping_origin,
            "locator_verification": "local-git-origin-only-no-remote-fetch",
            "commit": mapping_commit,
            "repository_path": "src/mapper.py",
            "entrypoint": "src/mapper.py",
            "command": ["python3", "-I", "-S", "-B", "src/mapper.py"],
            "bundle_path": mapping_path.relative_to(bundle_root).as_posix(),
            "raw_sha256": sha256_bytes(mapping_path.read_bytes()),
        }
    external["worksheet"] = {
        "path": worksheet_path.relative_to(bundle_root).as_posix(),
        "raw_sha256": sha256_bytes(worksheet_path.read_bytes()),
    }

    pulse_input_records: list[tuple[str, str, str]] = []
    pulse_values: dict[str, tuple[str, str, dict[str, Any]]] = {}
    for index, case_id in enumerate(SELECTED_CASE_IDS):
        case_run = external["case_runs"][index]
        if case_id not in completed_case_ids:
            result["results"][index]["limitations"] = ["Attempt did not complete this selected case."]
            continue
        for input_index, manifest_ref in enumerate(manifest["cases"][index]["inputs"]):
            source_path = manifest_ref["path"]
            local_path = bundle_root / "vate-inputs" / case_id / f"{manifest_ref['artifact_key']}.json"
            local_path.parent.mkdir(parents=True, exist_ok=True)
            local_path.write_bytes(source.blobs[source_path])
            case_run["vate_inputs"][input_index]["bundle_path"] = local_path.relative_to(bundle_root).as_posix()
            case_run["vate_inputs"][input_index]["bundle_raw_sha256"] = sha256_bytes(local_path.read_bytes())
        pulse_value = prebuilt_pulse_values[case_id]
        pulse_path = bundle_root / "pulse-inputs" / f"{case_id}.pulse-input.json"
        pulse_path.parent.mkdir(parents=True, exist_ok=True)
        pulse_path.write_bytes(canonical_json_bytes(pulse_value))
        pulse_relative = pulse_path.relative_to(bundle_root).as_posix()
        pulse_hash = sha256_bytes(pulse_path.read_bytes())
        case_run["pulse_input"] = {"path": pulse_relative, "raw_sha256": pulse_hash}
        pulse_input_records.append((case_id, pulse_relative, pulse_hash))
        pulse_values[case_id] = (pulse_relative, pulse_hash, pulse_value)
        spec = self_test_result_spec(case_id)
        result["results"][index] = {
            "case_id": case_id,
            "status": "completed",
            "outcome": spec["outcome"],
            "should_execute": spec["should_execute"],
            "reason_codes": spec["reason_codes"],
            "checks": spec["checks"],
            "artifacts": expected_comparison_artifact_ref(manifest["cases"][index]),
            "limitations": ["VATE-authored validator self-test only; never candidate evidence."],
        }
        report_index = len(pulse_input_records) - 1
        case_run["projection"] = {
            "result_index": index,
            "source_document": "raw_pulse_output",
            "source_json_pointer": f"/reports/{report_index}",
            "observed_relation_to_vate": spec["relation"],
            "pulse_outcome_class": spec["outcome_class"],
            "projected_vate_outcome": spec["outcome"],
            "projected_should_execute": spec["should_execute"],
            "projected_reason_codes": spec["reason_codes"],
            "projected_checks": spec["checks"],
        }

    result["results"].extend(out_of_scope_result_entries(source))
    eligible_path = bundle_root / "eligible-input-manifest.json"
    write_self_test_json(eligible_path, build_eligible_input_record(bundle_root, completed_case_ids, external))
    external["eligible_input_manifest"] = {
        "path": eligible_path.relative_to(bundle_root).as_posix(),
        "raw_sha256": sha256_bytes(eligible_path.read_bytes()),
    }
    if pulse_input_records:
        assert pulse_repo is not None
        reports, runtime = replay_pulse_reports(pulse_repo, bundle_root, pulse_input_records)
        raw_output = {
            "recordVersion": RAW_OUTPUT_VERSION,
            "pulseVerifierCommit": PULSE_COMMIT,
            "runtime": runtime,
            "execution": {
                "workingDirectory": "$PULSE_REPO",
                "entryPoint": "src/verifier.ts#verifyConformanceCase",
                "driverSha256": PULSE_REPLAY_SCRIPT_SHA256,
                "command": [
                    "node",
                    "--import",
                    "tsx",
                    "--input-type=module",
                    "--eval",
                    PULSE_REPLAY_SCRIPT,
                    "--",
                    *[f"$RUN_DIR/{path}" for _, path, _ in pulse_input_records],
                ],
            },
            "inputs": [
                {
                    "vateCaseId": case_id,
                    "pulseCaseId": expected_pulse_case_id(case_id),
                    "path": input_path,
                    "rawSha256Before": input_hash,
                    "rawSha256After": input_hash,
                }
                for case_id, input_path, input_hash in pulse_input_records
            ],
            "reports": reports,
        }
        raw_output_path = bundle_root / "raw-pulse-output.json"
        write_self_test_json(raw_output_path, raw_output)
        raw_relative = raw_output_path.relative_to(bundle_root).as_posix()
        raw_hash = sha256_bytes(raw_output_path.read_bytes())
        for report_index, case_id in enumerate(completed_case_ids):
            case_run = external["case_runs"][SELECTED_CASE_IDS.index(case_id)]
            case_run["raw_report"] = {
                "path": raw_relative,
                "raw_sha256": raw_hash,
                "report_index": report_index,
            }

        documents: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
        for case_id in completed_case_ids:
            selected_case = manifest["cases"][SELECTED_CASE_IDS.index(case_id)]
            refs = {entry["artifact_key"]: entry for entry in selected_case["inputs"]}
            documents[case_id] = (
                expect_object(parse_strict_json(source.blobs[refs["admission_request"]["path"]], "self-test admission request"), "self-test admission request"),
                expect_object(parse_strict_json(source.blobs[refs["ap2_mandate"]["path"]], "self-test AP2 mandate"), "self-test AP2 mandate"),
            )
        assert mapping_path is not None
        candidate_command, candidate_runtime, candidate_export_contract = validate_mapping_checkout(
            mapping_repo,
            expect_object(external["mapping_source"], "self-test mapping source"),
            mapping_path.read_bytes(),
            {case["case_id"]: case for case in manifest["cases"]},
            candidate_python_runtime=candidate_python_runtime,
            candidate_node_runtime=None,
            allow_self_test=True,
        )
        candidate_dir = bundle_root / "candidate-execution"
        candidate_dir.mkdir(parents=True, exist_ok=True)
        map_request_path = candidate_dir / "map-request.json"
        map_request_path.write_bytes(canonical_json_bytes(candidate_map_request_value(documents, completed_case_ids)))
        map_output_path = candidate_dir / "map-output.json"
        map_output_path.write_bytes(
            run_candidate_executable(
                mapping_repo,
                mapping_commit,
                candidate_command,
                candidate_runtime,
                map_request_path.read_bytes(),
                "self-test candidate map",
                expected_export_contract=candidate_export_contract,
            )
        )
        projection_request_path = candidate_dir / "projection-request.json"
        projection_request_path.write_bytes(
            canonical_json_bytes(candidate_projection_request_value(documents, completed_case_ids, reports))
        )
        projection_output_path = candidate_dir / "projection-output.json"
        projection_output_path.write_bytes(
            run_candidate_executable(
                mapping_repo,
                mapping_commit,
                candidate_command,
                candidate_runtime,
                projection_request_path.read_bytes(),
                "self-test candidate projection",
                expected_export_contract=candidate_export_contract,
            )
        )

        def self_test_ref(path: Path) -> dict[str, str]:
            return {
                "path": path.relative_to(bundle_root).as_posix(),
                "raw_sha256": sha256_bytes(path.read_bytes()),
            }

        external["candidate_execution"] = {
            "interface_version": CANDIDATE_INTERFACE_VERSION,
            "command": candidate_command,
            "runtime": candidate_runtime_record(candidate_runtime),
            "commit_export": candidate_export_contract,
            "map_request": self_test_ref(map_request_path),
            "map_output": self_test_ref(map_output_path),
            "projection_request": self_test_ref(projection_request_path),
            "projection_output": self_test_ref(projection_output_path),
            "sensitivity_contract": {
                "probe_dimensions": ["amount", "merchant", "evaluation_time", "replay_nonce"],
                "randomized_per_validation": True,
                "independent_recomputation": True,
                "tamper_proof_claim": False,
            },
        }
        generated_path = bundle_root / "generated-records.json"
        map_output_ref = external["candidate_execution"]["map_output"]
        write_self_test_json(
            generated_path,
            build_generated_record(
                completed_case_ids,
                completed_worksheet,
                pulse_values,
                worksheet_raw_sha256=sha256_bytes(worksheet_path.read_bytes()),
                candidate_map_output=(map_output_ref["path"], map_output_ref["raw_sha256"]),
            ),
        )
        external["generated_records"] = self_test_ref(generated_path)
        verify_candidate_runtime_unchanged(candidate_runtime, mapping_repo, "self-test bundle after all candidate executions")
    else:
        blocker_path = bundle_root / "blocker-record.json"
        write_self_test_json(
            blocker_path,
            {"stage": "pulse-install", "reasonCode": "ENVIRONMENT_BLOCKER", "details": "Validator self-test blocker."},
        )

    evidence: list[dict[str, Any]] = [
        {
            "case_id": None,
            "kind": "starter-manifest",
            "path": external["starter_manifest"]["path"],
            "raw_sha256": external["starter_manifest"]["raw_sha256"],
        }
    ]
    if completed_case_ids:
        for kind, ref in (
            ("mapping-source", {"path": external["mapping_source"]["bundle_path"], "raw_sha256": external["mapping_source"]["raw_sha256"]}),
            ("worksheet", external["worksheet"]),
            ("eligible-input-manifest", external["eligible_input_manifest"]),
            ("generated-records", external["generated_records"]),
            ("candidate-map-request", external["candidate_execution"]["map_request"]),
            ("candidate-map-output", external["candidate_execution"]["map_output"]),
            ("candidate-projection-request", external["candidate_execution"]["projection_request"]),
            ("candidate-projection-output", external["candidate_execution"]["projection_output"]),
        ):
            evidence.append({"case_id": None, "kind": kind, **ref})
        for case_id in completed_case_ids:
            case_run = external["case_runs"][SELECTED_CASE_IDS.index(case_id)]
            evidence.append({"case_id": case_id, "kind": "pulse-input", **case_run["pulse_input"]})
            evidence.append(
                {
                    "case_id": case_id,
                    "kind": "raw-pulse-output",
                    "path": case_run["raw_report"]["path"],
                    "raw_sha256": case_run["raw_report"]["raw_sha256"],
                }
            )
    else:
        blocker_path = bundle_root / "blocker-record.json"
        evidence.append(
            {
                "case_id": None,
                "kind": "blocker-record",
                "path": blocker_path.relative_to(bundle_root).as_posix(),
                "raw_sha256": sha256_bytes(blocker_path.read_bytes()),
            }
        )
        external["mapping_source"] = {
            "owner": "candidate_owned",
            "repository": None,
            "locator_verification": "local-git-origin-only-no-remote-fetch",
            "commit": None,
            "repository_path": None,
            "entrypoint": None,
            "command": None,
            "bundle_path": None,
            "raw_sha256": None,
        }
        external["worksheet"] = {"path": None, "raw_sha256": None}
        external["eligible_input_manifest"] = {"path": None, "raw_sha256": None}
        external["generated_records"] = {"path": None, "raw_sha256": None}
        result["implementation"].update({"source": "not-available", "commit": "not-available"})

    external["attempt"] = {
        "stage": "complete" if status == "completed" else "pulse-replay" if status == "partial" else "pulse-install",
        "reason_code": "COMPLETED" if status == "completed" else "TIMEBOX_REACHED" if status == "partial" else "ENVIRONMENT_BLOCKER",
        "details": "All three validator self-test cases replayed." if status == "completed" else "Validator self-test bounded attempt stopped honestly.",
        "completed_case_ids": list(completed_case_ids),
        "incomplete_case_ids": list(incomplete_case_ids),
        "evidence": evidence,
    }
    result["limitations"] = [
        "VATE-authored validator self-test only; evidence_class prevents candidate-evidence elevation.",
        "The amount-overrun Pulse rejection remains an explicit mismatch against VATE attenuation.",
    ]
    result_path = bundle_root / "pulse-sut-result.json"
    write_self_test_json(result_path, result)
    return result_path, mapping_repo


def run_self_tests(
    source_repo: Path,
    pulse_repo: Path | None,
    candidate_python_runtime: Path | None,
    candidate_node_runtime: Path | None,
) -> None:
    raw_files = validate_kit_file_set()
    manifest = expect_object(parse_strict_json(raw_files["manifest.json"], "self-test manifest"), "self-test manifest")
    worksheet = expect_object(parse_strict_json(raw_files["mapping-worksheet.template.json"], "self-test worksheet"), "self-test worksheet")
    result = expect_object(parse_strict_json(raw_files["pulse-sut-result.template.json"], "self-test result"), "self-test result")
    source = load_source_snapshot(source_repo)
    selected = validate_manifest(manifest, source)
    validate_worksheet(worksheet, selected, source=source)
    validate_result_template(result, selected)

    if pulse_repo is None:
        require(
            candidate_python_runtime is None and candidate_node_runtime is None,
            "self-test without --pulse-repo must not select candidate runtimes",
        )
    else:
        require(candidate_python_runtime is not None, "full self-test requires --candidate-python-runtime")
        require(candidate_node_runtime is not None, "full self-test requires --candidate-node-runtime")

    negative_count = 0
    sensitivity_matrix_status = "3-case x 4-dimension sensitivity deferred until --pulse-repo is supplied"

    def probe(label: str, operation: Callable[[], Any], message_fragment: str) -> None:
        nonlocal negative_count
        expect_failure(label, operation, message_fragment)
        negative_count += 1

    with tempfile.TemporaryDirectory(prefix="vate-pulse-starter-self-test-") as temp_dir:
        temp_root = Path(temp_dir)
        zero_path = temp_root / "zero.json"
        zero_path.write_bytes(b"")
        probe("zero-byte", lambda: read_regular_nonempty(zero_path), "zero-byte")
    probe(
        "duplicate-json-key",
        lambda: parse_strict_json(b'{"a":1,"a":2}', "duplicate-key-probe"),
        "duplicate JSON object key",
    )

    wrong_pin = copy.deepcopy(manifest)
    wrong_pin["source"]["commit"] = "0" * 40
    probe("VATE pin", lambda: validate_manifest(wrong_pin, source), "VATE pin")
    wrong_digest = copy.deepcopy(manifest)
    wrong_digest["source"]["corpus"]["digest"]["value"] = "0" * 64
    probe("corpus digest", lambda: validate_manifest(wrong_digest, source), "corpus digest")
    duplicate_path = copy.deepcopy(manifest)
    duplicate_path["cases"][0]["inputs"][1]["path"] = duplicate_path["cases"][0]["inputs"][0]["path"]
    probe("duplicate selected path", lambda: validate_manifest(duplicate_path, source), "duplicate")
    missing_case = copy.deepcopy(manifest)
    missing_case["cases"].pop()
    probe("selected case closure", lambda: validate_manifest(missing_case, source), "exactly three cases")
    unknown_manifest = copy.deepcopy(manifest)
    unknown_manifest["review_was_positive"] = True
    probe("unknown manifest field", lambda: validate_manifest(unknown_manifest, source), "unknown")
    affirmative_claim = copy.deepcopy(manifest)
    affirmative_claim["claim_contract"]["formal_audit"] = True
    affirmative_claim["claim_contract"]["endorsement"] = True
    probe("affirmative audit claim", lambda: validate_manifest(affirmative_claim, source), "negative claim boundary")
    runtime_supply_chain_claim = copy.deepcopy(manifest)
    runtime_supply_chain_claim["claim_contract"]["candidate_runtime_os_supply_chain_verified"] = True
    probe(
        "affirmative runtime supply-chain proof claim",
        lambda: validate_manifest(runtime_supply_chain_claim, source),
        "negative claim boundary",
    )
    blank_transform = copy.deepcopy(worksheet)
    blank_transform["mapping_rows"][0]["transform"] = ""
    probe("worksheet completeness", lambda: validate_worksheet(blank_transform, selected, source=source), "transform")
    expected_inventory_source = copy.deepcopy(worksheet)
    expected_inventory_source["generated_field_inventory"][0]["source_document"] = "vate_case"
    expected_inventory_source["generated_field_inventory"][0]["source_json_pointer"] = "/expected/outcome"
    probe(
        "generated inventory VATE expected source",
        lambda: validate_worksheet(expected_inventory_source, selected, source=source),
        "VATE /expected source is prohibited",
    )
    expected_mapping_source = copy.deepcopy(worksheet)
    expected_mapping_source["mapping_rows"][0]["source_document"] = "vate_case"
    expected_mapping_source["mapping_rows"][0]["source_json_pointer"] = "/expected/outcome"
    probe(
        "mapping row VATE expected source",
        lambda: validate_worksheet(expected_mapping_source, selected, source=source),
        "VATE /expected source is prohibited",
    )
    missing_generated_leaf = copy.deepcopy(worksheet)
    missing_generated_leaf["generated_field_inventory"].pop()
    probe(
        "required generated leaf missing",
        lambda: validate_worksheet(missing_generated_leaf, selected, source=source),
        "exactly 142",
    )
    missing_generated_container = build_synthetic_pulse_input(SELECTED_CASE_IDS[0])
    del missing_generated_container["expected"]["failureCodes"]
    probe(
        "required generated container missing",
        lambda: validate_completed_pulse_input(
            missing_generated_container,
            SELECTED_CASE_IDS[0],
            "missing generated container",
        ),
        "container set",
    )
    secret_material = copy.deepcopy(worksheet)
    secret_material["scaffolding_inputs"]["fixture_key_handling"]["private_key"] = "not-a-real-key"
    probe("secret-like key", lambda: scan_json_for_credentials(secret_material), "secret-bearing key")
    probe(
        "JWK private d",
        lambda: scan_json_for_credentials({"jwk": {"kty": "EC", "d": "redacted"}}, "JWK probe"),
        "secret-bearing key",
    )
    probe(
        "PEM private key",
        lambda: scan_text_for_credentials("-----BEGIN PRIVATE KEY-----\nredacted\n-----END PRIVATE KEY-----", "PEM probe"),
        "unsafe secret-like material",
    )
    probe(
        "secretKey assignment",
        lambda: scan_text_for_credentials("const secretKey = 'redacted';", "assignment probe"),
        "unsafe secret-like material",
    )
    probe(
        "hard-coded 32-byte hex",
        lambda: scan_text_for_credentials("const material = '0x" + "ab" * 32 + "';", "hex probe"),
        "unsafe 32-byte hex material",
    )
    prefilled_result = copy.deepcopy(result)
    prefilled_result["external_run"]["case_runs"][1]["projection"]["observed_relation_to_vate"] = "match"
    probe("prefilled relation", lambda: validate_result_template(prefilled_result, selected), "must remain unset")

    malformed_raw_output = {
        "recordVersion": "wrong",
        "reports": [],
        "raw_pulse_output_path": "../../etc/passwd",
        "observed_relation_to_vate": "match",
    }
    probe(
        "malformed raw Pulse output",
        lambda: validate_raw_pulse_output(malformed_raw_output, [], "malformed raw Pulse output"),
        "exact keys",
    )

    nonexistent_dependency = copy.deepcopy(worksheet)
    nonexistent_dependency["generated_field_inventory"][0]["dependencies"] = ["mapping_row:not-present"]
    probe(
        "nonexistent dependency",
        lambda: validate_worksheet(nonexistent_dependency, selected, source=source),
        "nonexistent mapping-row dependency",
    )
    self_dependency = copy.deepcopy(worksheet)
    first_destination = self_dependency["generated_field_inventory"][0]["pulse_destination"]
    self_dependency["generated_field_inventory"][0]["dependencies"] = [f"pulse_leaf:{first_destination}"]
    probe(
        "self dependency",
        lambda: validate_worksheet(self_dependency, selected, source=source),
        "self dependency",
    )
    cyclic_dependency = copy.deepcopy(worksheet)
    first = cyclic_dependency["generated_field_inventory"][0]["pulse_destination"]
    second = cyclic_dependency["generated_field_inventory"][1]["pulse_destination"]
    cyclic_dependency["generated_field_inventory"][0]["dependencies"] = [f"pulse_leaf:{second}"]
    cyclic_dependency["generated_field_inventory"][1]["dependencies"] = [f"pulse_leaf:{first}"]
    probe(
        "dependency cycle",
        lambda: validate_worksheet(cyclic_dependency, selected, source=source),
        "dependency cycle",
    )
    bad_pointer = copy.deepcopy(worksheet)
    bad_pointer["generated_field_inventory"][0]["source_document"] = "vate_admission_request"
    bad_pointer["generated_field_inventory"][0]["source_json_pointer"] = "/not-present"
    probe(
        "bad source pointer",
        lambda: validate_worksheet(bad_pointer, selected, source=source),
        "missing JSON Pointer target",
    )
    provenance_flip = copy.deepcopy(worksheet)
    for leaf in provenance_flip["generated_field_inventory"]:
        if leaf["pulse_destination"] == "/x402/payload/accepted/amount":
            leaf["provenance"] = "non-vate-scaffolding"
    probe(
        "exact-copy provenance flip",
        lambda: validate_worksheet(provenance_flip, selected, source=source),
        "exact-copy provenance",
    )
    open_provenance_destinations = {
        leaf["pulse_destination"]
        for leaf in worksheet["generated_field_inventory"]
        if leaf["provenance"] == "open_mapping_decision"
    }
    require(
        open_provenance_destinations
        == {
            "/ap2/closedMandate/execution_date",
            "/ap2/closedMandate/payee/name",
            "/ap2/closedMandate/payee/website",
            "/ap2/openMandate/constraints/3/allowed/0/name",
            "/ap2/openMandate/constraints/3/allowed/0/website",
        },
        "self-test template provenance sentinel closure mismatch",
    )
    candidate_owned_sentinel = copy.deepcopy(worksheet)
    candidate_owned_sentinel["generated_field_inventory"][0]["ownership"] = "candidate_owned"
    probe(
        "template provenance sentinel with candidate ownership",
        lambda: validate_worksheet(candidate_owned_sentinel, selected, source=source),
        "invalid provenance",
    )
    completed_provenance = completed_self_test_worksheet(worksheet)
    unresolved_completed = copy.deepcopy(completed_provenance)
    unresolved_completed["generated_field_inventory"][0]["provenance"] = "open_mapping_decision"
    probe(
        "completed provenance sentinel",
        lambda: validate_worksheet(unresolved_completed, selected, source=source, completed=True),
        "unresolved completion sentinel",
    )
    sensitivity_baseline = build_synthetic_pulse_input(SELECTED_CASE_IDS[0])
    provenance_contradiction_cases = (
        (
            "/ap2/closedMandate/execution_date",
            "2026-08-28T00:00:17Z",
            "/scaffolding_inputs/ap2_generation_profile/execution_date_transform",
            "scaffold:ap2-generation-profile",
            "mapping_row:evaluation-time",
        ),
        (
            "/ap2/closedMandate/payee/name",
            "probe-closed-payee-name",
            "/scaffolding_inputs/merchant_profile/name_transform",
            "scaffold:merchant-profile",
            "mapping_row:merchant-payee-id",
        ),
        (
            "/ap2/closedMandate/payee/website",
            "https://probe-closed-payee.example",
            "/scaffolding_inputs/merchant_profile/website_transform",
            "scaffold:merchant-profile",
            "mapping_row:merchant-payee-id",
        ),
        (
            "/ap2/openMandate/constraints/3/allowed/0/name",
            "probe-open-payee-name",
            "/scaffolding_inputs/merchant_profile/name_transform",
            "scaffold:merchant-profile",
            "mapping_row:merchant-allowed-id",
        ),
        (
            "/ap2/openMandate/constraints/3/allowed/0/website",
            "https://probe-open-payee.example",
            "/scaffolding_inputs/merchant_profile/website_transform",
            "scaffold:merchant-profile",
            "mapping_row:merchant-allowed-id",
        ),
    )
    for destination, changed_value, source_pointer, scaffold_dependency, mapping_dependency in provenance_contradiction_cases:
        sensitivity_probe = copy.deepcopy(sensitivity_baseline)
        set_json_pointer_value(sensitivity_probe, destination, changed_value)
        worksheet_contradiction = copy.deepcopy(completed_provenance)
        contradiction_leaf = next(
            leaf
            for leaf in worksheet_contradiction["generated_field_inventory"]
            if leaf["pulse_destination"] == destination
        )
        contradiction_leaf.update(
            {
                "source_document": "worksheet",
                "source_json_pointer": source_pointer,
                "dependencies": [scaffold_dependency, mapping_dependency],
                "transform": "Use fixed candidate metadata despite the recorded VATE mapping dependency.",
                "provenance": "non-vate-scaffolding",
            }
        )
        validate_worksheet(worksheet_contradiction, selected, source=source, completed=True)
        probe(
            f"VATE-sensitive worksheet provenance contradiction {destination}",
            lambda probe_value=sensitivity_probe, contradictory_worksheet=worksheet_contradiction, leaf_destination=destination: validate_sensitivity_provenance_diff(
                sensitivity_baseline,
                probe_value,
                contradictory_worksheet,
                f"worksheet provenance probe {leaf_destination}",
            ),
            "worksheet/non-vate-scaffolding direct origin",
        )
    generator_probe = copy.deepcopy(sensitivity_baseline)
    generator_destination = "/ap2/verification/cryptographicEvidence/mandateChain"
    set_json_pointer_value(generator_probe, generator_destination, "candidate-generated-probe-descendant")
    require(
        validate_sensitivity_provenance_diff(
            sensitivity_baseline,
            generator_probe,
            completed_provenance,
            "candidate generator descendant probe",
        )
        == (generator_destination,),
        "self-test candidate generator descendant diff mismatch",
    )

    with tempfile.TemporaryDirectory(prefix="vate-pulse-run-bundle-self-test-") as run_temp_dir:
        temp_root = Path(run_temp_dir)
        if pulse_repo is None:
            blocked_path, _ = build_synthetic_run_bundle(
                temp_root / "blocked",
                manifest,
                worksheet,
                result,
                source,
                status="blocked",
                completed_count=0,
                pulse_repo=None,
                candidate_python_runtime=None,
            )
            validate_run_bundle(blocked_path, manifest, source, selected, allow_self_test=True)
            print(
                "Pulse external SUT starter self-tests: blocked positive; "
                f"completed/partial actual replay deferred until --pulse-repo is supplied; {negative_count} fail-closed negative probes: ok"
            )
            return

        partial_path, partial_mapping_repo = build_synthetic_run_bundle(
            temp_root / "partial",
            manifest,
            worksheet,
            result,
            source,
            status="partial",
            completed_count=1,
            pulse_repo=pulse_repo,
            candidate_python_runtime=candidate_python_runtime,
        )
        probe(
            "partial completed case without replay repositories",
            lambda: validate_run_bundle(partial_path, manifest, source, selected, allow_self_test=True),
            "requires --mapping-repo",
        )
        validate_run_bundle(
            partial_path,
            manifest,
            source,
            selected,
            mapping_repo=partial_mapping_repo,
            pulse_repo=pulse_repo,
            candidate_python_runtime=candidate_python_runtime,
            candidate_node_runtime=None,
            allow_self_test=True,
        )
        partial_result = load_json_file(partial_path)

        unknown_reason = copy.deepcopy(partial_result)
        unknown_reason["external_run"]["attempt"]["reason_code"] = "FREE_TEXT_REASON"
        write_self_test_json(partial_path, unknown_reason)
        probe(
            "partial unknown reason",
            lambda: validate_run_bundle(partial_path, manifest, source, selected, mapping_repo=partial_mapping_repo, pulse_repo=pulse_repo, candidate_python_runtime=candidate_python_runtime, candidate_node_runtime=None, allow_self_test=True),
            "unknown stable reason code",
        )
        overlap = copy.deepcopy(partial_result)
        overlap["external_run"]["attempt"]["incomplete_case_ids"].insert(0, SELECTED_CASE_IDS[0])
        write_self_test_json(partial_path, overlap)
        probe(
            "partial overlapping case sets",
            lambda: validate_run_bundle(partial_path, manifest, source, selected, mapping_repo=partial_mapping_repo, pulse_repo=pulse_repo, candidate_python_runtime=candidate_python_runtime, candidate_node_runtime=None, allow_self_test=True),
            "overlap",
        )
        missing_evidence = copy.deepcopy(partial_result)
        missing_evidence["external_run"]["attempt"]["evidence"] = [
            item for item in missing_evidence["external_run"]["attempt"]["evidence"]
            if not (item["case_id"] == SELECTED_CASE_IDS[0] and item["kind"] == "raw-pulse-output")
        ]
        write_self_test_json(partial_path, missing_evidence)
        probe(
            "partial missing completed-case evidence",
            lambda: validate_run_bundle(partial_path, manifest, source, selected, mapping_repo=partial_mapping_repo, pulse_repo=pulse_repo, candidate_python_runtime=candidate_python_runtime, candidate_node_runtime=None, allow_self_test=True),
            "lacks Pulse input/raw output evidence",
        )
        write_self_test_json(partial_path, partial_result)

        generated_ref = partial_result["external_run"]["generated_records"]
        generated_file = partial_path.parent / generated_ref["path"]
        original_generated_bytes = generated_file.read_bytes()
        missing_generated = load_json_file(generated_file)
        missing_generated["cases"][0]["generatorRecords"].pop()
        write_self_test_json(generated_file, missing_generated)
        changed_generated_hash = sha256_bytes(generated_file.read_bytes())
        missing_generated_result = copy.deepcopy(partial_result)
        missing_generated_result["external_run"]["generated_records"]["raw_sha256"] = changed_generated_hash
        for item in missing_generated_result["external_run"]["attempt"]["evidence"]:
            if item["kind"] == "generated-records":
                item["raw_sha256"] = changed_generated_hash
        write_self_test_json(partial_path, missing_generated_result)
        probe(
            "missing generated record",
            lambda: validate_run_bundle(partial_path, manifest, source, selected, mapping_repo=partial_mapping_repo, pulse_repo=pulse_repo, candidate_python_runtime=candidate_python_runtime, candidate_node_runtime=None, allow_self_test=True),
            "generator record closure",
        )
        generated_file.write_bytes(original_generated_bytes)
        write_self_test_json(partial_path, partial_result)

        blocked_path, _ = build_synthetic_run_bundle(
            temp_root / "blocked",
            manifest,
            worksheet,
            result,
            source,
            status="blocked",
            completed_count=0,
            pulse_repo=None,
            candidate_python_runtime=None,
        )
        validate_run_bundle(blocked_path, manifest, source, selected, allow_self_test=True)
        blocked_result = load_json_file(blocked_path)
        bad_blocked_stage = copy.deepcopy(blocked_result)
        bad_blocked_stage["external_run"]["attempt"]["stage"] = "complete"
        write_self_test_json(blocked_path, bad_blocked_stage)
        probe(
            "blocked completion claim",
            lambda: validate_run_bundle(blocked_path, manifest, source, selected, allow_self_test=True),
            "cannot claim completion",
        )

        if pulse_repo is not None:
            assert candidate_python_runtime is not None and candidate_node_runtime is not None
            trusted_python_runtime = preflight_candidate_runtime(
                "python3",
                candidate_python_runtime,
                None,
                temp_root,
                "self-test trusted Python runtime",
            )
            trusted_node_runtime = preflight_candidate_runtime(
                "node",
                None,
                candidate_node_runtime,
                temp_root,
                "self-test trusted Node runtime",
            )

            def run_with_ambient_path(path_prefix: Path, operation: Callable[[], Any]) -> Any:
                prior_path = os.environ.get("PATH")
                os.environ["PATH"] = str(path_prefix) + (os.pathsep + prior_path if prior_path else "")
                try:
                    return operation()
                finally:
                    if prior_path is None:
                        os.environ.pop("PATH", None)
                    else:
                        os.environ["PATH"] = prior_path

            python_path_root = temp_root / "python-path-hijack"
            python_path_root.mkdir(parents=True, exist_ok=True)
            (python_path_root / ".gitignore").write_text(".venv/\n", encoding="utf-8")
            (python_path_root / "mapper.py").write_text(
                "import sys\nsys.stdin.read()\nsys.stdout.write('{}')\n",
                encoding="utf-8",
            )
            python_fake_dir = python_path_root / ".venv" / "bin"
            python_fake_dir.mkdir(parents=True)
            python_fake_marker = python_path_root / ".venv" / "ambient-python-used"
            python_fake_runtime = python_fake_dir / "python3"
            python_fake_runtime.write_text(
                "#!/bin/sh\nprintf used > " + repr(str(python_fake_marker)) + "\nprintf '{}'\n",
                encoding="utf-8",
            )
            python_fake_runtime.chmod(0o755)
            python_path_commit = commit_self_test_repository(
                python_path_root,
                [".gitignore", "mapper.py"],
                "Python PATH hijack positive baseline",
            )
            _, python_path_export = candidate_commit_files(python_path_root, python_path_commit)
            python_path_command = ["python3", "-I", "-S", "-B", "mapper.py"]
            python_path_positive = run_with_ambient_path(
                python_fake_dir,
                lambda: run_candidate_executable(
                    python_path_root,
                    python_path_commit,
                    python_path_command,
                    trusted_python_runtime,
                    b"{}\n",
                    "explicit Python runtime under hostile ambient PATH",
                    expected_export_contract=python_path_export,
                ),
            )
            require(python_path_positive == b"{}", "explicit Python runtime positive returned unexpected stdout")
            require(not python_fake_marker.exists(), "ambient Python launcher was executed despite the explicit runtime")
            (python_path_root / "mapper.py").write_text("raise SystemExit(9)\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(python_path_root), "add", "mapper.py"], check=True, capture_output=True)
            subprocess.run(
                ["git", "-C", str(python_path_root), "commit", "--quiet", "-m", "tracked mapper failure"],
                check=True,
                capture_output=True,
            )
            python_failure_commit = run_git(python_path_root, ["rev-parse", "HEAD"]).decode("ascii").strip()
            _, python_failure_export = candidate_commit_files(python_path_root, python_failure_commit)

            def reject_python_path_hijack() -> None:
                try:
                    run_with_ambient_path(
                        python_fake_dir,
                        lambda: run_candidate_executable(
                            python_path_root,
                            python_failure_commit,
                            python_path_command,
                            trusted_python_runtime,
                            b"{}\n",
                            "ignored Python PATH hijack",
                            expected_export_contract=python_failure_export,
                        ),
                    )
                finally:
                    require(not python_fake_marker.exists(), "ignored Python PATH launcher was executed")

            probe("ignored Python runtime PATH hijack", reject_python_path_hijack, "candidate executable failed")

            node_path_root = temp_root / "node-path-hijack"
            node_path_root.mkdir(parents=True, exist_ok=True)
            (node_path_root / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
            (node_path_root / "mapper.mjs").write_text(
                "process.stdin.on('data',()=>{});process.stdin.on('end',()=>process.stdout.write('{}'));\n",
                encoding="utf-8",
            )
            node_fake_dir = node_path_root / "node_modules" / ".bin"
            node_fake_dir.mkdir(parents=True)
            node_fake_marker = node_path_root / "node_modules" / "ambient-node-used"
            node_fake_runtime = node_fake_dir / "node"
            node_fake_runtime.write_text(
                "#!/bin/sh\nprintf used > " + repr(str(node_fake_marker)) + "\nprintf '{}'\n",
                encoding="utf-8",
            )
            node_fake_runtime.chmod(0o755)
            node_path_commit = commit_self_test_repository(
                node_path_root,
                [".gitignore", "mapper.mjs"],
                "Node PATH hijack positive baseline",
            )
            _, node_path_export = candidate_commit_files(node_path_root, node_path_commit)
            node_path_command = ["node", "--no-addons", "--no-global-search-paths", "mapper.mjs"]
            node_path_positive = run_with_ambient_path(
                node_fake_dir,
                lambda: run_candidate_executable(
                    node_path_root,
                    node_path_commit,
                    node_path_command,
                    trusted_node_runtime,
                    b"{}\n",
                    "explicit Node runtime under hostile ambient PATH",
                    expected_export_contract=node_path_export,
                ),
            )
            require(node_path_positive == b"{}", "explicit Node runtime positive returned unexpected stdout")
            require(not node_fake_marker.exists(), "ambient Node launcher was executed despite the explicit runtime")
            (node_path_root / "mapper.mjs").write_text("process.exit(9);\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(node_path_root), "add", "mapper.mjs"], check=True, capture_output=True)
            subprocess.run(
                ["git", "-C", str(node_path_root), "commit", "--quiet", "-m", "tracked mapper failure"],
                check=True,
                capture_output=True,
            )
            node_failure_commit = run_git(node_path_root, ["rev-parse", "HEAD"]).decode("ascii").strip()
            _, node_failure_export = candidate_commit_files(node_path_root, node_failure_commit)

            def reject_node_path_hijack() -> None:
                try:
                    run_with_ambient_path(
                        node_fake_dir,
                        lambda: run_candidate_executable(
                            node_path_root,
                            node_failure_commit,
                            node_path_command,
                            trusted_node_runtime,
                            b"{}\n",
                            "ignored Node PATH hijack",
                            expected_export_contract=node_failure_export,
                        ),
                    )
                finally:
                    require(not node_fake_marker.exists(), "ignored Node PATH launcher was executed")

            probe("ignored Node runtime PATH hijack", reject_node_path_hijack, "candidate executable failed")
            probe(
                "candidate-repository ignored runtime selected directly",
                lambda: preflight_candidate_runtime(
                    "python3",
                    python_fake_runtime,
                    None,
                    python_path_root,
                    "candidate repository runtime probe",
                ),
                "inside the candidate mapping repository",
            )
            probe(
                "relative candidate runtime path",
                lambda: preflight_candidate_runtime(
                    "python3",
                    Path("python3"),
                    None,
                    python_path_root,
                    "relative runtime probe",
                ),
                "must be absolute",
            )

            replacement_root = temp_root / "runtime-replacement"
            replacement_candidate = replacement_root / "candidate"
            replacement_operator = replacement_root / "operator"
            replacement_candidate.mkdir(parents=True)
            replacement_operator.mkdir(parents=True)
            replacement_runtime_path = replacement_operator / "python3"
            replacement_runtime_path.write_text(
                "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf 'Python 3.14.0\\n'; exit 0; fi\nexit 0\n",
                encoding="utf-8",
            )
            replacement_runtime_path.chmod(0o755)
            replacement_runtime = preflight_candidate_runtime(
                "python3",
                replacement_runtime_path,
                None,
                replacement_candidate,
                "runtime replacement probe",
            )
            replacement_runtime_path.write_text(
                "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf 'Python 3.14.1\\n'; exit 0; fi\nexit 9\n",
                encoding="utf-8",
            )
            replacement_runtime_path.chmod(0o755)
            probe(
                "runtime binary replacement after preflight",
                lambda: verify_candidate_runtime_unchanged(
                    replacement_runtime,
                    replacement_candidate,
                    "runtime replacement post-preflight",
                ),
                "changed after preflight",
            )

            completed_probe_worksheet = completed_self_test_worksheet(worksheet)
            allow_case = selected[SELECTED_CASE_IDS[0]]
            allow_refs = {entry["artifact_key"]: entry for entry in allow_case["inputs"]}
            allow_admission = expect_object(
                parse_strict_json(source.blobs[allow_refs["admission_request"]["path"]], "no-op probe admission"),
                "no-op probe admission",
            )
            allow_mandate = expect_object(
                parse_strict_json(source.blobs[allow_refs["ap2_mandate"]["path"]], "no-op probe mandate"),
                "no-op probe mandate",
            )
            allow_documents = {SELECTED_CASE_IDS[0]: (allow_admission, allow_mandate)}
            allow_map_request = candidate_map_request_value(allow_documents, (SELECTED_CASE_IDS[0],))

            ignored_root = temp_root / "ignored-runtime-attack"
            ignored_root.mkdir(parents=True, exist_ok=True)
            (ignored_root / ".gitignore").write_text("runtime_impl.py\n", encoding="utf-8")
            (ignored_root / "mapper.py").write_text(
                "import runpy\nrunpy.run_path('runtime_impl.py', run_name='__main__')\n",
                encoding="utf-8",
            )
            (ignored_root / "runtime_impl.py").write_text(
                "import json,sys\nrequest=json.load(sys.stdin)\njson.dump({'interfaceVersion':request['interfaceVersion'],'operation':request['operation'],'items':[]},sys.stdout)\n",
                encoding="utf-8",
            )
            ignored_commit = commit_self_test_repository(
                ignored_root,
                [".gitignore", "mapper.py"],
                "ignored runtime attack probe",
            )
            require(
                not run_git(ignored_root, ["status", "--porcelain"]).strip(),
                "ignored runtime attack setup must appear clean to ordinary Git status",
            )
            _, ignored_export_contract = candidate_commit_files(ignored_root, ignored_commit)
            probe(
                "ignored untracked runtime implementation",
                lambda: run_candidate_executable(
                    ignored_root,
                    ignored_commit,
                    ["python3", "-I", "-S", "-B", "mapper.py"],
                    trusted_python_runtime,
                    canonical_json_bytes(allow_map_request),
                    "ignored runtime attack",
                    expected_export_contract=ignored_export_contract,
                ),
                "candidate executable failed",
            )

            symlink_root = temp_root / "symlink-commit-entry"
            symlink_root.mkdir(parents=True, exist_ok=True)
            (symlink_root / "target.py").write_text("print('{}')\n", encoding="utf-8")
            (symlink_root / "mapper.py").symlink_to("target.py")
            symlink_commit = commit_self_test_repository(
                symlink_root,
                ["mapper.py", "target.py"],
                "symlink commit entry probe",
            )
            probe(
                "candidate commit symlink entry",
                lambda: candidate_commit_files(symlink_root, symlink_commit),
                "not a tracked regular file",
            )

            gitlink_root = temp_root / "gitlink-commit-entry"
            gitlink_root.mkdir(parents=True, exist_ok=True)
            (gitlink_root / "mapper.py").write_text("print('{}')\n", encoding="utf-8")
            gitlink_base_commit = commit_self_test_repository(
                gitlink_root,
                ["mapper.py"],
                "gitlink base probe",
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(gitlink_root),
                    "update-index",
                    "--add",
                    "--cacheinfo",
                    f"160000,{gitlink_base_commit},vendor/runtime",
                ],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "-C", str(gitlink_root), "commit", "--quiet", "-m", "gitlink entry probe"],
                check=True,
                capture_output=True,
            )
            gitlink_commit = run_git(gitlink_root, ["rev-parse", "HEAD"]).decode("ascii").strip()
            probe(
                "candidate commit gitlink entry",
                lambda: candidate_commit_files(gitlink_root, gitlink_commit),
                "not a tracked regular file",
            )

            write_root = temp_root / "export-write"
            write_root.mkdir(parents=True, exist_ok=True)
            (write_root / "mapper.py").write_text(
                "import pathlib,sys\nsys.stdin.read()\npathlib.Path('runtime-write.txt').write_text('x')\nsys.stdout.write('{}')\n",
                encoding="utf-8",
            )
            write_commit = commit_self_test_repository(write_root, ["mapper.py"], "export write probe")
            _, write_export_contract = candidate_commit_files(write_root, write_commit)
            probe(
                "candidate commit-export write",
                lambda: run_candidate_executable(
                    write_root,
                    write_commit,
                    ["python3", "-I", "-S", "-B", "mapper.py"],
                    trusted_python_runtime,
                    canonical_json_bytes(allow_map_request),
                    "export write probe",
                    expected_export_contract=write_export_contract,
                ),
                "modified the fresh commit-export execution tree",
            )

            external_import_root = temp_root / "external-import"
            external_import_root.mkdir(parents=True, exist_ok=True)
            (external_import_root / "mapper.py").write_text("import requests\n", encoding="utf-8")
            external_import_commit = commit_self_test_repository(
                external_import_root,
                ["mapper.py"],
                "external import probe",
            )
            external_import_files, _ = candidate_commit_files(external_import_root, external_import_commit)
            probe(
                "candidate external package import",
                lambda: validate_candidate_dependency_policy(external_import_files, "python3", "mapper.py"),
                "imports an external package",
            )

            network_import_root = temp_root / "network-import"
            network_import_root.mkdir(parents=True, exist_ok=True)
            (network_import_root / "mapper.py").write_text("import socket\n", encoding="utf-8")
            network_import_commit = commit_self_test_repository(
                network_import_root,
                ["mapper.py"],
                "network import probe",
            )
            network_import_files, _ = candidate_commit_files(network_import_root, network_import_commit)
            probe(
                "candidate network-capable import",
                lambda: validate_candidate_dependency_policy(network_import_files, "python3", "mapper.py"),
                "prohibited runtime module",
            )

            huge_stdout_root = temp_root / "huge-stdout"
            huge_stdout_root.mkdir(parents=True, exist_ok=True)
            (huge_stdout_root / "mapper.py").write_text(
                "import sys\nsys.stdin.read()\nsys.stdout.write('x' * 2048)\n",
                encoding="utf-8",
            )
            huge_stdout_commit = commit_self_test_repository(
                huge_stdout_root,
                ["mapper.py"],
                "huge stdout probe",
            )
            _, huge_stdout_export_contract = candidate_commit_files(huge_stdout_root, huge_stdout_commit)
            probe(
                "bounded candidate stdout",
                lambda: run_candidate_executable(
                    huge_stdout_root,
                    huge_stdout_commit,
                    ["python3", "-I", "-S", "-B", "mapper.py"],
                    trusted_python_runtime,
                    canonical_json_bytes(allow_map_request),
                    "huge stdout probe",
                    expected_export_contract=huge_stdout_export_contract,
                    stdout_limit=1024,
                ),
                "stdout exceeded its byte limit",
            )

            huge_stderr_root = temp_root / "huge-stderr"
            huge_stderr_root.mkdir(parents=True, exist_ok=True)
            (huge_stderr_root / "mapper.py").write_text(
                "import sys\nsys.stdin.read()\nsys.stderr.write('x' * 2048)\nsys.stdout.write('{}')\n",
                encoding="utf-8",
            )
            huge_stderr_commit = commit_self_test_repository(
                huge_stderr_root,
                ["mapper.py"],
                "huge stderr probe",
            )
            _, huge_stderr_export_contract = candidate_commit_files(huge_stderr_root, huge_stderr_commit)
            probe(
                "bounded candidate stderr",
                lambda: run_candidate_executable(
                    huge_stderr_root,
                    huge_stderr_commit,
                    ["python3", "-I", "-S", "-B", "mapper.py"],
                    trusted_python_runtime,
                    canonical_json_bytes(allow_map_request),
                    "huge stderr probe",
                    expected_export_contract=huge_stderr_export_contract,
                    stderr_limit=1024,
                ),
                "stderr exceeded its byte limit",
            )

            child_hang_root = temp_root / "child-hang"
            child_hang_root.mkdir(parents=True, exist_ok=True)
            (child_hang_root / "home").mkdir()
            (child_hang_root / "tmp").mkdir()
            child_hang_script = child_hang_root / "child_hang.py"
            child_hang_script.write_text(
                "import os,time\n"
                "child=os.fork()\n"
                "if child == 0:\n"
                "    time.sleep(30)\n",
                encoding="utf-8",
            )
            probe(
                "candidate child process hang",
                lambda: run_bounded_process(
                    [trusted_python_runtime.identity.realpath, "-I", "-S", "-B", child_hang_script.name],
                    cwd=child_hang_root,
                    request_raw=b"{}\n",
                    environment=candidate_subprocess_env(child_hang_root),
                    label="child process hang probe",
                    timeout_seconds=1.0,
                    stdout_limit=1024,
                    stderr_limit=1024,
                ),
                "descendant retained an output pipe",
            )

            sensitivity_root = temp_root / "three-case-sensitivity"
            sensitivity_root.mkdir(parents=True, exist_ok=True)
            sensitivity_documents: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
            sensitivity_fixtures: dict[str, dict[str, Any]] = {}
            for case_id in SELECTED_CASE_IDS:
                selected_case = selected[case_id]
                refs = {entry["artifact_key"]: entry for entry in selected_case["inputs"]}
                admission = expect_object(
                    parse_strict_json(source.blobs[refs["admission_request"]["path"]], "sensitivity admission"),
                    "sensitivity admission",
                )
                mandate = expect_object(
                    parse_strict_json(source.blobs[refs["ap2_mandate"]["path"]], "sensitivity mandate"),
                    "sensitivity mandate",
                )
                sensitivity_documents[case_id] = (admission, mandate)
                pulse_value = build_synthetic_pulse_input(case_id)
                expectations, _ = independent_mapping_expectations(
                    admission,
                    mandate,
                    completed_probe_worksheet,
                    f"sensitivity baseline {case_id}",
                )
                for pointer, expected_value in expectations.items():
                    set_json_pointer_value(pulse_value, pointer, expected_value)
                set_json_pointer_value(pulse_value, "/ap2/openMandate/constraints/2/min", 0)
                replay_nonce = expect_nonempty_string(
                    json_pointer_value(mandate, "/constraints/replay_nonce", "sensitivity replay nonce"),
                    "sensitivity replay nonce",
                )
                reference_bytes = hashlib.sha256(replay_nonce.encode("utf-8")).digest()
                reference = base64.urlsafe_b64encode(reference_bytes).rstrip(b"=").decode("ascii")
                set_json_pointer_value(pulse_value, "/ap2/verification/closedMandateReference", reference)
                set_json_pointer_value(
                    pulse_value,
                    "/x402/payload/payload/authorization/nonce",
                    "0x" + reference_bytes.hex(),
                )
                sensitivity_fixtures[CANDIDATE_WORK_ITEM_IDS[SELECTED_CASE_IDS.index(case_id)]] = pulse_value
            (sensitivity_root / "mapper.py").write_text(sensitivity_self_test_mapper_source(), encoding="utf-8")
            write_self_test_json(sensitivity_root / "fixtures.json", sensitivity_fixtures)
            sensitivity_commit = commit_self_test_repository(
                sensitivity_root,
                ["mapper.py", "fixtures.json"],
                "three-case sensitivity probe",
            )
            sensitivity_command = ["python3", "-I", "-S", "-B", "mapper.py"]
            sensitivity_files, sensitivity_export_contract = candidate_commit_files(
                sensitivity_root,
                sensitivity_commit,
            )
            validate_candidate_dependency_policy(sensitivity_files, "python3", "mapper.py")
            sensitivity_request = candidate_map_request_value(sensitivity_documents, SELECTED_CASE_IDS)
            sensitivity_baseline_raw = run_candidate_executable(
                sensitivity_root,
                sensitivity_commit,
                sensitivity_command,
                trusted_python_runtime,
                canonical_json_bytes(sensitivity_request),
                "three-case sensitivity baseline",
                expected_export_contract=sensitivity_export_contract,
            )
            sensitivity_baseline_outputs, _ = validate_candidate_map_output(
                sensitivity_baseline_raw,
                SELECTED_CASE_IDS,
                "three-case sensitivity baseline output",
            )
            run_sensitivity_probes(
                sensitivity_root,
                sensitivity_commit,
                sensitivity_command,
                trusted_python_runtime,
                sensitivity_export_contract,
                sensitivity_request,
                sensitivity_baseline_outputs,
                completed_probe_worksheet,
                SELECTED_CASE_IDS,
                "three-case sensitivity matrix",
            )
            sensitivity_matrix_status = "3-case x 4-dimension fresh-export sensitivity included"

            no_op_root = temp_root / "one-line-no-op"
            no_op_root.mkdir(parents=True, exist_ok=True)
            no_op_input = load_self_test_pulse_input(
                pulse_repo,
                "valid-base-sepolia-01",
                SELECTED_CASE_IDS[0],
            )
            no_op_input["description"] = "Lightly modified fixed Pulse fixture used only by a negative validator self-test."
            no_op_input["x402"]["payload"]["resource"]["description"] = "Lightly modified resource description."
            no_op_input_path = no_op_root / "pulse-input.json"
            no_op_input_path.write_bytes(canonical_json_bytes(no_op_input))
            preflight_hash = sha256_bytes(no_op_input_path.read_bytes())
            preflight_reports, _ = replay_pulse_reports(
                pulse_repo,
                no_op_root,
                [(SELECTED_CASE_IDS[0], no_op_input_path.name, preflight_hash)],
            )
            no_op_input["inputHash"] = preflight_reports[0]["computed"]["inputHash"]
            no_op_input_path.write_bytes(canonical_json_bytes(no_op_input))
            no_op_input_hash = sha256_bytes(no_op_input_path.read_bytes())
            no_op_map_output = canonical_json_bytes(
                {
                    "interfaceVersion": CANDIDATE_INTERFACE_VERSION,
                    "operation": "map",
                    "items": [
                        {
                            "workItemId": CANDIDATE_WORK_ITEM_IDS[0],
                            "pulseInputRaw": no_op_input_path.read_text(encoding="utf-8"),
                        }
                    ],
                }
            )
            no_op_script = no_op_root / "mapper.py"
            no_op_script.write_text(
                "import sys;sys.stdin.read();sys.stdout.write(" + repr(no_op_map_output.decode("utf-8")) + ")\n",
                encoding="utf-8",
            )
            no_op_commit = commit_self_test_repository(no_op_root, ["mapper.py"], "one-line no-op probe")
            _, no_op_export_contract = candidate_commit_files(no_op_root, no_op_commit)
            isolated_python_command = ["python3", "-I", "-S", "-B", "mapper.py"]

            def reject_one_line_no_op_with_actual_replay() -> None:
                replayed, _ = replay_pulse_reports(
                    pulse_repo,
                    no_op_root,
                    [(SELECTED_CASE_IDS[0], no_op_input_path.name, no_op_input_hash)],
                )
                require(replayed[0]["consistent"] is True, "one-line no-op negative setup did not produce a real Pulse accept")
                mapper_stdout = run_candidate_executable(
                    no_op_root,
                    no_op_commit,
                    isolated_python_command,
                    trusted_python_runtime,
                    canonical_json_bytes(allow_map_request),
                    "one-line no-op mapper",
                    expected_export_contract=no_op_export_contract,
                )
                _, values = validate_candidate_map_output(mapper_stdout, (SELECTED_CASE_IDS[0],), "one-line no-op output")
                validate_independent_mapping(
                    values[0],
                    allow_admission,
                    allow_mandate,
                    completed_probe_worksheet,
                    "allow",
                    "one-line no-op actual replay",
                )

            probe(
                "one-line no-op mapper with modified fixed fixture and actual replay",
                reject_one_line_no_op_with_actual_replay,
                "independent recomputation mismatch",
            )

            for lookup_label, lookup_expression in (
                ("obfuscated expected lookup", "item['eligibleInput']['admissionRequest']['ex'+'pected']"),
                ("obfuscated receipt lookup", "item['eligibleInput']['admission'+'_receipt']"),
            ):
                lookup_root = temp_root / lookup_label.replace(" ", "-")
                lookup_root.mkdir(parents=True, exist_ok=True)
                lookup_script = lookup_root / "mapper.py"
                lookup_script.write_text(
                    "import json,sys;request=json.load(sys.stdin);item=request['items'][0];"
                    + lookup_expression
                    + ";sys.stdout.write('{}')\n",
                    encoding="utf-8",
                )
                lookup_commit = commit_self_test_repository(lookup_root, ["mapper.py"], lookup_label)
                _, lookup_export_contract = candidate_commit_files(lookup_root, lookup_commit)
                probe(
                    lookup_label,
                    lambda root=lookup_root, commit=lookup_commit, contract=lookup_export_contract: run_candidate_executable(
                        root,
                        commit,
                        isolated_python_command,
                        trusted_python_runtime,
                        canonical_json_bytes(allow_map_request),
                        lookup_label,
                        expected_export_contract=contract,
                    ),
                    "candidate executable failed",
                )

            stale_case = selected[SELECTED_CASE_IDS[2]]
            stale_refs = {entry["artifact_key"]: entry for entry in stale_case["inputs"]}
            stale_admission = expect_object(parse_strict_json(source.blobs[stale_refs["admission_request"]["path"]], "stale probe admission"), "stale probe admission")
            stale_mandate = expect_object(parse_strict_json(source.blobs[stale_refs["ap2_mandate"]["path"]], "stale probe mandate"), "stale probe mandate")
            stale_projection = projection_semantic_value(
                {
                    "observed_relation_to_vate": "match",
                    "pulse_outcome_class": "reject",
                    "projected_vate_outcome": "deny",
                    "projected_should_execute": False,
                    "projected_reason_codes": ["PERMIT_EXPIRED", "FAIL_CLOSED"],
                    "projected_checks": [],
                }
            )
            stale_wrong_report = {
                "caseId": expected_pulse_case_id(SELECTED_CASE_IDS[2]),
                "consistent": False,
                "computed": {},
                "failures": [
                    {
                        "code": "EIP3009_VALID_BEFORE_EXPIRED",
                        "path": "x402.payload.payload.authorization.validBefore",
                        "message": "Negative projection self-test.",
                    },
                    {
                        "code": "AP2_OPEN_MANDATE_UNVERIFIED",
                        "path": "ap2.verification.cryptographicEvidence.mandateChain",
                        "message": "Negative projection self-test.",
                    }
                ],
            }
            probe(
                "stale unrelated AP2 open-mandate failure treated as match",
                lambda: validate_closed_projection_contract(
                    SELECTED_CASE_IDS[2],
                    stale_admission,
                    stale_mandate,
                    stale_wrong_report,
                    stale_projection,
                    "stale wrong-code probe",
                ),
                "unrelated Pulse failure",
            )

            allow_accept_report = {
                "caseId": expected_pulse_case_id(SELECTED_CASE_IDS[0]),
                "consistent": True,
                "computed": {},
                "failures": [],
            }
            for contradictory_class in ("error", "unsupported", "reject"):
                contradictory_projection = projection_semantic_value(
                    {
                        "observed_relation_to_vate": "match",
                        "pulse_outcome_class": contradictory_class,
                        "projected_vate_outcome": "allow",
                        "projected_should_execute": True,
                        "projected_reason_codes": ["EVIDENCE_VERIFIED", "POLICY_MATCH"],
                        "projected_checks": [],
                    }
                )
                probe(
                    f"raw accept with {contradictory_class} outcome class",
                    lambda projection=contradictory_projection: validate_closed_projection_contract(
                        SELECTED_CASE_IDS[0],
                        allow_admission,
                        allow_mandate,
                        allow_accept_report,
                        projection,
                        "raw accept contradiction",
                    ),
                    "completed case cannot use" if contradictory_class in {"error", "unsupported"} else "allow projection class/relation mismatch",
                )

            overrun_case = selected[SELECTED_CASE_IDS[1]]
            overrun_refs = {entry["artifact_key"]: entry for entry in overrun_case["inputs"]}
            overrun_admission = expect_object(parse_strict_json(source.blobs[overrun_refs["admission_request"]["path"]], "overrun contradiction admission"), "overrun contradiction admission")
            overrun_mandate = expect_object(parse_strict_json(source.blobs[overrun_refs["ap2_mandate"]["path"]], "overrun contradiction mandate"), "overrun contradiction mandate")
            rejected_report = {
                "caseId": expected_pulse_case_id(SELECTED_CASE_IDS[1]),
                "consistent": False,
                "computed": {},
                "failures": [
                    {
                        "code": "AP2_X402_AMOUNT_MISMATCH",
                        "path": "x402.requirements.amount",
                        "message": "Negative projection self-test.",
                    }
                ],
            }
            rejected_as_accept = projection_semantic_value(
                {
                    "observed_relation_to_vate": "match",
                    "pulse_outcome_class": "accept",
                    "projected_vate_outcome": "allow",
                    "projected_should_execute": True,
                    "projected_reason_codes": ["EVIDENCE_VERIFIED", "POLICY_MATCH"],
                    "projected_checks": [],
                }
            )
            probe(
                "raw reject with accept outcome class",
                lambda: validate_closed_projection_contract(
                    SELECTED_CASE_IDS[1],
                    overrun_admission,
                    overrun_mandate,
                    rejected_report,
                    rejected_as_accept,
                    "raw reject contradiction",
                ),
                "overrun projection must remain",
            )

            hardcoded_input = build_synthetic_pulse_input(SELECTED_CASE_IDS[0])
            hardcoded_expectations, _ = independent_mapping_expectations(
                allow_admission,
                allow_mandate,
                completed_probe_worksheet,
                "hardcoded probe baseline",
            )
            for pointer, expected_value in hardcoded_expectations.items():
                set_json_pointer_value(hardcoded_input, pointer, expected_value)
            set_json_pointer_value(hardcoded_input, "/ap2/openMandate/constraints/2/min", 0)
            hardcoded_reference = json_pointer_value(hardcoded_input, "/ap2/verification/closedMandateReference", "hardcoded input")
            set_json_pointer_value(
                hardcoded_input,
                "/x402/payload/payload/authorization/nonce",
                "0x" + base64.urlsafe_b64decode(hardcoded_reference + "=").hex(),
            )
            validate_independent_mapping(
                hardcoded_input,
                allow_admission,
                allow_mandate,
                completed_probe_worksheet,
                "allow",
                "hardcoded probe baseline",
            )
            hardcoded_root = temp_root / "hardcoded-sensitivity"
            hardcoded_root.mkdir(parents=True, exist_ok=True)
            hardcoded_output_raw = canonical_json_bytes(
                {
                    "interfaceVersion": CANDIDATE_INTERFACE_VERSION,
                    "operation": "map",
                    "items": [
                        {
                            "workItemId": CANDIDATE_WORK_ITEM_IDS[0],
                            "pulseInputRaw": canonical_json_bytes(hardcoded_input).decode("utf-8"),
                        }
                    ],
                }
            )
            (hardcoded_root / "mapper.py").write_text(
                "import sys;sys.stdin.read();sys.stdout.write(" + repr(hardcoded_output_raw.decode("utf-8")) + ")\n",
                encoding="utf-8",
            )
            hardcoded_commit = commit_self_test_repository(hardcoded_root, ["mapper.py"], "hardcoded sensitivity probe")
            _, hardcoded_export_contract = candidate_commit_files(hardcoded_root, hardcoded_commit)
            probe(
                "self-consistent candidate hardcoded outputs",
                lambda: run_sensitivity_probes(
                    hardcoded_root,
                    hardcoded_commit,
                    isolated_python_command,
                    trusted_python_runtime,
                    hardcoded_export_contract,
                    allow_map_request,
                    [canonical_json_bytes(hardcoded_input).decode("utf-8")],
                    completed_probe_worksheet,
                    (SELECTED_CASE_IDS[0],),
                    "hardcoded output probe",
                ),
                "independent recomputation mismatch",
            )

            bundle_root = temp_root / "completed"
            result_path, mapping_repo = build_synthetic_run_bundle(
                bundle_root,
                manifest,
                worksheet,
                result,
                source,
                status="completed",
                completed_count=3,
                pulse_repo=pulse_repo,
                candidate_python_runtime=candidate_python_runtime,
            )
            validate_run_bundle(
                result_path,
                manifest,
                source,
                selected,
                mapping_repo=mapping_repo,
                pulse_repo=pulse_repo,
                candidate_python_runtime=candidate_python_runtime,
                candidate_node_runtime=None,
                allow_self_test=True,
            )
            positive_result = load_json_file(result_path)

            probe(
                "completed missing explicit candidate runtime",
                lambda: validate_run_bundle(
                    result_path,
                    manifest,
                    source,
                    selected,
                    mapping_repo=mapping_repo,
                    pulse_repo=pulse_repo,
                    allow_self_test=True,
                ),
                "requires --candidate-python-runtime",
            )
            probe(
                "completed receives both candidate runtimes",
                lambda: validate_run_bundle(
                    result_path,
                    manifest,
                    source,
                    selected,
                    mapping_repo=mapping_repo,
                    pulse_repo=pulse_repo,
                    candidate_python_runtime=candidate_python_runtime,
                    candidate_node_runtime=candidate_node_runtime,
                    allow_self_test=True,
                ),
                "must not receive --candidate-node-runtime",
            )
            bad_runtime_record = copy.deepcopy(positive_result)
            bad_runtime_record["external_run"]["candidate_execution"]["runtime"]["raw_sha256"] = "0" * 64
            write_self_test_json(result_path, bad_runtime_record)
            probe(
                "candidate runtime record hash mutation",
                lambda: validate_run_bundle(
                    result_path,
                    manifest,
                    source,
                    selected,
                    mapping_repo=mapping_repo,
                    pulse_repo=pulse_repo,
                    candidate_python_runtime=candidate_python_runtime,
                    candidate_node_runtime=None,
                    allow_self_test=True,
                ),
                "recorded candidate runtime differs",
            )
            write_self_test_json(result_path, positive_result)

            probe(
                "completed missing mapping repo",
                lambda: validate_run_bundle(
                    result_path,
                    manifest,
                    source,
                    selected,
                    pulse_repo=pulse_repo,
                    candidate_python_runtime=candidate_python_runtime,
                    candidate_node_runtime=None,
                    allow_self_test=True,
                ),
                "requires --mapping-repo",
            )
            probe(
                "completed missing Pulse repo",
                lambda: validate_run_bundle(
                    result_path,
                    manifest,
                    source,
                    selected,
                    mapping_repo=mapping_repo,
                    candidate_python_runtime=candidate_python_runtime,
                    candidate_node_runtime=None,
                    allow_self_test=True,
                ),
                "requires --pulse-repo",
            )
            probe(
                "self-test evidence elevation",
                lambda: validate_run_bundle(
                    result_path,
                    manifest,
                    source,
                    selected,
                    mapping_repo=mapping_repo,
                    pulse_repo=pulse_repo,
                    candidate_python_runtime=candidate_python_runtime,
                    candidate_node_runtime=None,
                ),
                "evidence class",
            )

            unexpected_result_field = copy.deepcopy(positive_result)
            unexpected_result_field["results"][0]["expected_outcome_copy"] = "allow"
            write_self_test_json(result_path, unexpected_result_field)
            probe(
                "result expected_outcome_copy",
                lambda: validate_run_bundle(
                    result_path, manifest, source, selected, mapping_repo=mapping_repo, pulse_repo=pulse_repo, candidate_python_runtime=candidate_python_runtime, candidate_node_runtime=None, allow_self_test=True
                ),
                "unknown=['expected_outcome_copy']",
            )

            missing_out_of_scope = copy.deepcopy(positive_result)
            missing_out_of_scope["results"].pop()
            write_self_test_json(result_path, missing_out_of_scope)
            probe(
                "missing out-of-scope result",
                lambda: validate_run_bundle(
                    result_path, manifest, source, selected, mapping_repo=mapping_repo, pulse_repo=pulse_repo, candidate_python_runtime=candidate_python_runtime, candidate_node_runtime=None, allow_self_test=True
                ),
                "72 explicit out-of-scope",
            )

            fake_commit = copy.deepcopy(positive_result)
            fake_commit["implementation"]["commit"] = "0" * 40
            fake_commit["external_run"]["mapping_source"]["commit"] = "0" * 40
            write_self_test_json(result_path, fake_commit)
            probe(
                "fake mapping commit",
                lambda: validate_run_bundle(
                    result_path, manifest, source, selected, mapping_repo=mapping_repo, pulse_repo=pulse_repo, candidate_python_runtime=candidate_python_runtime, candidate_node_runtime=None, allow_self_test=True
                ),
                "candidate mapping commit",
            )

            fake_repository = copy.deepcopy(positive_result)
            fake_repository["implementation"]["source"] = "https://github.com/not-the-mapping/repository"
            fake_repository["external_run"]["mapping_source"]["repository"] = "https://github.com/not-the-mapping/repository"
            write_self_test_json(result_path, fake_repository)
            probe(
                "fake mapping repository",
                lambda: validate_run_bundle(
                    result_path, manifest, source, selected, mapping_repo=mapping_repo, pulse_repo=pulse_repo, candidate_python_runtime=candidate_python_runtime, candidate_node_runtime=None, allow_self_test=True
                ),
                "origin does not equal",
            )

            command_bypass = copy.deepcopy(positive_result)
            bypass_command = ["python3", "-c", "raise SystemExit(0)", "src/mapper.py"]
            command_bypass["external_run"]["mapping_source"]["command"] = bypass_command
            command_bypass["external_run"]["candidate_execution"]["command"] = bypass_command
            write_self_test_json(result_path, command_bypass)
            probe(
                "candidate launcher flag bypass",
                lambda: validate_run_bundle(
                    result_path, manifest, source, selected, mapping_repo=mapping_repo, pulse_repo=pulse_repo, candidate_python_runtime=candidate_python_runtime, candidate_node_runtime=None, allow_self_test=True
                ),
                "exact isolated launcher flags",
            )

            ignored_full_repo = temp_root / "full-bundle-ignored-runtime-repo"
            subprocess.run(
                ["git", "clone", "--quiet", str(mapping_repo), str(ignored_full_repo)],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "-C", str(ignored_full_repo), "config", "user.name", "VATE validator self-test"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "-C", str(ignored_full_repo), "config", "user.email", "validator-self-test@example.invalid"],
                check=True,
                capture_output=True,
            )
            ignored_full_origin = "https://validator-self-test.invalid/ignored-runtime.git"
            subprocess.run(
                ["git", "-C", str(ignored_full_repo), "remote", "set-url", "origin", ignored_full_origin],
                check=True,
                capture_output=True,
            )
            ignored_full_mapper = ignored_full_repo / "src" / "mapper.py"
            ignored_full_runtime = ignored_full_repo / "src" / "runtime_impl.py"
            ignored_full_runtime.write_bytes(read_regular_nonempty(ignored_full_mapper))
            ignored_full_mapper.write_text(
                "import runpy\nrunpy.run_path('src/runtime_impl.py', run_name='__main__')\n",
                encoding="utf-8",
            )
            (ignored_full_repo / ".gitignore").write_text("src/runtime_impl.py\n", encoding="utf-8")
            subprocess.run(
                ["git", "-C", str(ignored_full_repo), "add", ".gitignore", "src/mapper.py"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "-C", str(ignored_full_repo), "commit", "--quiet", "-m", "ignored runtime attack"],
                check=True,
                capture_output=True,
            )
            ignored_full_commit = run_git(ignored_full_repo, ["rev-parse", "HEAD"]).decode("ascii").strip()
            require(
                not run_git(ignored_full_repo, ["status", "--porcelain"]).strip(),
                "full-bundle ignored runtime setup must appear clean to ordinary Git status",
            )
            _, ignored_full_export_contract = candidate_commit_files(ignored_full_repo, ignored_full_commit)
            ignored_full_result = copy.deepcopy(positive_result)
            ignored_full_result["implementation"]["source"] = ignored_full_origin
            ignored_full_result["implementation"]["commit"] = ignored_full_commit
            ignored_full_source = ignored_full_result["external_run"]["mapping_source"]
            ignored_full_source["repository"] = ignored_full_origin
            ignored_full_source["commit"] = ignored_full_commit
            mapping_bundle_path = bundle_root / ignored_full_source["bundle_path"]
            original_mapping_bundle_bytes = mapping_bundle_path.read_bytes()
            mapping_bundle_path.write_bytes(read_regular_nonempty(ignored_full_mapper))
            ignored_full_hash = sha256_bytes(mapping_bundle_path.read_bytes())
            ignored_full_source["raw_sha256"] = ignored_full_hash
            ignored_full_result["external_run"]["candidate_execution"]["commit_export"] = ignored_full_export_contract
            for evidence_item in ignored_full_result["external_run"]["attempt"]["evidence"]:
                if evidence_item["kind"] == "mapping-source":
                    evidence_item["raw_sha256"] = ignored_full_hash
            write_self_test_json(result_path, ignored_full_result)
            probe(
                "full bundle ignored untracked runtime with actual Pulse replay",
                lambda: validate_run_bundle(
                    result_path,
                    manifest,
                    source,
                    selected,
                    mapping_repo=ignored_full_repo,
                    pulse_repo=pulse_repo,
                    candidate_python_runtime=candidate_python_runtime,
                    candidate_node_runtime=None,
                    allow_self_test=True,
                ),
                "candidate executable failed",
            )
            mapping_bundle_path.write_bytes(original_mapping_bundle_bytes)
            write_self_test_json(result_path, positive_result)

            untracked_mapping_file = mapping_repo / "untracked-runtime-input.json"
            untracked_mapping_file.write_text("{}\n", encoding="utf-8")
            write_self_test_json(result_path, positive_result)
            probe(
                "mapping repository untracked runtime material",
                lambda: validate_run_bundle(
                    result_path, manifest, source, selected, mapping_repo=mapping_repo, pulse_repo=pulse_repo, candidate_python_runtime=candidate_python_runtime, candidate_node_runtime=None, allow_self_test=True
                ),
                "tracked or untracked non-ignored changes",
            )
            untracked_mapping_file.unlink()

            escaped_input = copy.deepcopy(positive_result)
            escaped_input["external_run"]["case_runs"][0]["pulse_input"]["path"] = "../../etc/passwd"
            write_self_test_json(result_path, escaped_input)
            probe(
                "bundle path escape",
                lambda: validate_run_bundle(
                    result_path, manifest, source, selected, mapping_repo=mapping_repo, pulse_repo=pulse_repo, candidate_python_runtime=candidate_python_runtime, candidate_node_runtime=None, allow_self_test=True
                ),
                "unsafe path segment",
            )

            symlink_input = bundle_root / "pulse-inputs" / "symlink-input.json"
            symlink_input.symlink_to(bundle_root / positive_result["external_run"]["case_runs"][0]["pulse_input"]["path"])
            symlink_result = copy.deepcopy(positive_result)
            symlink_result["external_run"]["case_runs"][0]["pulse_input"]["path"] = symlink_input.relative_to(bundle_root).as_posix()
            write_self_test_json(result_path, symlink_result)
            probe(
                "bundle symlink reference",
                lambda: validate_run_bundle(
                    result_path, manifest, source, selected, mapping_repo=mapping_repo, pulse_repo=pulse_repo, candidate_python_runtime=candidate_python_runtime, candidate_node_runtime=None, allow_self_test=True
                ),
                "regular non-symlink",
            )

            zero_bundle_file = bundle_root / "pulse-inputs" / "zero-input.json"
            zero_bundle_file.write_bytes(b"")
            zero_result = copy.deepcopy(positive_result)
            zero_result["external_run"]["case_runs"][0]["pulse_input"] = {
                "path": zero_bundle_file.relative_to(bundle_root).as_posix(),
                "raw_sha256": sha256_bytes(b""),
            }
            write_self_test_json(result_path, zero_result)
            probe(
                "bundle zero-byte reference",
                lambda: validate_run_bundle(
                    result_path, manifest, source, selected, mapping_repo=mapping_repo, pulse_repo=pulse_repo, candidate_python_runtime=candidate_python_runtime, candidate_node_runtime=None, allow_self_test=True
                ),
                "zero-byte",
            )

            normalized_overrun = copy.deepcopy(positive_result)
            normalized_overrun["results"][1]["outcome"] = "attenuate"
            normalized_overrun["external_run"]["case_runs"][1]["projection"]["projected_vate_outcome"] = "attenuate"
            write_self_test_json(result_path, normalized_overrun)
            probe(
                "overrun normalization",
                lambda: validate_run_bundle(
                    result_path, manifest, source, selected, mapping_repo=mapping_repo, pulse_repo=pulse_repo, candidate_python_runtime=candidate_python_runtime, candidate_node_runtime=None, allow_self_test=True
                ),
                "candidate projection differs",
            )

            raw_ref = positive_result["external_run"]["case_runs"][0]["raw_report"]
            raw_path = bundle_root / raw_ref["path"]
            original_raw_bytes = raw_path.read_bytes()
            fake_raw = load_json_file(raw_path)
            fake_raw["reports"][0]["consistent"] = False
            fake_raw["reports"][0]["failures"] = [
                {"code": "AP2_X402_AMOUNT_MISMATCH", "path": "/synthetic", "message": "Self-consistent fake."}
            ]
            write_self_test_json(raw_path, fake_raw)
            fake_raw_hash = sha256_bytes(raw_path.read_bytes())
            fake_raw_result = copy.deepcopy(positive_result)
            for case_run in fake_raw_result["external_run"]["case_runs"]:
                case_run["raw_report"]["raw_sha256"] = fake_raw_hash
            for item in fake_raw_result["external_run"]["attempt"]["evidence"]:
                if item["kind"] == "raw-pulse-output":
                    item["raw_sha256"] = fake_raw_hash
            write_self_test_json(result_path, fake_raw_result)
            probe(
                "self-consistent fake raw report",
                lambda: validate_run_bundle(
                    result_path, manifest, source, selected, mapping_repo=mapping_repo, pulse_repo=pulse_repo, candidate_python_runtime=candidate_python_runtime, candidate_node_runtime=None, allow_self_test=True
                ),
                "do not exactly match frozen Pulse replay",
            )
            raw_path.write_bytes(original_raw_bytes)

            eligible_ref = positive_result["external_run"]["eligible_input_manifest"]
            eligible_path = bundle_root / eligible_ref["path"]
            original_eligible_bytes = eligible_path.read_bytes()
            receipt_eligible = load_json_file(eligible_path)
            receipt_source = manifest["cases"][0]["inputs"][3]
            receipt_eligible["cases"][0]["inputs"].append(
                {
                    "artifactKey": "admission_receipt",
                    "sourcePath": receipt_source["path"],
                    "sourceRawSha256": receipt_source["raw_sha256"],
                    "bundlePath": positive_result["external_run"]["case_runs"][0]["vate_inputs"][3]["bundle_path"],
                    "bundleRawSha256": receipt_source["raw_sha256"],
                }
            )
            write_self_test_json(eligible_path, receipt_eligible)
            receipt_eligible_hash = sha256_bytes(eligible_path.read_bytes())
            receipt_eligible_result = copy.deepcopy(positive_result)
            receipt_eligible_result["external_run"]["eligible_input_manifest"]["raw_sha256"] = receipt_eligible_hash
            for item in receipt_eligible_result["external_run"]["attempt"]["evidence"]:
                if item["kind"] == "eligible-input-manifest":
                    item["raw_sha256"] = receipt_eligible_hash
            write_self_test_json(result_path, receipt_eligible_result)
            probe(
                "receipt admitted to mapper inputs",
                lambda: validate_run_bundle(
                    result_path, manifest, source, selected, mapping_repo=mapping_repo, pulse_repo=pulse_repo, candidate_python_runtime=candidate_python_runtime, candidate_node_runtime=None, allow_self_test=True
                ),
                "exactly two mapper-eligible inputs",
            )
            eligible_path.write_bytes(original_eligible_bytes)

            mapping_source_path = mapping_repo / "src" / "mapper.py"
            mapping_source_path.write_text(
                "forbidden = 'admission_receipt /expected precomputed_vate'\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "-C", str(mapping_repo), "add", "src/mapper.py"], check=True, capture_output=True)
            subprocess.run(
                ["git", "-C", str(mapping_repo), "commit", "--quiet", "-m", "forbidden source probe"],
                check=True,
                capture_output=True,
            )
            forbidden_commit = run_git(mapping_repo, ["rev-parse", "HEAD"]).decode("ascii").strip()
            mapping_bundle_path = bundle_root / positive_result["external_run"]["mapping_source"]["bundle_path"]
            mapping_bundle_path.write_bytes(read_regular_nonempty(mapping_source_path))
            forbidden_hash = sha256_bytes(mapping_bundle_path.read_bytes())
            forbidden_mapping_result = copy.deepcopy(positive_result)
            forbidden_mapping_result["implementation"]["commit"] = forbidden_commit
            forbidden_mapping_result["external_run"]["mapping_source"]["commit"] = forbidden_commit
            forbidden_mapping_result["external_run"]["mapping_source"]["raw_sha256"] = forbidden_hash
            for item in forbidden_mapping_result["external_run"]["attempt"]["evidence"]:
                if item["kind"] == "mapping-source":
                    item["raw_sha256"] = forbidden_hash
            write_self_test_json(result_path, forbidden_mapping_result)
            probe(
                "mapping source expected/receipt reference",
                lambda: validate_run_bundle(
                    result_path, manifest, source, selected, mapping_repo=mapping_repo, pulse_repo=pulse_repo, candidate_python_runtime=candidate_python_runtime, candidate_node_runtime=None, allow_self_test=True
                ),
                "prohibited expected/receipt/precomputed reference",
            )
            mapping_source_path.write_text(
                mapping_source_path.read_text(encoding="utf-8") + "# tracked dirty probe\n",
                encoding="utf-8",
            )
            write_self_test_json(result_path, forbidden_mapping_result)
            probe(
                "mapping repository tracked dirty",
                lambda: validate_run_bundle(
                    result_path, manifest, source, selected, mapping_repo=mapping_repo, pulse_repo=pulse_repo, candidate_python_runtime=candidate_python_runtime, candidate_node_runtime=None, allow_self_test=True
                ),
                "tracked or untracked non-ignored changes",
            )

    replay_status = "actual frozen-Pulse completed replay included" if pulse_repo is not None else "completed replay deferred until --pulse-repo is supplied"
    print(
        "Pulse external SUT starter self-tests: partial and blocked positives; "
        f"{replay_status}; {sensitivity_matrix_status}; explicit Python/Node runtimes under hostile ambient PATH included; "
        f"{negative_count} fail-closed negative probes: ok"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-repo",
        type=Path,
        default=ROOT,
        help="Git repository containing the fixed VATE commit (default: this checkout)",
    )
    parser.add_argument(
        "--archive-safe",
        action="store_true",
        help=(
            "verify the committed 12-path starter closure from current source-tree bytes "
            "without claiming that the historical Git object was replayed"
        ),
    )
    parser.add_argument(
        "--pulse-repo",
        type=Path,
        help="optional Pulse checkout; HEAD and reviewed bytes must equal the frozen pin",
    )
    parser.add_argument(
        "--mapping-repo",
        type=Path,
        help="candidate mapping Git checkout; mandatory for completed and for any partial/blocked record with completed cases",
    )
    parser.add_argument(
        "--candidate-python-runtime",
        type=Path,
        metavar="ABSOLUTE-PYTHON3-PATH",
        help="operator-selected absolute Python runtime path; required only when the recorded logical command is python3",
    )
    parser.add_argument(
        "--candidate-node-runtime",
        type=Path,
        metavar="ABSOLUTE-NODE-PATH",
        help="operator-selected absolute Node runtime path; required only when the recorded logical command is node",
    )
    parser.add_argument(
        "--strict-json",
        action="append",
        default=[],
        type=Path,
        metavar="PATH",
        help="also reject zero bytes, duplicate keys, non-finite values, and secret-like material in PATH",
    )
    parser.add_argument(
        "--run-bundle",
        type=Path,
        metavar="PULSE-SUT-RESULT.JSON",
        help="validate a completed, partial, or blocked Pulse-side run bundle with the starter-specific closed contract",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run non-elevatable validator self-tests; with --pulse-repo, replay the completed positive through frozen Pulse",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        require(
            not (args.archive_safe and args.self_test),
            "--archive-safe cannot be combined with the history-dependent --self-test lane",
        )
        manifest, source, selected = validate_all(
            args.source_repo.resolve(),
            args.pulse_repo.resolve() if args.pulse_repo else None,
            args.strict_json,
            archive_safe=args.archive_safe,
        )
        if args.run_bundle is not None:
            validate_run_bundle(
                args.run_bundle,
                manifest,
                source,
                selected,
                mapping_repo=args.mapping_repo.resolve() if args.mapping_repo else None,
                pulse_repo=args.pulse_repo.resolve() if args.pulse_repo else None,
                candidate_python_runtime=args.candidate_python_runtime,
                candidate_node_runtime=args.candidate_node_runtime,
            )
        if args.self_test:
            run_self_tests(
                args.source_repo.resolve(),
                args.pulse_repo.resolve() if args.pulse_repo else None,
                args.candidate_python_runtime,
                args.candidate_node_runtime,
            )
        if args.run_bundle is None and not args.self_test:
            require(
                args.candidate_python_runtime is None and args.candidate_node_runtime is None,
                "candidate runtime options require --run-bundle or --self-test",
            )
    except CheckFailure as exc:
        raise SystemExit(f"Pulse external SUT starter validation failed: {exc}") from exc
    pulse_status = "verified" if args.pulse_repo else "not supplied (manifest pin/hash set checked)"
    source_status = (
        "archive-safe current-tree 12-path closure verified; historical Git-object replay not run"
        if args.archive_safe
        else "historical Git-object closure verified"
    )
    run_suffix = "; run bundle contract: ok" if args.run_bundle else ""
    suffix = "; fail-closed self-tests: ok" if args.self_test else ""
    print(
        "Pulse external SUT starter validation: ok "
        f"(VATE {VATE_COMMIT}; corpus 75 cases/212 artifacts; selected closure 3 cases/12 paths; "
        f"source lane {source_status}; Pulse checkout {pulse_status}){run_suffix}{suffix}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
