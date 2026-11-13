"""Connect authenticated policy leases to the ordinary Python verifier."""
import hashlib
from pathlib import Path
import sys

import authority_store as store_module
import snapshot as s

b, c, jwt = s.b, s.c, s.jwt
_source = None
try:
    _source = Path(__file__).read_bytes()
    LOADED_SOURCE_SHA256 = (hashlib.sha256(_source).hexdigest() if hasattr(sys, "_getframe")
        and sys._getframe().f_code == compile(_source, sys._getframe().f_code.co_filename,
            "exec", dont_inherit=True, optimize=sys.flags.optimize) else None)
except (OSError, SyntaxError, ValueError):
    # Import remains available; identity-dependent entry points reject None.
    LOADED_SOURCE_SHA256 = None
del _source


class ManagedAuthorityVerifier:
    _loaded_source_path = Path(__file__).resolve()
    _loaded_source_sha256 = LOADED_SOURCE_SHA256

    def __init__(self, *, source, verifier_id, policy, state_store, execute,
                 max_runtime_token_age_seconds, max_caller_token_age_seconds):
        s.class_identity(self, sys.modules[__name__])
        s.need(type(source) is store_module.AuthorityStore, "AUTHORITY_SOURCE_INVALID")
        self.source = source
        self._source_identity = source.configuration_id()
        configuration = b.object_hash({"source": self._source_identity,
            "managed_source": s.module_identity(sys.modules[__name__])})
        backend = source.verifier.backend
        max_age = source.verifier.selection.max_snapshot_age_seconds
        runtime = jwt.RuntimeJwtVerifier(expected_profile=jwt.PROFILE, node=backend.node,
            node_sha256=backend.node_sha256, trust_policy_provider=source.runtime_policy,
            max_token_age_seconds=max_runtime_token_age_seconds, max_policy_age_seconds=max_age,
            timeout_seconds=backend.timeout)
        caller = c.CallerJwtAuthorizer(expected_profile=c.PROFILE, authority_id=source.verifier.selection.issuer,
            node=backend.node, node_sha256=backend.node_sha256, authority_policy_provider=source.authority_policy,
            max_token_age_seconds=max_caller_token_age_seconds, max_policy_age_seconds=max_age,
            timeout_seconds=backend.timeout, authority_source_configuration_id=configuration)
        boundary = b.DispatchBoundary(execute=execute, clock=source.now)
        self._core = b.core.VateVerifier(verifier_id=verifier_id, policy=policy,
            state_store=state_store, dispatch_boundary=boundary,
            runtime_evidence_verifier=runtime.as_runtime_verifier(), caller_authorizer=caller.as_caller_authorizer())

    def _check(self):
        s.class_identity(self, sys.modules[__name__])
        s.need(self.source.configuration_id() == self._source_identity, "AUTHORITY_CONFIGURATION_CHANGED")

    def admit(self, admission_request, *, original, evidence_artifacts, caller_proof, require_new_permit=False):
        self._check()
        with self._core.dispatch_boundary.update(), self.source.lease():
            return self._core.admit(admission_request, original=original, evidence_artifacts=evidence_artifacts,
                caller_proof=caller_proof, require_new_permit=require_new_permit, now=self.source.now())

    def dispatch(self, admission, *, caller_proof):
        self._check()
        with self._core.dispatch_boundary.update(), self.source.lease():
            return self._core.dispatch(admission, caller_proof=caller_proof)

    def restore_admission(self, request_id):
        self._check()
        with self._core.dispatch_boundary.update(), self.source.lease():
            return self._core.restore_admission(request_id)

    def dispatch_status(self, request_id):
        self._check()
        return self._core.dispatch_status(request_id)
