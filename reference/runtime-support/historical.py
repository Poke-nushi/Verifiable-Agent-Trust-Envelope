"""Explicit, fixed historical replay support; never selected by incoming data."""
import hashlib
import types
import json
from pathlib import Path

COMMIT = "e845a6a8c118135e8e6a3e8de5a692f8536670c4"
MANIFEST_SHA256 = "d8a9f438d07818caa83de681311e217af4b8d8dae808c2999f30f0ee72d05056"


def historical_root(repository):
    root = Path(repository).resolve(strict=True) / "reference/historical-runtime/e845a6a8"
    manifest_path = root / "MANIFEST.json"
    if manifest_path.is_symlink():
        raise ValueError("historical manifest must be a regular file")
    raw = manifest_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != MANIFEST_SHA256:
        raise ValueError("historical manifest changed")
    manifest = json.loads(raw)
    if manifest["source_commit"] != COMMIT:
        raise ValueError("historical source commit changed")
    for name, expected in manifest["files"].items():
        path = root / name
        if any(part.is_symlink() for part in (path, *path.parents)):
            raise ValueError("historical source must not use symlinks: " + name)
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError("historical source changed: " + name)
    return root


def historical_api(repository):
    root = historical_root(repository)
    path = root / "reference/recipient-assessment/vate_recipient.py"
    module = types.ModuleType("_vate_e845a6a8_api")
    module.__file__ = str(path)
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != "f04249301cc7861e8854db2b0464f5f1fabaee3eae64969ba082eec11a702c93":
        raise ValueError("historical API changed while loading")
    exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
    return module, root
