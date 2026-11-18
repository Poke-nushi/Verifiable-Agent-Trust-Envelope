"""Load the bundled helpers from this distribution only."""
from pathlib import Path
import importlib.util
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference/execution-evidence-demo"))
import demo_contract as demo
import admission as original_admission


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


crypto = load("handoff_constrained_crypto", "reference/post-admission-revocation-sample/sample/contract.py")
fixture_crypto = load("handoff_fixture_crypto", "reference/minimal-al2-demo/trust_envelope_demo.py")
