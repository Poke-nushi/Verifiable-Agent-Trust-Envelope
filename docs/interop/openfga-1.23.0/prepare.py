"""Prepare the two pinned source trees for the OpenFGA 1.23.0 comparison."""

import argparse
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
from zipfile import ZipFile


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
VATE_COMMIT = "fac9d94c4c8093fdfb32491413794c9ac0a6411f"
TRIAL = "oauth-first-hop-revocation-trial-20261110"
ZIP_BYTES = 45_473
ZIP_SHA256 = "f34795280c075cb6bf45220afeab13bac58c1c9b76f0610b69fa335776876926"
TRIAL_FILES = (
    "run_chain.py", "test_chain.py", "setup_native.py", "MODEL.json",
    "GRANTS.json", "EXPECTED.json", "NATIVE-RELEASES.json",
)


def prepare(trial_zip, output):
    if os.path.lexists(output):
        raise FileExistsError(f"Choose a new source directory: {output}")
    with trial_zip.open("rb") as archive:
        raw = archive.read(ZIP_BYTES + 1)
    if len(raw) != ZIP_BYTES or hashlib.sha256(raw).hexdigest() != ZIP_SHA256:
        raise ValueError("The trial ZIP differs from the November 10 package")

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent) as temporary:
        tmp = Path(temporary)
        tree = tmp / "source"
        trial = tree / "trial"
        trial.mkdir(parents=True)
        with ZipFile(io.BytesIO(raw)) as package:
            for name in TRIAL_FILES:
                (trial / name).write_bytes(package.read(f"{TRIAL}/{name}"))

        tar_path = tmp / "vate.tar"
        subprocess.run(["git", "-C", str(REPO), "archive", "--format=tar",
                        "--output", str(tar_path), VATE_COMMIT], check=True)
        with tarfile.open(tar_path) as archive:
            archive.extractall(tree / "vate", filter="data")
        subprocess.run(["patch", "-f", "-F", "0", "-p1", "-i", str(HERE / "native-pins.patch")],
                       cwd=tree, check=True)
        if os.path.lexists(output):
            raise FileExistsError(f"The destination appeared during preparation: {output}")
        tree.rename(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trial-zip", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    prepare(args.trial_zip, args.output.absolute())
