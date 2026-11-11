"""Check the distributed files against the local raw-byte manifest."""
import hashlib
import json
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent


def main():
    manifest = json.loads((ROOT / "PACKAGE-MANIFEST.json").read_text(encoding="utf-8"))
    seen = set()
    for row in manifest["files"]:
        relative = PurePosixPath(row["path"])
        if (relative.is_absolute() or ".." in relative.parts
                or str(relative) != row["path"] or str(relative) in seen):
            raise ValueError("invalid manifest path")
        seen.add(str(relative))
        path = ROOT.joinpath(*relative.parts)
        if not path.resolve().is_relative_to(ROOT) or path.is_symlink():
            raise ValueError(f"nonlocal file: {relative}")
        data = path.read_bytes()
        if len(data) != row["bytes"] or hashlib.sha256(data).hexdigest() != row["sha256"]:
            raise ValueError(f"file mismatch: {relative}")
    print(f"Package bytes matched: {len(seen)} files")


if __name__ == "__main__":
    main()
