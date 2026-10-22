#!/usr/bin/env python3
"""Prepare standard-library bytecode in a disposable GitHub Actions interpreter."""

import compileall
import importlib.util
import json
import os
from pathlib import Path
import py_compile
import sys
import sysconfig
import time


EXCLUDED = frozenset(("site-packages", "dist-packages", "test", "tests", "__pycache__"))


def stdlib_sources(root):
    """Exclude dependencies, test fixtures and all symlinked paths."""
    for directory, names, files in os.walk(root, followlinks=False):
        folder = Path(directory)
        names[:] = sorted(name for name in names
                          if name not in EXCLUDED and not (folder / name).is_symlink())
        for name in sorted(files):
            path = folder / name
            if path.suffix == ".py" and not path.is_symlink() and path.is_file():
                yield path


def prepare(root):
    if sys.pycache_prefix is not None:
        raise ValueError("an alternate bytecode prefix is not supported")
    sources = list(stdlib_sources(root))
    if not sources:
        raise ValueError("standard library contains no source files")
    # Check every output before compiling any file.
    for source in sources:
        cache = Path(importlib.util.cache_from_source(str(source), optimization=""))
        if cache.is_symlink() or cache.parent.is_symlink():
            raise ValueError("bytecode output must not use a symlink")
        if not cache.is_relative_to(root):
            raise ValueError("bytecode output is outside the standard library")
    started = time.perf_counter()
    for source in sources:
        if not compileall.compile_file(str(source), quiet=1, optimize=0,
                                       invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP):
            raise RuntimeError("standard-library compilation failed: " + str(source))
    return {"stdlib": str(root), "source_files": len(sources),
            "seconds": time.perf_counter() - started}


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("This helper is restricted to disposable GitHub Actions runners.")
    if sys.prefix != sys.base_prefix:
        raise SystemExit("Use the setup-python interpreter, not a virtual environment.")
    root = Path(sysconfig.get_path("stdlib")).resolve(strict=True)
    repository = Path(__file__).resolve().parents[1]
    if (not root.is_relative_to(Path(sys.base_prefix).resolve(strict=True))
            or root.is_relative_to(repository) or repository.is_relative_to(root)):
        raise SystemExit("Standard library must be in the interpreter, outside the repository.")
    print(json.dumps(prepare(root), sort_keys=True))


if __name__ == "__main__":
    main()
