# Validation of this source distribution

Measured on 2026-10-24. Every environment below passed **69 behavior tests,
7 distribution/relocation tests, and 8 CLI scenarios**. Each also passed
fresh-process query/export/reader checks for a completed operation, a partial
operation (`unknown`), and a refusal (`not_accepted`).

| Platform | CPython | SQLite | OpenSSL | Result |
| --- | --- | --- | --- | --- |
| macOS arm64 | 3.11.14 | 3.54.0 | 4.0.3 | passed |
| macOS arm64 | 3.12.15 | 3.53.1 | 4.0.3 | passed |
| macOS arm64 | 3.13.3 | 3.49.1 | 4.0.3 | passed |
| macOS arm64 | 3.14.8 | 3.54.0 | 4.0.3 | passed |
| Linux x86_64 (VM) | 3.11.15 | 3.40.1 | 3.0.20 | passed |
| Linux x86_64 (VM) | 3.12.15 | 3.40.1 | 3.0.22 | passed |
| Linux x86_64 (VM) | 3.14.8 | 3.40.1 | 3.0.22 | passed |

## What was executed

Each job extracted the ZIP into a new folder containing spaces, created a
fresh virtual environment with `--without-pip`, and ran the bundled code.
The tests used actual OpenSSL signatures with disposable keys, actual SQLite
transactions, and actual local file writes. Saved results were not substituted
for those operations. Both `WAL` and `DELETE` journal modes were exercised by
the behavior tests; the eight-scenario demo used `WAL`.

The three recovery checks compared the file bytes and acceptance/native-result
row counts before and after query/export/reader. The observations stayed
unchanged. The exported evidence, selection, and anchor were also copied to a
separate folder and read there, without reopening the live database.

The seven distribution tests cover an intact moved copy, missing/changed files,
source symlinks, manifest shape/inventory, running through a source-directory
alias, leftover importable modules/packages/bytecode/native modules, and an
external `PYTHONHOME` that must not affect the crash-worker subprocess.

Linux ran in cached x86_64 containers inside a local QEMU VM. Image IDs were
fixed, image pulls and networking were disabled, the container root and mounted
input archive were read-only, and extracted source, keys, and effects were in
temporary storage. No original repository checkout was mounted into the
containers. The macOS jobs used the installed arm64 interpreters.

## Source correspondence

All seven environments used the same 12 Python source files included in this
distribution. Their raw hashes were checked against each job.
The complete seven-environment matrix was rerun after the admission time-boundary
fix, including the earlier historical-status conflict and malformed-authorization
fixes. README and validation-result updates followed that run; the 12 Python
source files were unchanged.
`SOURCE-MANIFEST.json` lists the delivered files. The original public reference
modules and license match the VATE commit named in that manifest.

## Unexecuted scope

- Linux Python 3.13 was not tested.
- Intel macOS, Linux arm64, PyPy, and other Python minor versions were not tested.
  Windows is outside this sample's POSIX file-lock implementation.
- Remote authorities/providers, receipt-inbox integration, power loss, live
  database relocation/repair, independent time/completeness proof, and external
  operator trials were not performed.

These results establish the stated local behavior and distribution checks.
They do not establish production readiness, general PKI support, or general
compatibility. See [CONTRACT.md](CONTRACT.md) for the decision boundary.
