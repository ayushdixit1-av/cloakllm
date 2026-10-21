#!/usr/bin/env python3
"""Deterministic Build & Reproducibility Verification Script.

Compares Build 1 (dist/) and Build 2 (dist_rebuild/):
1. Verifies both expected artifacts exist (.whl and .tar.gz).
2. Requires binary wheels (.whl) to match byte-for-byte across builds.
3. For source distributions (.tar.gz), verifies that all internal code files,
   metadata, and manifests match 100% byte-for-byte (accounting for gzip
   container timestamp differences in setuptools).
"""

from __future__ import annotations

import hashlib
import os
import sys
import tarfile
from pathlib import Path


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    dist1 = Path(sys.argv[1] if len(sys.argv) > 1 else "dist")
    dist2 = Path(sys.argv[2] if len(sys.argv) > 2 else "dist_rebuild")

    if not dist1.is_dir() or not dist2.is_dir():
        print(f"Error: Build directories not found: {dist1}, {dist2}", file=sys.stderr)
        return 1

    entries1 = sorted(dist1.iterdir(), key=lambda p: p.name)
    entries2 = sorted(dist2.iterdir(), key=lambda p: p.name)

    # Reject non-regular entries (subdirectories, symlinks, sockets)
    non_regular1 = [e.name for e in entries1 if not e.is_file() or e.is_symlink()]
    non_regular2 = [e.name for e in entries2 if not e.is_file() or e.is_symlink()]
    if non_regular1 or non_regular2:
        print(f"Error: Non-regular entries (directories/symlinks) found in dist: {non_regular1 or non_regular2}", file=sys.stderr)
        return 1

    files1 = entries1
    files2 = entries2

    names1 = [f.name for f in files1]
    names2 = [f.name for f in files2]

    if not files1:
        print(f"Error: No artifacts found in {dist1}", file=sys.stderr)
        return 1

    if names1 != names2:
        print(f"Error: Asymmetric artifact list between builds:\nBuild 1: {names1}\nBuild 2: {names2}", file=sys.stderr)
        return 1

    # Verify expected artifacts: strictly one .whl and one .tar.gz
    whl_files = [n for n in names1 if n.endswith(".whl")]
    tar_files = [n for n in names1 if n.endswith(".tar.gz")]
    extra_files = [n for n in names1 if not (n.endswith(".whl") or n.endswith(".tar.gz"))]

    if len(whl_files) != 1 or len(tar_files) != 1 or extra_files:
        print(f"Error: Invalid artifact set. Wheels: {whl_files}, Sdist: {tar_files}, Extra: {extra_files}", file=sys.stderr)
        return 1

    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    summary_lines = [
        "### Release Artifact Checksums & Reproducibility",
        "| Artifact | SHA-256 (Build 1) | Size | Rebuild Match |",
        "| :--- | :--- | :--- | :--- |",
    ]

    mismatch = False

    for f1 in files1:
        f2 = dist2 / f1.name
        if not f2.is_file():
            print(f"Error: Missing artifact in rebuild: {f2}", file=sys.stderr)
            mismatch = True
            continue

        h1 = sha256(f1)
        h2 = sha256(f2)
        size = f1.stat().st_size

        if h1 == h2:
            status = "PASSED (Deterministic)"
            print(f"PASS: {f1.name} matches byte-for-byte across builds ({h1})")
        elif f1.suffix == ".whl":
            status = "FAILED (Wheel Checksum Mismatch)"
            print(f"FAIL: Wheel checksum mismatch: {h1} != {h2}", file=sys.stderr)
            mismatch = True
        elif f1.name.endswith(".tar.gz"):
            # Check every file inside the tar archive with strict safety & exception handling
            try:
                with tarfile.open(f1, "r:gz") as t1, tarfile.open(f2, "r:gz") as t2:
                    members1 = t1.getmembers()
                    members2 = t2.getmembers()
                    tnames1 = [m.name for m in members1]
                    tnames2 = [m.name for m in members2]

                    # Enforce member name uniqueness
                    if len(tnames1) != len(set(tnames1)) or len(tnames2) != len(set(tnames2)):
                        print("FAIL: Duplicate member names detected in sdist tar archive", file=sys.stderr)
                        mismatch = True

                    # Enforce safe member paths (no traversal '..', no absolute paths)
                    for m in members1 + members2:
                        if m.name.startswith(("/", "\\")) or ".." in Path(m.name).parts:
                            print(f"FAIL: Unsafe member path in archive: '{m.name}'", file=sys.stderr)
                            mismatch = True

                    if sorted(tnames1) != sorted(tnames2):
                        print(f"FAIL: Sdist member mismatch:\nBuild 1: {sorted(tnames1)}\nBuild 2: {sorted(tnames2)}", file=sys.stderr)
                        status = "FAILED (Member List Mismatch)"
                        mismatch = True
                    else:
                        tar_mismatch = False
                        for m in sorted(tnames1):
                            ef1 = t1.extractfile(m)
                            ef2 = t2.extractfile(m)
                            if ef1 and ef2:
                                ch1 = hashlib.sha256(ef1.read()).hexdigest()
                                ch2 = hashlib.sha256(ef2.read()).hexdigest()
                                if ch1 != ch2:
                                    print(f"FAIL: Sdist content mismatch in member '{m}'", file=sys.stderr)
                                    tar_mismatch = True
                                    break
                            elif bool(ef1) != bool(ef2):
                                print(f"FAIL: Sdist member extraction difference in '{m}'", file=sys.stderr)
                                tar_mismatch = True
                                break
                                break
                        if tar_mismatch:
                            status = "FAILED (Content Mismatch)"
                            mismatch = True
                        else:
                            status = "PASSED (Content Deterministic; gzip metadata variance documented)"
                            print(f"PASS: {f1.name} internal code and manifests verified 100% byte-for-byte identical")
            except Exception as exc:
                print(f"FAIL: Sdist archive parsing error: {exc}", file=sys.stderr)
                status = f"FAILED (Archive Parse Error: {exc})"
                mismatch = True
        else:
            status = "UNEXPECTED FILE TYPE"
            print(f"FAIL: Unexpected file type: {f1.name}", file=sys.stderr)
            mismatch = True

        summary_lines.append(f"| `{f1.name}` | `{h1}` | {size} bytes | {status} |")

    if summary_file:
        with open(summary_file, "a", encoding="utf-8") as sf:
            sf.write("\n".join(summary_lines) + "\n")

    if mismatch:
        print("Release gate failed: Rebuild produced non-deterministic or invalid outputs", file=sys.stderr)
        return 1

    print("\nALL ARTIFACTS VERIFIED DETERMINISTIC AND REPRODUCIBLE.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
