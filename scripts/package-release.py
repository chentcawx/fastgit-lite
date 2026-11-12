#!/usr/bin/env python3
"""Build a clean distributable zip for a FastGit Lite release.

Usage:
    python scripts/package-release.py
    python scripts/package-release.py --version 2.1.5

Guards:
  * binary must be PE32 / machine 0x14C (i386) / subsystem 2 (WINDOWS_GUI)
  * config/appsettings.json must keep the safe default ProxyBind=127.0.0.1
  * no CA private key, certificate, log or runtime cache is ever bundled

The CA is intentionally NOT shipped: fastgithub.exe generates its own on first
run, and install-ca.ps1 starts the exe briefly when the CA is missing.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import struct
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PREFIX = "fastgit-lite"
USER_SCRIPTS = (
    "install-ca.ps1",
    "regen-ca.ps1",
    "install-silent-task.ps1",
    "verify-pe.ps1",
)
FORBIDDEN = re.compile(r"(?i)(\.key|\.pem|\.cer)$|^logs/|^cacert/")


def read_version() -> str:
    text = (ROOT / "Cargo.toml").read_text(encoding="utf-8-sig")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    if not match:
        raise SystemExit("Cargo.toml: version not found")
    return match.group(1)


def pe_info(data: bytes) -> tuple[int, int, int]:
    if data[:2] != b"MZ":
        raise SystemExit("binary is not a PE file (missing MZ header)")
    offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[offset:offset + 4] != b"PE\0\0":
        raise SystemExit("binary is not a PE file (missing PE signature)")
    machine = struct.unpack_from("<H", data, offset + 4)[0]
    optional = offset + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    subsystem = struct.unpack_from("<H", data, optional + 68)[0]
    return machine, magic, subsystem


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", default=None, help="defaults to Cargo.toml version")
    args = parser.parse_args()
    version = args.version or read_version()

    candidates = (
        ROOT / "target" / "i686-pc-windows-msvc" / "release" / "fastgithub.exe",
        ROOT / "dist" / "fastgithub.exe",
    )
    binary = next((path for path in candidates if path.is_file()), None)
    if binary is None:
        raise SystemExit("release binary not found; run scripts/build-x86.cmd first")

    exe = binary.read_bytes()
    machine, magic, subsystem = pe_info(exe)
    if (machine, magic, subsystem) != (0x14C, 0x10B, 2):
        raise SystemExit(
            f"unexpected PE: machine=0x{machine:X}, magic=0x{magic:X}, subsystem={subsystem}"
        )

    config = (ROOT / "config" / "appsettings.json").read_text(encoding="utf-8-sig")
    if not re.search(r'"ProxyBind"\s*:\s*"127\.0\.0\.1"', config):
        raise SystemExit(
            "refusing to package: config/appsettings.json ProxyBind must be 127.0.0.1"
        )

    readme = (ROOT / "README.md").read_bytes()
    files: dict[str, bytes] = {"fastgithub.exe": exe, "README.md": readme}

    config_root = ROOT / "config"
    for path in sorted(config_root.rglob("*")):
        if path.is_file():
            files[f"config/{path.relative_to(config_root).as_posix()}"] = path.read_bytes()
    for name in USER_SCRIPTS:
        files[f"scripts/{name}"] = (ROOT / "scripts" / name).read_bytes()

    for name in files:
        if FORBIDDEN.search(name):
            raise SystemExit(f"refusing to package sensitive/runtime file: {name}")

    sums = "".join(
        f"{sha256(data)}  {name}\n" for name, data in sorted(files.items())
    )
    files["SHA256SUMS.txt"] = sums.encode("utf-8")

    out_dir = ROOT / "dist"
    out_dir.mkdir(exist_ok=True)
    zip_path = out_dir / f"fastgit-lite-v{version}-win-x86.zip"
    sums_path = out_dir / f"fastgit-lite-v{version}-SHA256SUMS.txt"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(files.items()):
            archive.writestr(f"{PREFIX}/{name}", data)
    sums_path.write_text(sums, encoding="utf-8")
    (out_dir / "README.md").write_bytes(readme)

    print(f"binary : {binary.relative_to(ROOT)}")
    print(f"PE     : machine=0x{machine:X} (i386), magic=0x{magic:X} (PE32), "
          f"subsystem={subsystem} (WINDOWS_GUI)")
    print(f"bundle : {zip_path.name}  {zip_path.stat().st_size:,} bytes")
    print(f"sha256 : {sha256(zip_path.read_bytes())}")
    print(f"sums   : {sums_path.name}")
    print(f"entries: {len(files)}")
    for name in sorted(files):
        print(f"  {PREFIX}/{name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
