#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Reconstruct the exact pinned SEV source plus bounded P-384 API adapters.

This is source provenance and patch-scope evidence, not cryptographic execution
or constant-time acceptance. No advisory exception is granted here.
"""
import hashlib
import json
from pathlib import Path
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
REVISION = "a966d06d9bf0e68afe2733e7bfbf278fd7fd65b5"
TREE = "636379a232b75ad3c0f2a079acc1788dc13a920f"
ARCHIVE_SHA256 = "6fa9d33543b5ea51b153d2fbe01111eba821f4dc92a7949d83056b2d947eb2b5"
LICENSE_SHA256 = "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"
VENDOR = Path("third_party/rust/vendor/sev-8.0.0")


def replace_exact(source, old, new, count=1):
    if source.count(old) != count:
        raise ValueError("SEV upstream adapter input changed")
    return source.replace(old, new)


def permitted_source(name, raw):
    if name == "Cargo.toml":
        return replace_exact(raw, b'p384 = { version = "0.13", optional = true }',
                             b'p384 = { version = "=0.14.0", optional = true }')
    if name == "src/certs/snp/ecdsa/mod.rs":
        return replace_exact(raw, b'''        let r_big_endian: Vec<u8> = signature.r.iter().copied().take(48).rev().collect();
        let s_big_endian: Vec<u8> = signature.s.iter().copied().take(48).rev().collect();

        use p384::elliptic_curve::generic_array::GenericArray;
        p384::ecdsa::Signature::from_scalars(
            GenericArray::clone_from_slice(&r_big_endian),
            GenericArray::clone_from_slice(&s_big_endian),
        )''', b'''        let r_big_endian: [u8; 48] = core::array::from_fn(|index| signature.r[47 - index]);
        let s_big_endian: [u8; 48] = core::array::from_fn(|index| signature.s[47 - index]);

        p384::ecdsa::Signature::from_scalars(r_big_endian, s_big_endian)''')
    if name == "src/firmware/guest/types/snp.rs":
        raw = replace_exact(raw,
                            b'let base_digest = sha2::Sha384::new_with_prefix(measurable_bytes);',
                            b'let base_digest = sha2::Sha384::digest(measurable_bytes);', 2)
        raw = replace_exact(raw, b'use p384::ecdsa::signature::DigestVerifier;',
                            b'use p384::ecdsa::signature::hazmat::PrehashVerifier;', 2)
        return replace_exact(raw, b'verifying_key.verify_digest(base_digest, &sig)',
                             b'verifying_key.verify_prehash(&base_digest, &sig)', 2)
    return raw


def original_files(root=ROOT):
    archive = root / "third_party/rust/sources/sev-8.0.0-a966d06.tar.gz"
    if hashlib.sha256(archive.read_bytes()).hexdigest() != ARCHIVE_SHA256:
        raise ValueError("SEV archive identity changed")
    files = {}
    with tarfile.open(archive) as source:
        for member in source.getmembers():
            if member.isdir():
                continue
            name = member.name.removeprefix("sev-8.0.0/")
            if (not member.isfile() or not member.name.startswith("sev-8.0.0/")
                    or Path(name).is_absolute() or ".." in Path(name).parts or name in files):
                raise ValueError("invalid SEV source archive entry")
            files[name] = source.extractfile(member).read()
    if hashlib.sha256(files["LICENSE"]).hexdigest() != LICENSE_SHA256:
        raise ValueError("SEV upstream license changed")
    return files


def expected_files(root=ROOT):
    return {name: permitted_source(name, raw) for name, raw in original_files(root).items()}


def verify(files, root=ROOT):
    if files != expected_files(root):
        raise ValueError("SEV exceeds the approved P-384 API adapter scope")


def verify_repository(root=ROOT):
    vendor = root / VENDOR
    if any(path.is_symlink() for path in vendor.rglob("*")):
        raise ValueError("SEV vendor symlink is forbidden")
    verify({path.relative_to(vendor).as_posix(): path.read_bytes()
            for path in vendor.rglob("*") if path.is_file()}, root)


def verify_metadata(metadata, fuzz, root=ROOT):
    """Require fixed registry arithmetic and prohibit the retired crypto graph."""
    registry = "registry+https://github.com/rust-lang/crates.io-index"
    fixed = {"crypto-bigint": "0.7.9", "p384": "0.14.0", "ecdsa": "0.17.0",
             "elliptic-curve": "0.14.3", "primeorder": "0.14.0"}
    packages = metadata["packages"]
    for name, version in fixed.items():
        matches = [package for package in packages if package["name"] == name]
        if len(matches) != 1 or matches[0]["version"] != version or matches[0]["source"] != registry:
            raise ValueError("fixed SEV P-384 registry graph changed")
    matches = [package for package in packages if package["name"] == "sev"]
    if (len(matches) != 1 or matches[0]["version"] != "8.0.0" or matches[0]["source"] is not None
            or matches[0]["manifest_path"] != str(root / VENDOR / "Cargo.toml")):
        raise ValueError("SEV path source changed")
    if any(package["name"] in {"sev", *fixed} for package in fuzz["packages"]):
        raise ValueError("SEV P-384 graph unexpectedly entered fuzz")
    for graph in (metadata, fuzz):
        matches = [package for package in graph["packages"] if package["name"] == "ctutils"]
        if (len(matches) != 1 or matches[0]["version"] != "0.4.5" or matches[0]["source"] is not None
                or matches[0]["manifest_path"] != str(root / "third_party/rust/vendor/ctutils-0.4.5/Cargo.toml")):
            raise ValueError("current ctutils fixed path source changed")


def main(arguments=()):
    verify_repository()
    if arguments:
        if len(arguments) != 2:
            raise ValueError("expected root and fuzz metadata paths")
        values = []
        for name in arguments:
            with Path(name).open("rb") as stream:
                raw = stream.read(8 * 1024 * 1024 + 1)
            if len(raw) > 8 * 1024 * 1024:
                raise ValueError("SEV graph metadata is oversized")
            values.append(json.loads(raw))
        verify_metadata(*values)
    print("PASS  exact SEV a966d06 source, unchanged license and bounded P-384 API adapters; no advisory waiver")


if __name__ == "__main__":
    main(sys.argv[1:])
