#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Verify the complete, approved ctutils 0.4.4 -> Rust 1.85 compatibility surface."""

import hashlib
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_SHA256 = "12218662ccac37d9714f2191252553d67585b97df8c839cbe49e0bde278dc865"
CHOICE_METHODS = (
    "to_bool", "to_u8", "to_bool_vartime", "to_u8_vartime",
    "to_u8_mask", "to_u16_mask", "to_u32_mask", "to_u64_mask", "to_u128_mask",
    "select_i64", "select_u8", "select_u16", "select_u32", "select_u64", "select_u128",
    "from_u128_lt", "from_u128_le",
)
OPTION_METHODS = ("expect_ref", "expect_copied", "into_option_copied")
CURRENT_VERSION = "0.4.5"
CURRENT_ARCHIVE_SHA256 = "38d28fb6aa7dd680b3ffd1a3e64e115c177bdba63c0ae7f9cd48129ff05c4fa0"


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError("upstream compatibility-contract input changed")
    return source.replace(old, new)


def permitted_source(name, raw):
    """Only these reviewed substitutions are permitted; no algorithm changes."""
    if name in ("Cargo.toml", "Cargo.toml.orig"):
        return replace_once(raw, b'rust-version = "1.87"', b'rust-version = "1.85"')
    if name not in ("src/choice.rs", "src/ct_option.rs", "src/traits/ct_gt.rs", "src/traits/ct_lt.rs"):
        return raw
    source = raw.decode()
    methods = CHOICE_METHODS if name == "src/choice.rs" else OPTION_METHODS if name == "src/ct_option.rs" else ()
    for method in methods:
        source = replace_once(source, f"pub const fn {method}(", f"pub fn {method}(")
    if name == "src/choice.rs":
        source = replace_once(source, "const fn from_u128_lt_halves(", "fn from_u128_lt_halves(")
        source = replace_once(source, "Self::from_u64_nz(x.cast_unsigned() ^ y.cast_unsigned()).not()",
                              "Self::from_u64_nz(x as u64 ^ y as u64).not()")
        source = replace_once(source, "    pub const fn from_i64_eq(",
                              "    #[allow(clippy::cast_sign_loss)] // Rust 1.85: same-width bit-preserving casts.\n    pub const fn from_i64_eq(")
        source = replace_once(source, "self.select_u64(a.cast_unsigned(), b.cast_unsigned())\n            .cast_signed()",
                              "self.select_u64(a as u64, b as u64) as i64")
        source = replace_once(source, "    pub fn select_i64(",
                              "    #[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)] // Same-width bits.\n    pub fn select_i64(")
        for upper, lower in (("LT", "lt"), ("LE", "le")):
            source = replace_once(source, f"const {upper}: Choice =", f"let {lower}: Choice =")
            source = replace_once(source, f"assert!({upper}.to_bool());", f"assert!({lower}.to_bool());")
    elif name == "src/ct_option.rs":
        source = replace_once(source, "const fn select_vartime(", "fn select_vartime(")
    else:
        op = Path(name).stem
        source = replace_once(source, f"a.cast_unsigned().{op}(&b.cast_unsigned())",
                              f"(a as u8).{op}(&(b as u8))")
    return source.encode()


def expected_files():
    archive = ROOT / "third_party/rust/sources/ctutils-0.4.4.crate"
    if hashlib.sha256(archive.read_bytes()).hexdigest() != ARCHIVE_SHA256:
        raise ValueError("ctutils official archive identity changed")
    with tarfile.open(archive) as source:
        return {member.name.removeprefix("ctutils-0.4.4/"):
                permitted_source(member.name.removeprefix("ctutils-0.4.4/"), source.extractfile(member).read())
                for member in source.getmembers() if member.isfile()}


def verify(files):
    if files != expected_files():
        raise ValueError("ctutils exceeds the approved Rust 1.85 compatibility scope")


def current_expected_files():
    """The current compiler uses unmodified fixed upstream source, including const API."""
    prefix = f"ctutils-{CURRENT_VERSION}/"
    archive = ROOT / f"third_party/rust/sources/ctutils-{CURRENT_VERSION}.crate"
    if hashlib.sha256(archive.read_bytes()).hexdigest() != CURRENT_ARCHIVE_SHA256:
        raise ValueError("current ctutils official archive identity changed")
    with tarfile.open(archive) as source:
        files = {}
        for member in source.getmembers():
            if member.isdir():
                continue
            name = member.name.removeprefix(prefix)
            if (not member.isfile() or not member.name.startswith(prefix)
                    or Path(name).is_absolute() or ".." in Path(name).parts or name in files):
                raise ValueError("invalid current ctutils archive entry")
            files[name] = source.extractfile(member).read()
        return files


def verify_current(files):
    if files != current_expected_files():
        raise ValueError("ctutils exceeds the approved unmodified 0.4.5 source scope")


def main():
    vendor = ROOT / "third_party/rust/vendor/ctutils-0.4.4"
    verify({str(path.relative_to(vendor)): path.read_bytes()
            for path in vendor.rglob("*") if path.is_file()})
    print("PASS  ctutils exact fixed 0.4.4 source plus 20 documented const reductions and same-width casts")
    vendor = ROOT / f"third_party/rust/vendor/ctutils-{CURRENT_VERSION}"
    if any(path.is_symlink() for path in vendor.rglob("*")):
        raise ValueError("current ctutils vendor symlink is forbidden")
    verify_current({str(path.relative_to(vendor)): path.read_bytes()
                    for path in vendor.rglob("*") if path.is_file()})
    print("PASS  current ctutils is unmodified upstream 0.4.5; historical 0.4.4 compatibility source retained")


if __name__ == "__main__":
    main()
