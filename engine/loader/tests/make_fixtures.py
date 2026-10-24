#!/usr/bin/env python3
"""Build tiny structural APK/CRX and WASI smoke fixtures for the CI gate.

The APK contains a valid empty DEX file and a binary Android XML manifest.
It has no launchable activity, so CI inspects it but never installs it.
The CRX fixture deliberately has no publisher signature; CI tests container
validation only and never installs it in Chromium.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import struct
import sys
import zipfile
import zlib

ROOT = pathlib.Path(__file__).resolve().parent
FIXTURES = ROOT / "fixtures"


def chunk(kind: int, header: bytes, body: bytes, header_size: int | None = None) -> bytes:
    size = 8 + len(header) + len(body)
    return struct.pack("<HHI", kind, header_size or 8 + len(header), size) + header + body


def axml_manifest() -> bytes:
    strings = ["manifest", "package", "com.example.nexus.smoke"]
    encoded = bytearray()
    offsets = []
    for value in strings:
        raw = value.encode("utf-8")
        offsets.append(len(encoded))
        encoded.extend((len(value), len(raw)))
        encoded.extend(raw)
        encoded.append(0)
    table = b"".join(struct.pack("<I", n) for n in offsets)
    string_header = struct.pack("<IIIII", len(strings), 0, 0x100, 28 + len(table), 0)
    string_chunk = struct.pack("<HHI", 1, 28, 28 + len(table) + len(encoded)) + string_header + table + encoded

    node_header = struct.pack("<II", 1, 0xFFFFFFFF)
    attr_ext = struct.pack("<IIHHHHHH", 0xFFFFFFFF, 0, 20, 20, 1, 0, 0, 0)
    attr = struct.pack("<IIIHBBI", 0xFFFFFFFF, 1, 2, 8, 0, 3, 2)
    start = chunk(0x0102, node_header + attr_ext, attr, header_size=16)
    end = chunk(0x0103, node_header + struct.pack("<II", 0xFFFFFFFF, 0), b"", header_size=16)
    payload = string_chunk + start + end
    return struct.pack("<HHI", 3, 8, 8 + len(payload)) + payload


def empty_dex() -> bytes:
    header = bytearray(112)
    header[:8] = b"dex\n035\0"
    struct.pack_into("<IIII", header, 32, 128, 112, 0x12345678, 0)
    struct.pack_into("<II", header, 48, 0, 0)
    struct.pack_into("<II", header, 52, 112, 0)
    # Eight zero-sized ID/class tables, each with zero offset.
    struct.pack_into("<IIIIIIII", header, 56, 0, 0, 0, 0, 0, 0, 0, 0)
    struct.pack_into("<IIII", header, 88, 0, 0, 0, 0)
    struct.pack_into("<II", header, 104, 16, 112)
    map_list = struct.pack("<IHHII", 1, 0, 0, 1, 0)
    data = header + map_list
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(data[12:]) & 0xFFFFFFFF)
    return bytes(data)


def wasm_command() -> bytes:
    # Valid WASI command module with an empty exported _start function.
    return bytes.fromhex(
        "0061736d01000000"  # magic + version
        "010401600000"      # one () -> () function type
        "03020100"          # one function of type 0
        "070a01065f73746172740000"  # export _start
        "0a040102000b"      # function body: no locals; end
    )


def make(output: pathlib.Path) -> None:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    output.mkdir(parents=True, exist_ok=True)
    manifest = axml_manifest()
    (FIXTURES / "minimal-manifest.axml").write_bytes(manifest)
    with zipfile.ZipFile(output / "minimal.apk", "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr("classes.dex", empty_dex())
    wasm = wasm_command()
    (output / "wasi-exit-zero.wasm").write_bytes(wasm)
    with zipfile.ZipFile(output / "extension.zip", "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("manifest.json", json.dumps({"manifest_version": 3, "name": "Nexus CI structural fixture", "version": "1.0.0"}))
    zip_bytes = (output / "extension.zip").read_bytes()
    # CRX3 envelope with empty structural protobuf fields. The fixture is
    # unsigned on purpose and therefore must never be installable.
    crx_header = b"\x12\x00\x1a\x00"
    (output / "unsigned-extension.crx").write_bytes(b"Cr24" + struct.pack("<II", 3, len(crx_header)) + crx_header + zip_bytes)


if __name__ == "__main__":
    destination = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "target" / "runtime-fixtures"
    make(destination)
    print(f"Generated structural fixtures in {destination}")
