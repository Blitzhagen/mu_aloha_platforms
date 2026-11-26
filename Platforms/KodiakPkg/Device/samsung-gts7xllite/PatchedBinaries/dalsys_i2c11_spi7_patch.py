#!/usr/bin/env python3
"""
DALSYSDxe v174 patch: populate /dev/i2c11 in-place and recycle the
experimental /dev/i2c4 slot as /dev/SPI7, exactly following
woa-t736b/re/dalsys-format-report.md section 5.3.

The patch is size-neutral.  It must preserve the four v171 USB-host-fix
bytes in DALSYSDxe.efi:
  0x1b6f9=0x14, 0x1b6f6=0x2b, 0x1ba66=0xc4, 0x1ba67=0x89

Default target is the active device binary.  A pre-patch backup is created
next to the target on the first run.
"""
import argparse
import hashlib
import shutil
import struct
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
DEVICE_DIR = SCRIPT_DIR.parent
DEFAULT_TARGET = DEVICE_DIR / "Binaries/QcomPkg/Drivers/DALSYSDxe/DALSYSDxe.efi"

V171_BYTES = {
    0x1B6F9: 0x14,
    0x1B6F6: 0x2B,
    0x1BA66: 0xC4,
    0x1BA67: 0x89,
}

I2C11_CFG = bytes.fromhex(
    "000090000000000000009c000000000000000900010b04000001000000000a0051800100418001000000fc0100000000000000000000000090b802000000000018b902000000000038b9020000000000"
)
SPI7_CFG = bytes.fromhex(
    "000090000000000000009c000000000000000800010700000001000000000600"
    "00000000d1000400e140040001410400f1400400d0000000e000000000010000"
    "f0000000000000000000fc0100000000000000000000000090b8020000000000"
    "f8b802000000000038b9020000000000"
)

assert len(I2C11_CFG) == 80
assert len(SPI7_CFG) == 112

# (offset, bytes, description)
PATCHES = [
    (0x466F8, I2C11_CFG, "/dev/i2c11 80-byte config"),
    (0x46F28, SPI7_CFG, "/dev/SPI7 112-byte config over recycled copies"),
    (0x1CBE0, bytes.fromhex("2f6465762f5350493700"), "rename /dev/i2c4 -> /dev/SPI7"),
    (0x1C740, bytes.fromhex("25852814"), "DJB2 hash /dev/SPI7 = 0x14288525"),
    (0x1CBCC, bytes.fromhex("42000000"), "stream payload struct index 66"),
    (0x4C0E8, bytes.fromhex("80af"), "reloc config+0x58 -> 0x46f80"),
    (0x4C0EA, bytes.fromhex("88af"), "reloc config+0x60 -> 0x46f88"),
    (0x4C0EC, bytes.fromhex("90af"), "reloc config+0x68 -> 0x46f90"),
]


def djb2(data: bytes) -> int:
    h = 0x1505
    for c in data:
        h = (h * 0x21 + c) & 0xFFFFFFFF
    return h


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check_v171(data: bytearray, label: str) -> None:
    bad = [(hex(o), data[o], v) for o, v in V171_BYTES.items() if data[o] != v]
    if bad:
        detail = ", ".join(f"{o}: got 0x{got:02x}, want 0x{want:02x}" for o, got, want in bad)
        raise SystemExit(f"ERROR: v171 USB-fix byte mismatch {label}: {detail}")


def verify(data: bytearray) -> list[str]:
    messages = []
    check_v171(data, "after patch")

    # Direct patch-byte verification.
    for off, patch, desc in PATCHES:
        end = off + len(patch)
        if data[off:end] != patch:
            raise SystemExit(f"ERROR: patch verification failed at 0x{off:x} ({desc})")

    # Format-level verification from dalsys-format-report.md section 8.
    blob, struct_tbl, numdevs, dev_tbl = struct.unpack_from("<QQQQ", data, 0x7FB0)
    if numdevs != 15:
        raise SystemExit(f"ERROR: expected 15 DAL devices, got {numdevs}")

    def cstr(addr: int) -> bytes:
        return data[addr:data.index(b"\0", addr)]

    def device(name: bytes):
        want = djb2(name)
        rows = []
        for i in range(numdevs):
            ent = dev_tbl + i * 0x28
            name_ptr, h, stream_off = struct.unpack_from("<QII", data, ent)
            if h == want and cstr(name_ptr) == name:
                rows.append((i, name_ptr, h, stream_off))
        if len(rows) != 1:
            raise SystemExit(f"ERROR: expected exactly one {name!r}, got {len(rows)}")
        return rows[0]

    def struct_ptr(index: int) -> int:
        size, reserved, ptr = struct.unpack_from("<IIQ", data, struct_tbl + index * 16)
        if size != 8 or reserved != 0:
            raise SystemExit(f"ERROR: unexpected struct-table entry {index}: size={size}, reserved={reserved}")
        return ptr

    def stream_struct_index(stream_off: int) -> int:
        pos = blob + stream_off
        word, payload, endmark = struct.unpack_from("<III", data, pos)
        if word != 0x12800079 or endmark != 0xFF00FF00:
            raise SystemExit(f"ERROR: bad config stream at blob+0x{stream_off:x}: {word:08x} {payload:08x} {endmark:08x}")
        return payload

    i2c_idx, _, i2c_hash, i2c_stream = device(b"/dev/i2c11")
    spi_idx, _, spi_hash, spi_stream = device(b"/dev/SPI7")
    if i2c_hash != 0x9AB73F82:
        raise SystemExit(f"ERROR: /dev/i2c11 hash mismatch: 0x{i2c_hash:08x}")
    if spi_hash != 0x14288525:
        raise SystemExit(f"ERROR: /dev/SPI7 hash mismatch: 0x{spi_hash:08x}")
    if stream_struct_index(i2c_stream) != 6:
        raise SystemExit("ERROR: /dev/i2c11 stream does not reference struct index 6")
    if stream_struct_index(spi_stream) != 66:
        raise SystemExit("ERROR: /dev/SPI7 stream does not reference struct index 66")
    if struct_ptr(6) != 0x466F8:
        raise SystemExit("ERROR: struct index 6 does not point at 0x466f8")
    if struct_ptr(66) != 0x46F28:
        raise SystemExit("ERROR: struct index 66 does not point at 0x46f28")

    i2c_base, i2c_common, i2c_off = struct.unpack_from("<QQI", data, 0x466F8)
    spi_base, spi_common, spi_off = struct.unpack_from("<QQI", data, 0x46F28)
    if i2c_base + i2c_off != 0x990000 or i2c_common != 0x9C0000:
        raise SystemExit(f"ERROR: /dev/i2c11 physical address decode mismatch: base={i2c_base:x} common={i2c_common:x} off={i2c_off:x}")
    if spi_base + spi_off != 0x980000 or spi_common != 0x9C0000:
        raise SystemExit(f"ERROR: /dev/SPI7 physical address decode mismatch: base={spi_base:x} common={spi_common:x} off={spi_off:x}")

    messages.append(f"/dev/i2c11: device[{i2c_idx}] stream=blob+0x{i2c_stream:x} struct=6 cfg=0x466f8 phys=0x990000")
    messages.append(f"/dev/SPI7:  device[{spi_idx}] stream=blob+0x{spi_stream:x} struct=66 cfg=0x46f28 phys=0x980000")
    messages.append("v171 USB-fix bytes preserved")
    messages.append("relocs 0x4c0e8..0x4c0ec = 80 af 88 af 90 af")
    return messages


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", type=Path, default=DEFAULT_TARGET)
    ap.add_argument("--backup", type=Path, default=None, help="backup path (default: <target>.v173-pre-i2c11-spi7-bak)")
    ap.add_argument("--verify-only", action="store_true")
    args = ap.parse_args()

    target = args.target.resolve()
    backup = (args.backup or target.with_name(target.name + ".v173-pre-i2c11-spi7-bak")).resolve()
    data = bytearray(target.read_bytes())
    before_hash = sha256(data)
    print(f"target: {target}")
    print(f"before: size=0x{len(data):x} sha256={before_hash}")
    check_v171(data, "before patch")

    if args.verify_only:
        for msg in verify(data):
            print("OK:", msg)
        return 0

    if not backup.exists():
        shutil.copy2(target, backup)
        print(f"backup: created {backup}")
    else:
        print(f"backup: exists {backup}")

    for off, patch, desc in PATCHES:
        data[off:off + len(patch)] = patch
        print(f"patched 0x{off:x} +{len(patch)}: {desc}")

    for msg in verify(data):
        print("OK:", msg)

    target.write_bytes(data)
    after_hash = sha256(data)
    print(f"after:  size=0x{len(data):x} sha256={after_hash}")
    print(f"md5:    {hashlib.md5(data).hexdigest()}")
    if before_hash == after_hash:
        print("note: input already contained the complete patch (idempotent no-op)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
