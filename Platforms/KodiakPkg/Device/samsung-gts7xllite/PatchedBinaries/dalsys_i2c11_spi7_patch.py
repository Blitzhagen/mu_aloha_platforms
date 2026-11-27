#!/usr/bin/env python3
"""
DALSYSDxe v178 patch: populate /dev/i2c11 in-place while preserving the
v61 /dev/i2c4 and /dev/i2c9 nodes required by Samsung's stock SM5714
drivers.  v174-v177 incorrectly recycled /dev/i2c4 as /dev/SPI7; that
made MuicDxe fail i2c_open(4) with i2c_status 28 and hit its unconditional
Sm5714MuicLib.c line-445 assert.  v178 therefore keeps the i2c11 config
and the v176 PE relocation-metadata repair, but restores the i2c4 device
name/hash, the v61 stream struct indexes (i2c4 -> 5, i2c9 -> 4), the two
now-unreferenced copied config structs, and their original relocation
entries.  /dev/SPI7 is intentionally not populated by this revision.

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

I2C11_CFG_FILE_OFFSET = 0x466F8
FINAL_RELOC_BLOCK_FILE_OFFSET = 0x4C0E0
FINAL_RELOC_PAGE_RVA = 0x46000
FINAL_RELOC_BLOCK_SIZE = 0x1C
RELOC_DIR_SIZE_FILE_OFFSET = 0xF0C
RELOC_SECTION_VSIZE_FILE_OFFSET = 0xFB8
RELOC_DIR_SIZE = 0x50FC
FINAL_RELOC_ENTRIES = (
    0xAF60, 0xAF68, 0xAF70,  # unreferenced i2c4-copy cfg clock pointers 0x46f60/68/70
    0xAFB0, 0xAFB8, 0xAFC0,  # unreferenced i2c9-copy cfg clock pointers 0x46fb0/b8/c0
    0xA730, 0xA738, 0xA740,  # i2c11 clock pointers 0x46730/38/40
    0x0000,                  # type-0 alignment pad
)

I2C11_CFG = bytes.fromhex(
    "000090000000000000009c000000000000000900010b04000000010000000a0051800100418001000000fc0100000000000000000000000090b802000000000018b902000000000038b9020000000000"
)
# v61/v173 state of the two 80-byte copied i2c4/i2c9 config structs at
# 0x46f28/0x46f78.  They are unreferenced because the v61 streams point at
# stock struct indexes 5/4, but preserving them avoids carrying v174's
# overlapping SPI7 experiment forward as dead corrupted data.
I2C4_I2C9_COPY_CFGS = bytes.fromhex(
    "000090000000000000009c000000000000c00800000403000000010000000300"
    "d1800100c18001000000fc01000000000000000000000000f8cb010000000000"
    "60cc01000000000010cf0100000000000000a000000000000000ac0000000000"
    "0000080001090000000001000000080011820100018201000000fc0100000000"
    "000000000000000020cc01000000000088cc01000000000010cf010000000000"
)

assert len(I2C11_CFG) == 80
assert len(I2C4_I2C9_COPY_CFGS) == 160

# (offset, bytes, description)
PATCHES = [
    (RELOC_DIR_SIZE_FILE_OFFSET, bytes.fromhex("fc500000"), "base relocation directory size 0x50fc"),
    (RELOC_SECTION_VSIZE_FILE_OFFSET, bytes.fromhex("fc500000"), ".reloc section VirtualSize 0x50fc"),
    (0x466F8, I2C11_CFG, "/dev/i2c11 80-byte config"),
    (0x46F28, I2C4_I2C9_COPY_CFGS, "restore unreferenced i2c4/i2c9 copied configs"),
    (0x1CBE0, bytes.fromhex("2f6465762f6932633400"), "restore /dev/i2c4 device name"),
    (0x1C740, bytes.fromhex("34193414"), "DJB2 hash /dev/i2c4 = 0x14341934"),
    (0x1CBCC, bytes.fromhex("05000000"), "restore /dev/i2c4 stream payload struct index 5"),
    (0x4C0E4, bytes.fromhex("1c000000"), "final relocation block size 0x1c (nine DIR64 entries + pad)"),
    (0x4C0E8, bytes.fromhex("60af"), "reloc i2c4-copy cfg+0x38 -> 0x46f60"),
    (0x4C0EA, bytes.fromhex("68af"), "reloc i2c4-copy cfg+0x40 -> 0x46f68"),
    (0x4C0EC, bytes.fromhex("70af"), "reloc i2c4-copy cfg+0x48 -> 0x46f70"),
    (0x4C0F4, bytes.fromhex("30a738a740a70000"), "reloc i2c11 clock pointers 0x46730/0x46738/0x46740 + align pad"),
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


def pe32plus_layout(data: bytearray) -> dict:
    """Return the PE32+ layout facts needed for relocation validation."""
    if len(data) < 0x400:
        raise SystemExit("ERROR: file too small for a PE32+ image")
    peoff = struct.unpack_from("<I", data, 0x3C)[0]
    if data[peoff:peoff + 4] != b"PE\0\0":
        raise SystemExit(f"ERROR: missing PE signature at 0x{peoff:x}")
    machine, num_sections, _timestamp, _symptr, _nsyms, opt_size, _chars = struct.unpack_from("<HHIIIHH", data, peoff + 4)
    optoff = peoff + 24
    magic = struct.unpack_from("<H", data, optoff)[0]
    if magic != 0x20B:
        raise SystemExit(f"ERROR: expected PE32+ optional header magic 0x20b, got 0x{magic:x}")
    num_rva_sizes = struct.unpack_from("<I", data, optoff + 108)[0]
    if num_rva_sizes <= 5:
        raise SystemExit(f"ERROR: PE image has no base-relocation directory (NumberOfRvaAndSizes={num_rva_sizes})")
    reloc_dir_offset = optoff + 112 + 5 * 8
    reloc_rva, reloc_size = struct.unpack_from("<II", data, reloc_dir_offset)
    section_table = optoff + opt_size
    sections = []
    for index in range(num_sections):
        off = section_table + index * 40
        name = bytes(data[off:off + 8]).rstrip(b"\0").decode("ascii", "replace")
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, off + 8)
        sections.append({
            "index": index,
            "name": name,
            "header_offset": off,
            "vsize_offset": off + 8,
            "vsize": vsize,
            "va": va,
            "rawsize": rawsize,
            "rawptr": rawptr,
        })
    return {
        "machine": machine,
        "peoff": peoff,
        "optoff": optoff,
        "num_sections": num_sections,
        "reloc_dir_offset": reloc_dir_offset,
        "reloc_dir_size_offset": reloc_dir_offset + 4,
        "reloc_rva": reloc_rva,
        "reloc_size": reloc_size,
        "sections": sections,
    }


def rva_to_file_offset(sections: list[dict], rva: int) -> int:
    for sec in sections:
        # The file-backed part of a section can extend up to SizeOfRawData;
        # the loader-visible part is additionally constrained by VirtualSize.
        span = max(sec["vsize"], sec["rawsize"])
        if sec["va"] <= rva < sec["va"] + span:
            return sec["rawptr"] + (rva - sec["va"])
    raise SystemExit(f"ERROR: RVA 0x{rva:x} is not inside any PE section")


def verify(data: bytearray) -> list[str]:
    messages = []
    check_v171(data, "after patch")

    # Direct patch-byte verification.
    for off, patch, desc in PATCHES:
        end = off + len(patch)
        if data[off:end] != patch:
            raise SystemExit(f"ERROR: patch verification failed at 0x{off:x} ({desc})")

    # The stock i2c3/i2c8 configs use mode/enable flags 00 00 01 00 at
    # cfg+0x18..+0x1b.  v174 mistakenly carried the one at +0x19; I2CDxe
    # reads +0x1a.  Verify the exact v175 pattern.
    flag_bytes = bytes(data[I2C11_CFG_FILE_OFFSET + 0x18:I2C11_CFG_FILE_OFFSET + 0x1C])
    if flag_bytes != b"\x00\x00\x01\x00":
        raise SystemExit(f"ERROR: /dev/i2c11 cfg+0x18..+0x1b mismatch: {flag_bytes.hex()}, want 00000100")

    # Parse, rather than merely byte-compare, the PE base-relocation metadata.
    # v175 enlarged the final block from 0x14 to 0x1c bytes but left both the
    # relocation directory and .reloc VirtualSize at their old end 0x4c0f4.
    # EDK2 BasePeCoff.c rejects such an image because the final block's
    # RelocEnd is beyond RelocBaseOrg+RelocDir->Size; in addition the section
    # loader copies only min(VirtualSize, SizeOfRawData), so bytes after the
    # old 0x50f4-byte .reloc VirtualSize would not even be present in memory.
    layout = pe32plus_layout(data)
    if layout["reloc_dir_size_offset"] != RELOC_DIR_SIZE_FILE_OFFSET:
        raise SystemExit(
            f"ERROR: relocation-directory size field is at 0x{layout['reloc_dir_size_offset']:x}, "
            f"patch constant expects 0x{RELOC_DIR_SIZE_FILE_OFFSET:x}"
        )
    if layout["reloc_rva"] != 0x47000:
        raise SystemExit(f"ERROR: unexpected relocation directory RVA 0x{layout['reloc_rva']:x}, want 0x47000")
    if layout["reloc_size"] != RELOC_DIR_SIZE:
        raise SystemExit(f"ERROR: relocation directory size is 0x{layout['reloc_size']:x}, want 0x{RELOC_DIR_SIZE:x}")

    reloc_sections = [s for s in layout["sections"] if s["va"] <= layout["reloc_rva"] < s["va"] + max(s["vsize"], s["rawsize"])]
    if len(reloc_sections) != 1:
        raise SystemExit(f"ERROR: expected exactly one section containing relocation RVA 0x47000, got {len(reloc_sections)}")
    reloc_sec = reloc_sections[0]
    if reloc_sec["name"] != ".reloc":
        raise SystemExit(f"ERROR: relocation directory is in section {reloc_sec['name']!r}, want '.reloc'")
    if reloc_sec["vsize_offset"] != RELOC_SECTION_VSIZE_FILE_OFFSET:
        raise SystemExit(
            f"ERROR: .reloc VirtualSize field is at 0x{reloc_sec['vsize_offset']:x}, "
            f"patch constant expects 0x{RELOC_SECTION_VSIZE_FILE_OFFSET:x}"
        )
    if reloc_sec["vsize"] != RELOC_DIR_SIZE:
        raise SystemExit(f"ERROR: .reloc VirtualSize is 0x{reloc_sec['vsize']:x}, want 0x{RELOC_DIR_SIZE:x}")
    # This is the exact copy-length rule in EDK2 BasePeCoff.c: zero or
    # overlarge VirtualSize means SizeOfRawData, otherwise VirtualSize wins.
    edk2_copy_len = reloc_sec["rawsize"] if reloc_sec["vsize"] == 0 or reloc_sec["vsize"] > reloc_sec["rawsize"] else reloc_sec["vsize"]
    reloc_sec_off = layout["reloc_rva"] - reloc_sec["va"]
    if reloc_sec_off + layout["reloc_size"] > edk2_copy_len:
        raise SystemExit(
            f"ERROR: relocation directory end exceeds EDK2-copied .reloc bytes: "
            f"secoff=0x{reloc_sec_off:x} size=0x{layout['reloc_size']:x} copylen=0x{edk2_copy_len:x}"
        )

    reloc_file_start = rva_to_file_offset(layout["sections"], layout["reloc_rva"])
    reloc_file_end = reloc_file_start + layout["reloc_size"]
    if reloc_file_end > len(data):
        raise SystemExit("ERROR: relocation directory extends beyond end of file")
    blocks = []
    pos = reloc_file_start
    while pos < reloc_file_end:
        page, bsz = struct.unpack_from("<II", data, pos)
        if bsz == 0:
            raise SystemExit(f"ERROR: zero-sized relocation block at file offset 0x{pos:x}")
        if bsz < 8 or (bsz & 1):
            raise SystemExit(f"ERROR: malformed relocation block at file offset 0x{pos:x}: size 0x{bsz:x}")
        block_end = pos + bsz
        if block_end > reloc_file_end:
            raise SystemExit(
                f"ERROR: relocation block at file offset 0x{pos:x} ends at 0x{block_end:x}, "
                f"beyond directory end 0x{reloc_file_end:x} (EDK2 RETURN_LOAD_ERROR condition)"
            )
        entry_count = (bsz - 8) // 2
        entries_here = struct.unpack_from(f"<{entry_count}H", data, pos + 8) if entry_count else ()
        blocks.append((pos, page, bsz, entries_here))
        pos = block_end
    if pos != reloc_file_end:
        raise SystemExit(f"ERROR: relocation chain ended at 0x{pos:x}, directory end is 0x{reloc_file_end:x}")
    if not blocks or blocks[-1][0] != FINAL_RELOC_BLOCK_FILE_OFFSET:
        got = hex(blocks[-1][0]) if blocks else "none"
        raise SystemExit(f"ERROR: final relocation block is at {got}, want 0x{FINAL_RELOC_BLOCK_FILE_OFFSET:x}")

    # The final block covers the 0x46000 page and must contain nine DIR64
    # entries plus one type-0 alignment pad.  In particular the three entries
    # for 0x46730/0x46738/0x46740 make the i2c11 clock pointers runtime-relocated;
    # without them i2c_open dereferences raw RVAs such as 0x2b890 and faults.
    _final_off, page_rva, block_size, entries = blocks[-1]
    if page_rva != FINAL_RELOC_PAGE_RVA or block_size != FINAL_RELOC_BLOCK_SIZE:
        raise SystemExit(
            f"ERROR: final relocation block header mismatch: page=0x{page_rva:x} size=0x{block_size:x}, "
            f"want page=0x{FINAL_RELOC_PAGE_RVA:x} size=0x{FINAL_RELOC_BLOCK_SIZE:x}"
        )
    if entries != FINAL_RELOC_ENTRIES:
        got = " ".join(f"{e:04x}" for e in entries)
        want = " ".join(f"{e:04x}" for e in FINAL_RELOC_ENTRIES)
        raise SystemExit(f"ERROR: final relocation entries mismatch: {got}, want {want}")
    relocated = []
    for entry in entries[:9]:
        reloc_type = entry >> 12
        target = FINAL_RELOC_PAGE_RVA + (entry & 0x0FFF)
        if reloc_type != 10:
            raise SystemExit(f"ERROR: relocation target 0x{target:x} has type {reloc_type}, want DIR64 type 10")
        relocated.append(target)
    for target in (0x46730, 0x46738, 0x46740):
        if target not in relocated:
            raise SystemExit(f"ERROR: missing DIR64 relocation for i2c11 clock pointer at 0x{target:x}")

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
    i2c4_idx, _, i2c4_hash, i2c4_stream = device(b"/dev/i2c4")
    i2c9_idx, _, i2c9_hash, i2c9_stream = device(b"/dev/i2c9")
    if i2c_hash != 0x9AB73F82:
        raise SystemExit(f"ERROR: /dev/i2c11 hash mismatch: 0x{i2c_hash:08x}")
    if i2c4_hash != 0x14341934:
        raise SystemExit(f"ERROR: /dev/i2c4 hash mismatch: 0x{i2c4_hash:08x}")
    if i2c9_hash != 0x14341939:
        raise SystemExit(f"ERROR: /dev/i2c9 hash mismatch: 0x{i2c9_hash:08x}")
    if stream_struct_index(i2c_stream) != 6:
        raise SystemExit("ERROR: /dev/i2c11 stream does not reference struct index 6")
    if stream_struct_index(i2c4_stream) != 5:
        raise SystemExit("ERROR: /dev/i2c4 stream does not reference stock struct index 5")
    if stream_struct_index(i2c9_stream) != 4:
        raise SystemExit("ERROR: /dev/i2c9 stream does not reference stock struct index 4")
    if struct_ptr(6) != 0x466F8:
        raise SystemExit("ERROR: struct index 6 does not point at 0x466f8")
    if struct_ptr(5) != 0x2B9D0:
        raise SystemExit("ERROR: stock struct index 5 does not point at 0x2b9d0")
    if struct_ptr(4) != 0x2B980:
        raise SystemExit("ERROR: stock struct index 4 does not point at 0x2b980")
    if struct_ptr(66) != 0x46F28 or struct_ptr(67) != 0x46F78:
        raise SystemExit("ERROR: dead copied-config struct entries 66/67 do not point at 0x46f28/0x46f78")

    spi7_hash = djb2(b"/dev/SPI7")
    spi7_rows = []
    for i in range(numdevs):
        ent = dev_tbl + i * 0x28
        name_ptr, h, _stream_off = struct.unpack_from("<QII", data, ent)
        if h == spi7_hash or cstr(name_ptr) == b"/dev/SPI7":
            spi7_rows.append(i)
    if spi7_rows:
        raise SystemExit(f"ERROR: /dev/SPI7 must be absent in v178, found device rows {spi7_rows}")

    i2c_base, i2c_common, i2c_off = struct.unpack_from("<QQI", data, 0x466F8)
    i2c4_base, i2c4_common, i2c4_off = struct.unpack_from("<QQI", data, 0x2B9D0)
    i2c9_base, i2c9_common, i2c9_off = struct.unpack_from("<QQI", data, 0x2B980)
    if i2c_base + i2c_off != 0x990000 or i2c_common != 0x9C0000:
        raise SystemExit(f"ERROR: /dev/i2c11 physical address decode mismatch: base={i2c_base:x} common={i2c_common:x} off={i2c_off:x}")
    if i2c4_base + i2c4_off != 0x984000 or i2c4_common != 0x9C0000:
        raise SystemExit(f"ERROR: /dev/i2c4 physical address decode mismatch: base={i2c4_base:x} common={i2c4_common:x} off={i2c4_off:x}")
    if i2c9_base + i2c9_off != 0x888000 or i2c9_common != 0x8C0000:
        raise SystemExit(f"ERROR: /dev/i2c9 physical address decode mismatch: base={i2c9_base:x} common={i2c9_common:x} off={i2c9_off:x}")

    messages.append(f"/dev/i2c11: device[{i2c_idx}] stream=blob+0x{i2c_stream:x} struct=6 cfg=0x466f8 phys=0x990000")
    messages.append(f"/dev/i2c4:  device[{i2c4_idx}] stream=blob+0x{i2c4_stream:x} struct=5 cfg=0x2b9d0 phys=0x984000")
    messages.append(f"/dev/i2c9:  device[{i2c9_idx}] stream=blob+0x{i2c9_stream:x} struct=4 cfg=0x2b980 phys=0x888000")
    messages.append("/dev/SPI7:  absent (v178 restores stock SM5714 buses; SPI7 recycling reverted)")
    messages.append("v171 USB-fix bytes preserved")
    messages.append("i2c11 cfg+0x18..+0x1b = 00 00 01 00")
    messages.append("reloc directory size and .reloc VirtualSize = 0x50fc; chain ends exactly at directory end")
    messages.append("final reloc block page=0x46000 size=0x1c entries include DIR64 0x46730/0x46738/0x46740")
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
