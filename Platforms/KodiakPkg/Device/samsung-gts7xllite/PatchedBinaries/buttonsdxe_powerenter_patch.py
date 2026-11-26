#!/usr/bin/env python3
"""
ButtonsDxe (stock T736B, v147-base fb0e2015) Power-key ENTER patch.

ConvertEfiKeyCode composites scan = r_volup<<0 | r_voldown<<1 | r_pwr<<7.
Power alone therefore yields scan 0x0080 (SCAN_VOLUME_UP) - useless in UEFI
menus/HII/grub (ENTER is UnicodeChar 0x0D, ScanCode 0).

Patch: at 0x13878 replace `strh w9, [sp, 8]` with a branch to the .text
tail cave (vaddr 0x177e8). Cave logic:
    cmp w9, 0x80
    b.ne store
    movz w9, 0xd, lsl 16   ; ScanCode=0, UnicodeChar=0x0D in the u32
store:
    str w9, [sp, 8]        ; full-width store safe: composite only uses bits
                           ; 0..7, upper half was pre-zeroed (str wzr,[sp,8])
    b 0x1387c              ; back to cbz w9
"""
import struct, sys, hashlib

SRC = 'stock-v147.efi'
DST = 'ButtonsDxe.v17x-powerenter.efi'

data = bytearray(open(SRC, 'rb').read())

def foff(vaddr):
    return vaddr - 0x10000

def a64_b(src_va, dst_va):
    # unconditional branch: 0x14000000 | ((dst-src)/4) & 0x03ffffff
    imm = (dst_va - src_va) // 4
    assert (dst_va - src_va) % 4 == 0
    return struct.pack('<I', 0x14000000 | (imm & 0x03ffffff))

def a64_cmp_w(reg, imm):
    # cmp wn, #imm -> subs wzr, wn, #imm : 0x7100001f base? use encoding:
    # subs wzr, wn, imm12: sf=0 op=1 S=1 -> 0x71000000 | imm12<<10 | rn<<5 | 31
    assert 0 <= imm < 4096
    return struct.pack('<I', 0x71000000 | (imm << 10) | (reg << 5) | 0x1f)

def a64_bne(src_va, dst_va):
    imm = (dst_va - src_va) // 4
    return struct.pack('<I', 0x54000000 | ((imm & 0x7ffff) << 5) | 0x1)  # cond 0001 = NE

def a64_movz_w(reg, imm16, shift):
    # movz wd, #imm, lsl #shift: 0x52800000 | hw<<21 | imm16<<5 | rd ; hw = shift/16
    return struct.pack('<I', 0x52800000 | ((shift//16) << 21) | ((imm16 & 0xffff) << 5) | reg)

def a64_str_w(rt, rn, byteoff):
    # str wt, [xn, #imm] unsigned offset, imm12 scaled by 4 for 32-bit stores
    assert byteoff % 4 == 0
    imm12 = byteoff // 4
    return struct.pack('<I', 0xB9000000 | ((imm12 & 0xfff) << 10) | (rn << 5) | rt)

# sanity: verify original bytes at patch site
PATCH_SITE = 0x13878
orig = struct.unpack('<I', data[foff(PATCH_SITE):foff(PATCH_SITE)+4])[0]
print(f"orig insn @0x13878: {hex(orig)}")
# strh w9, [sp, 8]: strh encoding 0x79000000 | imm12<<10 | rn<<5 | rt ; rn=sp(31) rt=9
expect = 0x79000000 | ((8//2) << 10) | (31 << 5) | 9
print(f"expected strh w9,[sp,8]: {hex(expect)}")
if orig != expect:
    print("!! WARNING: original instruction mismatch, aborting")
    sys.exit(1)

CAVE = 0x177e8
# verify cave is zero
cave_off = foff(CAVE)
assert all(b == 0 for b in data[cave_off:cave_off+0x40]), "cave not zero!"

# build cave code
cave = b''
# cmp w9, 0x80
cave += a64_cmp_w(9, 0x80)
# b.ne +12 (skip the movz) -> to store
cave += a64_bne(CAVE+4, CAVE+12)
# movz w9, 0xd, lsl 16
cave += a64_movz_w(9, 0xd, 16)
# str w9, [sp, 8]  (rn=31=sp)
cave += a64_str_w(9, 31, 8)
# b 0x1387c
cave += a64_b(CAVE+16, 0x1387c)

print("cave len:", len(cave), "bytes:", cave.hex())

# write cave
data[cave_off:cave_off+len(cave)] = cave
# patch site: b cave
data[foff(PATCH_SITE):foff(PATCH_SITE)+4] = a64_b(PATCH_SITE, CAVE)

open(DST, 'wb').write(bytes(data))
print("wrote", DST, "md5:", hashlib.md5(bytes(data)).hexdigest())
