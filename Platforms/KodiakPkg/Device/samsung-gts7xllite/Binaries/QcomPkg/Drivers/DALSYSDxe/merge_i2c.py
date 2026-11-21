#!/usr/bin/env python3
# Merge /dev/i2c4 + /dev/i2c9 DAL nodes from bundled DALSYSDxe.efi into stock.
# Strategy: relocate dev-table + struct-table into .text free zone (0x1c530-0x1d000),
# put copied config structs in .data tail (0x46f28+), append new .reloc blocks.
import struct, sys, hashlib

STOCK = 'DALSYSDxe.efi'
BUND  = 'DALSYSDxe.efi.bundled'
OUT   = 'DALSYSDxe.efi.i2cmerged'

d = bytearray(open(STOCK, 'rb').read())
b = open(BUND, 'rb').read()

# ---------------- source data from bundled ----------------
CFG4_SRC = b[0x2ec20:0x2ec20+80]          # i2c4 config struct
CFG9_SRC = b[0x2ec70:0x2ec70+80]          # i2c9 config struct
TBL48    = b[0x2eb38:0x2eb38+72]          # shared freq/div table (+0x48)

# ---------------- new layout in .text free zone ----------------
NEWTBL    = 0x1c530                      # 15 * 0x28 dev entries
NEWSTRUCT = 0x1c788                      # 68 * 0x10 records (= NEWTBL + 0x258)
STREAM4   = 0x1cbc8                      # 12B prop stream
STREAM9   = 0x1cbd4                      # 12B
STR4      = 0x1cbe0                      # '/dev/i2c4\0'
STR9      = 0x1cbea                      # '/dev/i2c9\0'
WRAP0     = 0x1cbf8                      # 5 qwords
WRAP1     = 0x1cc20                      # 5 qwords
SEARR     = 0x1cc48                      # 16 qwords
CLKSTR    = 0x1ccc8                      # clock-name strings packed here
VAL4 = STREAM4 - 0x1bf18                 # = 0xcb0
VAL9 = STREAM9 - 0x1bf18                 # = 0xcbc

# clock-name strings (bundled addr -> bytes)
CLK_NAMES = [
    0x7f1b, 0x7f34, 0x7f50, 0x7f6b,      # wrap0 core, core_2x, m_ahb, s_ahb
    0x7f86, 0x7f9f, 0x7fbb, 0x7fd6,      # wrap1 core, core_2x, m_ahb, s_ahb
    0x7ff1, 0x8008, 0x801f, 0x8036, 0x804d, 0x8064, 0x807b, 0x8092,  # wrap0 s0-s7
    0x80a9, 0x80c0, 0x80d7, 0x80ee, 0x8105, 0x811c, 0x8133, 0x814a,  # wrap1 s0-s7
]
str_addr = {}
pos = CLKSTR
for sa in CLK_NAMES:
    e = b.find(b'\x00', sa)
    s = b[sa:e+1]
    str_addr[sa] = pos
    d[pos:pos+len(s)] = s
    pos += len(s)
TBL48_ADDR = (pos + 7) & ~7              # 8-align shared table
d[TBL48_ADDR:TBL48_ADDR+72] = TBL48

# ---------------- device table (13 old + 2 new) ----------------
newtbl = bytearray(d[0x1c2b8:0x1c2b8 + 13*0x28])
for name_ptr, h, val in ((STR4, 0x14341934, VAL4), (STR9, 0x14341939, VAL9)):
    newtbl += struct.pack('<QII', name_ptr, h, val) + bytes(0x18)
d[NEWTBL:NEWTBL+len(newtbl)] = newtbl

# ---------------- struct table (66 old + 2 new) ----------------
CFG4, CFG9 = 0x46f28, 0x46f78
newst = bytearray(d[0x1bae8:0x1bae8 + 66*0x10])
newst += struct.pack('<IIQ', 8, 0, CFG4)
newst += struct.pack('<IIQ', 8, 0, CFG9)
d[NEWSTRUCT:NEWSTRUCT+len(newst)] = newst

# ---------------- prop streams ----------------
# name-ref 0x79 -> 'config' in STOCK name table (same as i2c3/8/11 streams)
d[STREAM4:STREAM4+12] = struct.pack('<III', 0x12800079, 66, 0xff00ff00)
d[STREAM9:STREAM9+12] = struct.pack('<III', 0x12800079, 67, 0xff00ff00)

# ---------------- device name strings ----------------
d[STR4:STR4+10] = b'/dev/i2c4\x00'
d[STR9:STR9+10] = b'/dev/i2c9\x00'

# ---------------- clock-name pointer arrays ----------------
# wrap0 wrap clocks: core, core_2x, m_ahb, s_ahb, NULL
w0 = [str_addr[a] for a in (0x7f1b, 0x7f34, 0x7f50, 0x7f6b)] + [0]
w1 = [str_addr[a] for a in (0x7f86, 0x7f9f, 0x7fbb, 0x7fd6)] + [0]
for i, v in enumerate(w0):
    d[WRAP0+i*8:WRAP0+i*8+8] = struct.pack('<Q', v)
for i, v in enumerate(w1):
    d[WRAP1+i*8:WRAP1+i*8+8] = struct.pack('<Q', v)
# SE array: wrap0 s0-s7 + wrap1 s0-s7  (bundled order)
se_src = [0x7ff1, 0x8008, 0x801f, 0x8036, 0x804d, 0x8064, 0x807b, 0x8092,
          0x80a9, 0x80c0, 0x80d7, 0x80ee, 0x8105, 0x811c, 0x8133, 0x814a]
for i, a in enumerate(se_src):
    d[SEARR+i*8:SEARR+i*8+8] = struct.pack('<Q', str_addr[a])

# ---------------- config structs in .data ----------------
c4 = bytearray(CFG4_SRC); c9 = bytearray(CFG9_SRC)
c4[0x38:0x40] = struct.pack('<Q', WRAP0)          # wrap0 wrap-clock list
c4[0x40:0x48] = struct.pack('<Q', SEARR + 3*8)    # -> wrap0_s3 (SE3)
c4[0x48:0x50] = struct.pack('<Q', TBL48_ADDR)
c9[0x38:0x40] = struct.pack('<Q', WRAP1)          # wrap1 wrap-clock list
c9[0x40:0x48] = struct.pack('<Q', SEARR + 8*8)    # -> wrap1_s0 (SE0)
c9[0x48:0x50] = struct.pack('<Q', TBL48_ADDR)
d[CFG4:CFG4+80] = c4
d[CFG9:CFG9+80] = c9

# ---------------- PropsInfo + blob-header fixes ----------------
struct.pack_into('<Q', d, 0x7fb8, NEWSTRUCT)      # structTbl ptr
struct.pack_into('<Q', d, 0x7fc0, 15)             # numDevs 13 -> 15
struct.pack_into('<Q', d, 0x7fc8, NEWTBL)         # devTable ptr
struct.pack_into('<I', d, 0x1bf18, STREAM9 + 12 - 0x1bf18)  # blob size -> 0xcc8

# ---------------- new reloc blocks ----------------
def rel_block(page, addrs):
    ents = b''.join(struct.pack('<H', (10 << 12) | (a & 0xfff)) for a in sorted(addrs))
    sz = 8 + len(ents)
    pad = (-sz) % 4
    if pad:
        ents += b'\x00' * pad                     # zero entry (type ABSOLUTE) = skip
        sz += pad                                  # size must include padding
    return struct.pack('<II', page, sz) + ents

r1 = [NEWTBL + i*0x28 for i in range(15)]                          # name_ptrs
r1 += [NEWSTRUCT + i*0x10 + 8 for i in range(68)]                  # record ptrs
r1 += [WRAP0 + i*8 for i in range(4)] + [WRAP1 + i*8 for i in range(4)]
r1 += [SEARR + i*8 for i in range(16)]
r2 = [CFG4+0x38, CFG4+0x40, CFG4+0x48, CFG9+0x38, CFG9+0x40, CFG9+0x48]
newrels = rel_block(0x1c000, r1) + rel_block(0x46000, r2)
RELOC_ADD = len(newrels)
d += newrels
pad = (0x1000 - len(d) % 0x1000) % 0x1000
d += bytes(pad)                                   # pad file to 0x4d000

# ---------------- PE header updates ----------------
coff  = struct.unpack('<I', d[0x3c:0x40])[0]
opt   = coff + 24
optsz = struct.unpack('<H', d[coff+20:coff+22])[0]
dd    = opt + 112 + 8*5                            # DataDirectory[5] reloc
new_rsize = 0x5000 + RELOC_ADD
struct.pack_into('<I', d, dd+4, new_rsize)         # dir size
struct.pack_into('<I', d, opt+56, 0x4d000)         # SizeOfImage
sh = coff + 24 + optsz + 2*40                      # .reloc = 3rd section
struct.pack_into('<I', d, sh+8,  new_rsize)        # VirtualSize
struct.pack_into('<I', d, sh+16, 0x6000)           # SizeOfRawData

open(OUT, 'wb').write(d)
print('wrote %s  size=0x%x  md5=%s  sha256=%s' % (
    OUT, len(d), hashlib.md5(d).hexdigest(), hashlib.sha256(d).hexdigest()))
print('reloc added: %d bytes, .reloc vsize=0x%x, SizeOfImage=0x4d000' % (RELOC_ADD, new_rsize))
print('strings end 0x%x, tbl48 @0x%x, clk strings 0x%x-0x%x' % (pos, TBL48_ADDR, CLKSTR, pos))
