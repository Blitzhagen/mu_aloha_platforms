#!/usr/bin/env python3
# Verify DALSYSDxe.efi.i2cmerged: decode device table + prop streams the same
# way DALSYS_GetDALDeviceIdStr / DALSYS_GetPropertyValue do.
import struct, sys, hashlib

def cstr(d, a):
    return d[a:d.find(b'\x00', a)]

def djb2(s):
    h = 0x1505
    for c in s:
        h = (h * 0x21 + c) & 0xffffffff
    return h

def load(path):
    d = open(path, 'rb').read()
    blob     = struct.unpack('<Q', d[0x7fb0:0x7fb8])[0]
    structtb = struct.unpack('<Q', d[0x7fb8:0x7fc0])[0]
    numdevs  = struct.unpack('<Q', d[0x7fc0:0x7fc8])[0]
    devtbl   = struct.unpack('<Q', d[0x7fc8:0x7fd0])[0]
    devs = []
    for i in range(numdevs):
        e = devtbl + i*0x28
        np, h, val = struct.unpack('<QII', d[e:e+16])
        devs.append((cstr(d, np), h, val))
    return d, blob, structtb, devs

def resolve(devs, name):
    h = djb2(name)
    return [dv for dv in devs if dv[1] == h and dv[0] == name]

def get_struct(d, structtb, idx):
    sz, pad, ptr = struct.unpack('<IIQ', d[structtb+idx*16:structtb+idx*16+16])
    return ptr

def parse_stream(d, blob, val):
    off = blob + val
    recs = []
    while True:
        w, v = struct.unpack('<II', d[off:off+8])
        off += 8
        if w == 0xff00ff00:
            break
        typ = (w >> 24) & 0xff
        nref = w & 0xffffff
        recs.append((typ, nref, v))
    return recs

def main(path):
    d, blob, structtb, devs = load(path)
    print('== %s ==' % path)
    print('blob=0x%x structtbl=0x%x numdevs=%d' % (blob, structtb, len(devs)))
    for name, h, val in devs:
        print('  %-28s hash=0x%08x val=0x%x stream@0x%x' % (name.decode(), h, val, blob+val))
    for target in (b'/dev/i2c4', b'/dev/i2c9'):
        r = resolve(devs, target)
        if not r:
            print('!! %s NOT FOUND' % target); continue
        name, h, val = r[0]
        recs = parse_stream(d, blob, val)
        print('%s: hash=0x%x val=0x%x records=%s' % (target, h, val, recs))
        for typ, nref, v in recs:
            if typ == 0x12:
                ptr = get_struct(d, structtb, v)
                cfg = d[ptr:ptr+80]
                print('  struct idx=%d -> cfg @0x%x:' % (v, ptr))
                for i in range(0, 80, 16):
                    print('    +%02x: %s' % (i, cfg[i:i+16].hex()))
                se = struct.unpack('<Q', cfg[0:8])[0] + struct.unpack('<I', cfg[0x10:0x14])[0]
                print('    qup_base=0x%x  se_off=0x%x  SE=0x%x  bus=%d' % (
                    struct.unpack('<Q', cfg[0:8])[0],
                    struct.unpack('<I', cfg[0x10:0x14])[0], se, cfg[0x15]))
    return d, devs

d_new, devs_new = main('DALSYSDxe.efi.i2cmerged')
print()
d_old, blob_old, st_old, devs_old = load('DALSYSDxe.efi')
same = all(dev in devs_new for dev in devs_old)
print('all %d stock devices present unchanged in merged: %s' % (len(devs_old), same))
for dev in devs_old:
    if dev not in devs_new:
        print('  MISSING/CHANGED:', dev)
