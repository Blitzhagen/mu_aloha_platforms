#!/usr/bin/env python3
"""v163: UsbConfigDxe.efi Print-Hooks auf alle Kill-Kandidaten-Pfade.

Befund: UsbConfigDxe kann den Host-Controller via deferred Events/Notifies
abrissen (0x4b80 = DisconnectController -> PORTSC->RxDetect+CSC = exakt die
beobachtete Todes-Signatur). Externe Event-Groups (Ev2/Ev3/Ev4/Ev5) feuern
in unserem Pfad vermutlich nicht, aber interne Trigger sind offen:
0.1s-Provision-Poll (0x4790 -> 0x69f0 -> conditional restart), Protocol-
Notify (0x67a0), Toggle-Timer (0x55b0).

11 Hooks: ersetzen Entry-Instruktion durch 'b stub'. Stub druckt Hook-ID
via Print-Helfer 0x1b94 (w0=0x80000000, x1=fmt "UCF %x\n", w2=id),
restauriert Register, fuehrt Original-Instruktion aus, springt zurueck.

Achtung adrp-Originale (0x17d8->x1=0x12000, 0x67a0->x1=0xf000): im Stub
als adrp mit CAVE-PC neu kodiert (gleiche Zieladresse).

Ergebnis im Log: welche IDs zwischen 'Loading driver' und erstem cc4
feuern -> Kill-Kette. Dann gezielt NOPen (v164).

Cave @0x115e8 (.text-Zero-Run 0x115e5+0xa1b), Fmt @0x12548 (Zero-Run).
Backup: UsbConfigDxe.efi.v162-bak.
"""
import sys, struct

CAVE = 0x115E8
FMT_ADDR = 0x12548
FMT = b"UCF %x\n\x00"
PRINT = 0x1B94
STUB_SIZE = 0x44  # 17 instrs

# (id, entry, orig_word_be, special_adrp_target)
HOOKS = [
    (0x01, 0x1728, 0xf9446d4b, None),  # Ev2 notify stub  -> ToggleMode beide cores
    (0x02, 0x1744, 0x2a1f03e1, None),  # Ev3 notify stub  -> mode4 core0
    (0x03, 0x1784, 0xaa0803e3, None),  # Ev4 notify stub  -> mode via var
    (0x04, 0x17d8, 0xb0000081, 0x12000),  # Ev5 notify stub (orig adrp->0x12000)
    (0x05, 0x4790, 0xf9462160, None),  # provision-poll notify (0.1s timer)
    (0x06, 0x4b80, 0x2a0803e9, None),  # StopController (DisconnectController!)
    (0x07, 0x4178, 0xf9400908, None),  # StartController / mode-apply
    (0x08, 0x55b0, 0xb85fc3a9, None),  # ToggleMode worker
    (0x09, 0xa040, 0x321f03e8, None),  # PHY op (power/role)
    (0x0A, 0x67a0, 0xb0000041, 0x0F000),  # protocol-notify (orig adrp->0xf000)
    (0x0B, 0x4918, 0x8b080168, None),  # EBS teardown
]

def stp_pre(rt1, rt2, rn=31):
    return 0xA9BF0000 | (0x7E << 15) | (rt2 << 10) | (rn << 5) | rt1

def ldp_post(rt1, rt2, rn=31):
    # Template: ldp x8,x30,[sp],#16 = 0xA8C17BE8; Rt[4:0]/Rt2[14:10] ersetzen
    return (0xA8C17BE8 & ~0x1F & ~0x7C00) | rt1 | (rt2 << 10)

def movz_w(rd, imm16, shift=0):
    return 0x52800000 | ((shift // 16) << 21) | (imm16 << 5) | rd

def b_(pc, target):
    return 0x14000000 | (((target - pc) >> 2) & 0x3FFFFFF)

def bl_(pc, target):
    return 0x94000000 | (((target - pc) >> 2) & 0x3FFFFFF)

def adrp_(pc, rd, target):
    imm = ((target & ~0xFFF) - (pc & ~0xFFF)) >> 12
    return 0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | rd

def add_(rd, rn, imm):
    return 0x91000000 | (imm << 10) | (rn << 5) | rd

def emit_stub(pc, hook_id, orig_word, adrp_target):
    w = []
    w.append(stp_pre(8, 30))          # save x8,x30
    w.append(stp_pre(9, 10))          # save x9,x10
    w.append(stp_pre(11, 12))         # save x11,x12
    w.append(stp_pre(0, 1))           # save x0,x1
    w.append(stp_pre(2, 3))           # save x2,x3
    w.append(0x320103E0)              # orr w0,wzr,#0x80000000 (level mask)
    w.append(adrp_(pc + 0x18, 1, FMT_ADDR))
    w.append(add_(1, 1, FMT_ADDR & 0xFFF))
    w.append(movz_w(2, hook_id))
    w.append(bl_(pc + 0x24, PRINT))
    w.append(ldp_post(2, 3))
    w.append(ldp_post(0, 1))
    w.append(ldp_post(11, 12))
    w.append(ldp_post(9, 10))
    w.append(ldp_post(8, 30))
    if adrp_target is not None:
        w.append(adrp_(pc + 0x3C, 1, adrp_target))
    else:
        w.append(orig_word)
    w.append(b_(pc + 0x40, entry_map[hook_id] + 4))
    return b"".join(struct.pack("<I", x) for x in w)

entry_map = {hid: e for hid, e, _, _ in HOOKS}

def main(path):
    cave = bytearray()
    stubs = {}
    for hid, entry, orig, tgt in HOOKS:
        stub_pc = CAVE + len(cave)
        stubs[hid] = stub_pc
        cave += emit_stub(stub_pc, hid, orig, tgt)
    assert len(cave) == len(HOOKS) * STUB_SIZE, len(cave)

    with open(path, "r+b") as f:
        # cave: overwrite allowed (previous v163 cave bytes are nonzero)
        f.seek(CAVE)
        got = f.read(len(cave))
        if got == bytes(cave):
            print("cave already written")
        else:
            f.seek(CAVE)
            f.write(cave)
            print(f"cave@{CAVE:#x}: wrote {len(cave)}B ({len(HOOKS)} stubs)")
        f.seek(FMT_ADDR)
        got = f.read(len(FMT))
        if got != FMT:
            if any(got):
                sys.exit(f"fmt@{FMT_ADDR:#x} not zero")
            f.seek(FMT_ADDR)
            f.write(FMT)
        # hooks
        for hid, entry, orig, tgt in HOOKS:
            hook = struct.pack("<I", b_(entry, stubs[hid]))
            f.seek(entry)
            got = f.read(4)
            if got == hook:
                print(f"{entry:#06x}: already hooked (id {hid:#x})")
                continue
            if got != struct.pack("<I", orig):
                sys.exit(f"{entry:#06x}: MISMATCH {got.hex()} != "
                         f"{struct.pack('<I', orig).hex()} (id {hid:#x})")
            f.seek(entry)
            f.write(hook)
            print(f"{entry:#06x}: hooked -> stub@{stubs[hid]:#x} (id {hid:#x})")
    print("done:", path)

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "UsbConfigDxe.efi")
