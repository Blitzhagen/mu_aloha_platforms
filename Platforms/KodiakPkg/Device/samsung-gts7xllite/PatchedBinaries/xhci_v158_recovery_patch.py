#!/usr/bin/env python3
"""v158: XhciDxe.efi Error-Recovery-Fix (REA-Befund, siehe woa-t736b console-v157).

Bug: Nach USB Transaction Error (cc=4) ist der EP per xHCI-Spec Halted.
Der Blob ruft XhcRecoverHaltedEndpoint NUR bei Result==STALL(2) auf.
Beim Timeout-Pfad laeuft XhcDequeueTrbFromEndpoint -> XhcStopEndpoint auf
dem halted EP -> Context State Error (cc=0x13) -> EP permanent tot ->
endlos 'XhcBulkTransfer: Time out - 40' / UsbBotSendCommand-Timeouts.

Patch A (DequeueTrb-Fallback): schlaegt XhcStopEndpoint fehl, wird statt-
dessen XhcResetEndpoint aufgerufen (toter ASSERT-Block @0x63d8 als Platz).
Patch B (Bulk-Trigger): Recover bei JEDEM Fehler-Result, nicht nur STALL.

Offsets = File-Offsets (.text VA==raw). Bytes sind little-endian wie im File.
Verwendung: python3 xhci_v158_recovery_patch.py <pfad-zu-XhciDxe.efi>
"""
import sys

PATCHES = [
    # A1: tbnz x0,#63,fail(0x63f4) -> in dead block 0x63d8
    (0x639C, bytes.fromhex("c002f8b7"), bytes.fromhex("e001f8b7"), "DequeueTrb fail->recovery"),
    # A2: dead block 0x63d8-0x63f3 (7 instr):
    #   mov x0,x19 ; mov w1,w21 ; mov w2,w23 ; bl XhcResetEndpoint(0x6188)
    #   tbnz x0,#63,fail ; b 0x63a0 ; nop
    (0x63D8,
     bytes.fromhex("400000d0420000f000083991e1678052422c01918d1a00941f2003d5"),
     bytes.fromhex("e00313aae103152ae203172a69ffff976000f8b7edffff171f2003d5"),
     "recovery: ResetEP fallback"),
    # B: XhcBulkTransfer - Recover bei jedem Result!=0 (b.ne -> nop)
    (0x2D68, bytes.fromhex("a1010054"), bytes.fromhex("1f2003d5"), "bulk: recover on any error"),
]

def main(path):
    with open(path, "r+b") as f:
        for off, expect, patch, desc in PATCHES:
            f.seek(off)
            got = f.read(len(expect))
            if got == patch:
                print(f"{off:#06x}: already patched ({desc})")
                continue
            if got != expect:
                sys.exit(f"{off:#06x}: MISMATCH {got.hex()} != {expect.hex()} ({desc}) - abbruch")
            f.seek(off)
            f.write(patch)
            print(f"{off:#06x}: patched ({desc})")
    print("done:", path)

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else
         "../Binaries/QcomPkg/Drivers/XhciDxe/XhciDxe.efi")
