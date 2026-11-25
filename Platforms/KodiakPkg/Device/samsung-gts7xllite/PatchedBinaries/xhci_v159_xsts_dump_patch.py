#!/usr/bin/env python3
"""v159: XhciDxe.efi PORTSC/USBSTS-Dump beim ersten TRANSACTION_ERROR (cc=4).

Befund v158 (console-v158.txt): Recovery-Patch wirkt (kein 0x13/Wedge),
aber JEDE Bulk-Transaktion im App-Kontext schlaegt cc=4 fehl (Link tot).
Blob programmiert selbst kein LPM -> Dump entscheidet: Link suspend?
Port disabled? Power weg? (PLS/PED/CCS/PP in PORTSC, HCH in USBSTS).

Mechanik: cc=4-Case-Body in XhcCheckUrbResult endet bei 0x6a70 mit
'b 0x6a8c' (Common-Tail: Result store + Print + ret). Hook -> Cave @0x14300
(.text-Zero-Tail, executable). Cave liest phys xHC-Base 0x0A600000 +
CAPLENGTH -> opreg base, dumpt USBCMD/USBSTS/PORTSC0/PMSC0/PORTLI0/PORTSC1
einmalig (Flag @0x15500 in .data) via Print-Helfer 0xcc94
(w0=0x80000000, x1=fmt @0x14400, w2..w7=args). Register x8/x30 preserved.

Vorsicht: 0x0A600000 = DWC3/xHC-Basis laut PlatformMemoryMapLib 'USB'-Eintrag
(0x0A600000, 64MB); CAPLENGTH-Byte validiert Basis implizit (Sondermfaelle:
falsche Basis -> psc/psc1 = 0xffffffff o.ae. im Dump sichtbar).

Verwendung: python3 xhci_v159_xsts_dump_patch.py <pfad-zu-XhciDxe.efi>
(baut auf v158-PatchedBinaries-Stand auf)
"""
import sys

CAVE = bytes.fromhex(
    "090000b0"  # adrp x9, 0x15000          (flag @0x15500)
    "2a0145b9"  # ldr  w10, [x9,#0x500]
    "4a020035"  # cbnz w10, done (0x14350)
    "2a008052"  # mov  w10, #1
    "2a0105b9"  # str  w10, [x9,#0x500]
    "e87bbfa9"  # stp  x8, x30, [sp,#-16]!
    "094ca1d2"  # movz x9, #0xa60, lsl #16  (=0x0A600000)
    "2a014039"  # ldrb w10, [x9]            (CAPLENGTH)
    "29412a8b"  # add  x9, x9, w10, uxtw    (opreg base)
    "220140b9"  # ldr  w2, [x9]             (USBCMD)
    "230540b9"  # ldr  w3, [x9,#4]          (USBSTS)
    "240144b9"  # ldr  w4, [x9,#0x400]      (PORTSC0)
    "250544b9"  # ldr  w5, [x9,#0x404]      (PORTPMSC0)
    "260944b9"  # ldr  w6, [x9,#0x408]      (PORTLI0)
    "271144b9"  # ldr  w7, [x9,#0x410]      (PORTSC1)
    "0000b052"  # mov  w0, #0x80000000
    "01000090"  # adrp x1, 0x14000
    "21001091"  # add  x1, x1, #0x400       (fmt @0x14400)
    "53e2ff97"  # bl   0xcc94
    "e87bc1a8"  # ldp  x8, x30, [sp],#16
    "cfc9ff17"  # done: b 0x6a8c
)

FMT = b"XSTS cmd=%x sts=%x psc0=%x pmsc=%x pli=%x psc1=%x\n\x00"

PATCHES = [
    (0x6A70, bytes.fromhex("07000014"), bytes.fromhex("24370014"),
     "hook cc4-case -> cave@0x14300"),
]
WRITES = [
    (0x14300, CAVE, "dump-cave (.text zero tail)"),
    (0x14400, FMT, "fmt string"),
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
                sys.exit(f"{off:#06x}: MISMATCH {got.hex()} != {expect.hex()} ({desc})")
            f.seek(off)
            f.write(patch)
            print(f"{off:#06x}: patched ({desc})")
        for off, blob, desc in WRITES:
            f.seek(off)
            got = f.read(len(blob))
            if got == blob:
                print(f"{off:#06x}: already written ({desc})")
                continue
            if any(got):
                sys.exit(f"{off:#06x}: area not zero ({desc}) - abbruch")
            f.seek(off)
            f.write(blob)
            print(f"{off:#06x}: wrote {len(blob)}B ({desc})")
    print("done:", path)

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else
         "../Binaries/QcomPkg/Drivers/XhciDxe/XhciDxe.efi")
