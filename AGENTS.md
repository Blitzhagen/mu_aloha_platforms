# mu_aloha_platforms — UEFI-Build für SM-T736B (samsung-gts7xllite)

EDK2/MU-basierter UEFI-Port für das Samsung Galaxy Tab S7 FE 5G (SM7225/Kodiak).
Arbeits-Workspace mit Logs/RE/Workflow-Doku: `/home/blitzhagen/Projekte/woa-t736b`
(dort AGENTS.md zuerst lesen — Hardware-Fakten, Testprotokoll, Memory-Regeln).

## Build

```
sg docker -c "docker exec -w /build/mu_aloha_platforms mubuild \
  python3 build_uefi.py -d samsung-gts7xllite -t DEBUG"
```

- `sg docker` ist nötig (docker-Gruppe 975 erst nach Login in Session aktiv).
- **Immer DEBUG** — RELEASE kompiliert DEBUG() weg → pstore/serial bleiben leer.
- Output: `Build/KodiakPkg/samsung-gts7xllite.img` (3.006.464 B = 734×4096).
- `build_uefi.py` ignoriert Build-Fehler → bei altem .img-Timestamp BUILDLOG prüfen.

## Repo-Struktur

- Superprojekt + Submodules `Common/MU*`, `MU_BASECORE` u.a. Commits zuerst in den
  Submodules, dann `format-patch`-Export nach `Patches/<Submodul>/NNNN-*.patch`,
  dann Superprojekt inkl. Pointer. `Patches/apply_patches.sh` spielt sie ein.
- `Common/MU_TIANO`-Pointer ist seit Commit 9502c557 auf den Build-Stand gepinnt.

## Device-Binaries — Provenienz strikt trennen

`Platforms/KodiakPkg/Device/samsung-gts7xllite/`:

- `Binaries/QcomPkg/Drivers/*/*.efi` — aktiv gebaute Blobs. ACHTUNG: mehrere sind
  instrumentierte/gepatchte Versionen, NICHT stock (v142-UsbBusDxe, v160-XhciDxe,
  v163-UsbConfigDxe). Stock-XBL enthält KEINEN USB-Host-Stack (nur Gadget).
- `PatchedBinaries/` — Patch-Skripte + Backup-Kette (*.vNN-bak).
- **DALSYSDxe.efi trägt den v171-USB-FIX**: 4 Datenbytes PHY-Host-Tuning
  (`0x1b6f9=0x14, 0x1b6f6=0x2b, 0x1ba66=0xc4, 0x1ba67=0x89`, Backup `*.v170-bak`).
  Nicht mit dem Backup oder der DALSys_stock.efi aus fw-t736b überschreiben!

## Debug-Instrumentierung (aktiv in v171, Cleanup-Kandidaten)

Source: `Common/MU/PcBdsPkg/MsBootPolicy/MsBootPolicy.c` (XWATCH, StressUsbBlockRead
64MB, Dwc3Fix — erwiesener no-op, kann zuerst raus), `MU_BASECORE/.../BmBoot.c`
(post/pre-startimage), `DriverSupport.c` (CNCT/DCNCT/BSTART/BDONE+PSCWATCH),
`Event.c` (RTB-arming). Binary: XhciDxe v160 (XSTS/cc4), UsbBusDxe v142,
UsbConfigDxe v163 (UCF-Hooks). Cleanup schrittweise mit Boot-Verifikation —
Serial-Timing beeinflusst race-empfindliches Verhalten.
