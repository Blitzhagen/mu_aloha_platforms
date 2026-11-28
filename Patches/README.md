# Lokale Submodule-Patches (gts7xllite WoA-Bringup)

Die Submodule-Gitlinks dieses Branches zeigen auf **upstream-Commits**
(microsoft/mu_* bzw. Projekt-Upstreams), damit `clone --recursive` funktioniert.
Die gesamte lokale Firmware-Arbeit liegt als Patch-Serie hier:

| Verzeichnis | Submodule | Commits | Inhalt |
|---|---|---|---|
| `MU_BASECORE/` | MU_BASECORE | 7 | WIP bis v73; v156 EBS-TRACE; v164-v170 DxeCore/BmBoot/PSCWATCH-Diagnose; v173 USB-Hunt-Cleanup; v179 direct-serial EBS-TRACE in `CoreExitBootServices` |
| `Common-MU/` | Common/MU | 10 | WIP bis v73; MsBootPolicy CENSUS/DEBUG/Raw-LBA/MMAP/BlockIo-Stress/XWATCH-Diagnose; v169-v171 Dwc3Fix; v173 USB-Hunt-Cleanup |
| `Common-MU_TIANO/` | Common/MU_TIANO | 1 | WIP bis v73 |
| `Silicon-Arm-MU_TIANO/` | Silicon/Arm/MU_TIANO | 2 | v182 physikalischer Arch-Timer/PPI18-Haertung; v183 reduzierter Timer-IRQ-Trace-Spam |

## Anwenden (frischer Clone)

```sh
git clone --recursive -b xyz/sm7225/gts7xllite <repo-url>
cd mu_aloha_platforms
# user.name/user.email in den drei Submodulen setzen (git am braucht Identitaet)
sh Patches/apply_patches.sh
```

Hinweis: `apply_patches.sh` nutzt `git am --ignore-whitespace`, weil Upstream
teilweise CRLF-Dateien fuehrt (`.gitattributes`: `* -text`), die Patch-Serie
aber auf einem LF-normalisierten Tree entstand.

Danach entspricht der Tree dem lokalen Build-Stand dieses Branches
(Submodule-HEADs: MU_BASECORE `e37b9a8ebb`, Common/MU `130a693a`,
Common/MU_TIANO `07e3d31434`, Silicon/Arm/MU_TIANO `bb9e62bc77`).

Build immer DEBUG: `python3 build_uefi.py -d samsung-gts7xllite -t DEBUG`
