# Lokale Submodule-Patches (gts7xllite WoA-Bringup)

Die Submodule-Gitlinks dieses Branches zeigen auf **upstream-Commits**
(microsoft/mu_* bzw. Projekt-Upstreams), damit `clone --recursive` funktioniert.
Die gesamte lokale Firmware-Arbeit liegt als Patch-Serie hier:

| Verzeichnis | Submodule | Commits | Inhalt |
|---|---|---|---|
| `MU_BASECORE/` | MU_BASECORE | 2 | WIP bis v73 (Build-Fixes, gts7xllite-Anpassungen); v156 EBS-TRACE-Marker in `CoreExitBootServices` + `RuntimeDriverSetVirtualAddressMap` |
| `Common-MU/` | Common/MU | 5 | WIP bis v73; MsBootPolicy CENSUS-Instrumentierung + DEBUG→Print (v144/145); DEBUG-Diagnose + Raw-LBA-Logkanal (v152/153); MMAP/GCD-Dump + MTI-Var-Reset (v154); v157 BlockIo-Read-Stress |
| `Common-MU_TIANO/` | Common/MU_TIANO | 1 | WIP bis v73 |

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

Danach entspricht der Tree dem Stand des Docker-Build-Trees `/work/mu`
(Submodule-HEADs: MU_BASECORE `94340f38`, Common/MU `cd861219`,
Common/MU_TIANO `868fd026`).

Build immer DEBUG: `python3 build_uefi.py -d samsung-gts7xllite -t DEBUG`
