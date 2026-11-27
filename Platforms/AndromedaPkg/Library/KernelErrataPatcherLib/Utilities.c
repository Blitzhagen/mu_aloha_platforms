/** @file

  Patches NTOSKRNL to not cause a SError when reading/writing ACTLR_EL1
  Patches NTOSKRNL to not cause a SError when reading/writing AMCNTENSET0_EL0
  Patches NTOSKRNL to not cause a bugcheck when attempting to use
  PSCI_MEMPROTECT Due to an issue in QHEE

  Based on https://github.com/SamuelTulach/rainbow

  Copyright (c) 2021 Samuel Tulach
  Copyright (c) 2022-2023 DuoWoA authors

  SPDX-License-Identifier: MIT

**/
#include "KernelErrataPatcherLib.h"

#include <Library/PrintLib.h>
#include <Library/SerialPortLib.h>

#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_NT_SIGNATURE 0x00004550

/*
  v179 diagnostic: KernelErrataPatcher is intentionally still SILENT through
  FirmwarePrint, but the ExitBootServices transition needs a small number of
  unconditional breadcrumbs.  Direct SerialPortWrite reaches the framebuffer
  and pstore backends without depending on PcdDebugPrintErrorLevel or on the
  boot-services console.
*/
STATIC BOOLEAN mKepSerialInitTried;
STATIC BOOLEAN mKepSerialReady;

VOID
KepTracePrint(IN CONST CHAR8 *Format, ...)
{
  CHAR8   Buffer[192];
  VA_LIST Marker;
  UINTN   Length;

  if (!mKepSerialInitTried) {
    mKepSerialInitTried = TRUE;
    mKepSerialReady     = !RETURN_ERROR(SerialPortInitialize());
  }

  if (!mKepSerialReady) {
    return;
  }

  VA_START(Marker, Format);
  Length = AsciiVSPrint(Buffer, sizeof(Buffer), Format, Marker);
  VA_END(Marker);

  if (Length != 0) {
    SerialPortWrite((UINT8 *)Buffer, Length);
  }
}

EFI_PHYSICAL_ADDRESS LocateWinloadBase(EFI_PHYSICAL_ADDRESS base, UINTN *size)
{
  if (base & (EFI_PAGE_SIZE - 1)) {
    base &= ~(EFI_PAGE_SIZE - 1);
    base += EFI_PAGE_SIZE;
  }

  do {
    if (*(UINT16 *)base == IMAGE_DOS_SIGNATURE) {
      UINT32               newBaseOffset = *(UINT32 *)(base + 0x3C);
      EFI_PHYSICAL_ADDRESS newBase       = base + newBaseOffset;

      if (*(UINT16 *)newBase == IMAGE_NT_SIGNATURE) {
        *size = *(UINT32 *)(newBase + 0x110);
        if (*size & (EFI_PAGE_SIZE - 1)) {
          *size &= ~(EFI_PAGE_SIZE - 1);
          *size += EFI_PAGE_SIZE;
        }
        break;
      }
    }

    base -= EFI_PAGE_SIZE;
  } while (TRUE);

  return base;
}

VOID CopyMemory(
    EFI_PHYSICAL_ADDRESS destination, EFI_PHYSICAL_ADDRESS source, UINTN size)
{
  UINT8 *dst = (UINT8 *)(destination);
  UINT8 *src = (UINT8 *)(source);
  for (UINTN i = 0; i < size; i++) {
    dst[i] = src[i];
  }
}

EFI_PHYSICAL_ADDRESS
FindPattern(EFI_PHYSICAL_ADDRESS baseAddress, UINTN size, const CHAR8 *pattern)
{
  EFI_PHYSICAL_ADDRESS firstMatch     = 0;
  const CHAR8         *currentPattern = pattern;

  for (EFI_PHYSICAL_ADDRESS current = baseAddress; current < baseAddress + size;
       current++) {
    UINT8 byte = currentPattern[0];
    if (!byte)
      return firstMatch;
    if (byte == '\?' ||
        *(UINT8 *)(current) == GET_BYTE(byte, currentPattern[1])) {
      if (!firstMatch)
        firstMatch = current;
      if (!currentPattern[2])
        return firstMatch;
      ((byte == '\?') ? (currentPattern += 2) : (currentPattern += 3));
    }
    else {
      currentPattern = pattern;
      firstMatch     = 0;
    }
  }

  return 0;
}