import sys

p = '/work/mu/Common/MU/PcBdsPkg/MsBootPolicy/MsBootPolicy.c'
s = open(p).read()

s = s.replace(
    '#include <Protocol/DevicePath.h>',
    '#include <Protocol/DevicePath.h>\n#include <Protocol/BlockIo.h>\n#include <Protocol/DiskIo.h>\n#include <Protocol/UsbIo.h>'
)

helper = '''
VOID
DumpHandlesByProtocol (
  EFI_GUID  *Guid,
  CHAR8     *Name
  )
{
  EFI_HANDLE                    *H;
  UINTN                         C, I;
  EFI_STATUS                    St;
  EFI_DEVICE_PATH_PROTOCOL      *Dp;
  CHAR16                        *Txt;

  St = gBS->LocateHandleBuffer (ByProtocol, Guid, NULL, &C, &H);
  if (EFI_ERROR (St)) {
    DEBUG ((DEBUG_WARN, "CENSUS %a: locate failed %r\\n", Name, St));
    return;
  }

  DEBUG ((DEBUG_WARN, "CENSUS %a: %d handles\\n", Name, C));
  for (I = 0; I < C; I++) {
    St = gBS->HandleProtocol (H[I], &gEfiDevicePathProtocolGuid, (VOID **)&Dp);
    if (EFI_ERROR (St) || (Dp == NULL)) {
      DEBUG ((DEBUG_WARN, "  CENSUS %a[%d]: no devpath\\n", Name, I));
      continue;
    }

    Txt = ConvertDevicePathToText (Dp, TRUE, TRUE);
    if (Txt != NULL) {
      DEBUG ((DEBUG_WARN, "  CENSUS %a[%d]: %s\\n", Name, I, Txt));
      FreePool (Txt);
    }
  }

  return;
}

'''
anchor = 'EFI_STATUS\nSelectAndBootDevice ('
assert anchor in s, 'function anchor missing'
s = s.replace(anchor, helper + anchor)

old = '''  DEBUG ((DEBUG_WARN, "Found %d handles\\n", HandleCount));
  DisplayDevicePaths (Handles, HandleCount);'''
new = '''  DEBUG ((DEBUG_WARN, "Found %d handles\\n", HandleCount));
  DisplayDevicePaths (Handles, HandleCount);
  DumpHandlesByProtocol (&gEfiBlockIoProtocolGuid, "BLOCKIO");
  DumpHandlesByProtocol (&gEfiDiskIoProtocolGuid, "DISKIO");
  DumpHandlesByProtocol (&gEfiUsbIoProtocolGuid, "USBIO");'''
assert old in s, 'call anchor missing'
s = s.replace(old, new)

# v144: DEBUG -> Print() Konvertierung, damit Output ueber ConOut->Serial->ramoops
# sichtbar wird (Mu-DEBUG landete im RELEASE trotz Level 0x800fee0f nicht im pmsg).
import re
s = re.sub(
    r'DEBUG \(\(DEBUG_\w+, "([^"]*)",\s*(.*?)\)\)',
    lambda m: 'Print (L"' + m.group(1) + '", ' + m.group(2) + ')',
    s
)
s = re.sub(
    r'DEBUG \(\(DEBUG_\w+, "([^"]*)"\)\)',
    lambda m: 'Print (L"' + m.group(1) + '")',
    s
)

open(p, 'w').write(s)
print('patched ok')
