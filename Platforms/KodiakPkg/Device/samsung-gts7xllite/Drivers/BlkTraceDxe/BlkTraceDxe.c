/*
  Minimal removable-media BlockIo read tracer.

  v175 diagnostic for the Windows boot black box: hook removable-media
  EFI_BLOCK_IO_PROTOCOL instances, count successful ReadBlocks bytes, and
  emit sparse serial/pstore progress lines.  The tracer is deliberately
  passive for all error paths in its own setup: a tracer failure must never
  become a boot blocker.
*/

#include <Uefi.h>

#include <Guid/EventGroup.h>
#include <Protocol/BlockIo.h>
#include <Protocol/DevicePath.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/SerialPortLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

#define BLKTRACE_MAX_HOOKS    32
#define BLKTRACE_REPORT_MIB   64
#define BLKTRACE_MIB          0x100000ULL
#define BLKTRACE_SCAN_MS      50
#define BLKTRACE_SCAN_TPL     TPL_CALLBACK
#define BLKTRACE_MAX_ERRLOGS  4

/*
  v180 winload liveness probe: hook the central memory boot services in the
  boot-services table itself (same technique as KernelErrataPatcher uses for
  ExitBootServices).  Everything winload does before ExitBootServices —
  kernel/hive loading, handoff structure building, ACPI table copying —
  allocates memory through these services.  A rate-limited heartbeat plus
  immediate failure prints answer the key blackbox question: is winload
  still alive and working after the ramdisk reads end, or frozen/crashed?
*/
#define BSLIVE_HEARTBEAT      4096
#define BSLIVE_MAX_FAILLOGS   8
#define BSLIVE_GMM_PRINT_MOD  16

typedef struct {
  BOOLEAN                    InUse;
  BOOLEAN                    Logical;
  BOOLEAN                    Usb;
  UINT32                     ErrorPrints;
  UINTN                      Index;
  EFI_HANDLE                 Handle;
  EFI_BLOCK_IO_PROTOCOL      *BlockIo;
  EFI_BLOCK_READ             OriginalReadBlocks;
  UINT64                     TotalBytes;
  UINT64                     TotalReads;
} BLKTRACE_HOOK;

STATIC BLKTRACE_HOOK  mHooks[BLKTRACE_MAX_HOOKS];
STATIC UINTN          mHookCount;
STATIC UINTN          mLogicalHookCount;
STATIC UINT64         mPrimaryBytes;
STATIC UINT64         mPrimaryReads;
STATIC UINT64         mNextReportBytes = BLKTRACE_REPORT_MIB * BLKTRACE_MIB;
STATIC BOOLEAN        mStartPrinted;
STATIC BOOLEAN        mEndPrinted;
STATIC BOOLEAN        mTableFullPrinted;
STATIC BOOLEAN        mSerialReady;
STATIC EFI_EVENT      mScanTimerEvent;
STATIC EFI_EVENT      mProtocolNotifyEvent;
STATIC BOOLEAN        mProtocolNotifyRegistered;
STATIC EFI_EVENT      mExitBootServicesEvent;

STATIC EFI_ALLOCATE_PAGES   mOrigAllocatePages;
STATIC EFI_ALLOCATE_POOL    mOrigAllocatePool;
STATIC EFI_FREE_PAGES       mOrigFreePages;
STATIC EFI_FREE_POOL        mOrigFreePool;
STATIC EFI_GET_MEMORY_MAP   mOrigGetMemoryMap;
STATIC BOOLEAN              mBsHooksInstalled;
STATIC UINT64               mApCalls;
STATIC UINT64               mApFail;
STATIC UINT64               mPoolCalls;
STATIC UINT64               mPoolFail;
STATIC UINT64               mFpCalls;
STATIC UINT64               mFpoolCalls;
STATIC UINT64               mGmmCalls;
STATIC UINT64               mGmmFail;
STATIC UINT64               mBsEvents;
STATIC UINT32               mApFailPrints;
STATIC UINT32               mPoolFailPrints;

STATIC
EFI_STATUS
EFIAPI
TracedReadBlocks (
  IN EFI_BLOCK_IO_PROTOCOL  *This,
  IN UINT32                 MediaId,
  IN EFI_LBA                Lba,
  IN UINTN                  BufferSize,
  OUT VOID                  *Buffer
  );

STATIC
VOID
BlkTracePrint (
  IN CONST CHAR8  *Format,
  ...
  );

/*
  Heartbeat is deliberately cheap: one short line per 4096 boot-service
  memory events.  During a healthy winload phase thousands of allocations
  are expected, so a continuing heartbeat after the last BLKRD line means
  winload is alive and working; an abrupt stop means frozen/crashed.
*/
STATIC
VOID
BsLiveEvent (
  VOID
  )
{
  mBsEvents++;
  if ((mBsEvents % BSLIVE_HEARTBEAT) == 0) {
    BlkTracePrint (
      "BSHB: ev=%lu ap=%lu pool=%lu gmm=%lu af=%lu pf=%lu\n",
      mBsEvents,
      mApCalls,
      mPoolCalls,
      mGmmCalls,
      mApFail,
      mPoolFail
      );
  }
}

STATIC
EFI_STATUS
EFIAPI
TracedAllocatePages (
  IN     EFI_ALLOCATE_TYPE    Type,
  IN     EFI_MEMORY_TYPE      MemoryType,
  IN     UINTN                Pages,
  IN OUT EFI_PHYSICAL_ADDRESS *Memory
  )
{
  EFI_STATUS  Status;

  Status = mOrigAllocatePages (Type, MemoryType, Pages, Memory);
  mApCalls++;
  if (EFI_ERROR (Status)) {
    mApFail++;
    if (mApFailPrints < BSLIVE_MAX_FAILLOGS) {
      mApFailPrints++;
      BlkTracePrint (
        "BSAF: st=0x%lx type=%u mt=0x%x pages=%lx\n",
        (UINT64)Status,
        (UINT32)Type,
        (UINT32)MemoryType,
        (UINT64)Pages
        );
    }
  }
  BsLiveEvent ();
  return Status;
}

STATIC
EFI_STATUS
EFIAPI
TracedAllocatePool (
  IN  EFI_MEMORY_TYPE  PoolType,
  IN  UINTN            Size,
  OUT VOID             **Buffer
  )
{
  EFI_STATUS  Status;

  Status = mOrigAllocatePool (PoolType, Size, Buffer);
  mPoolCalls++;
  if (EFI_ERROR (Status)) {
    mPoolFail++;
    if (mPoolFailPrints < BSLIVE_MAX_FAILLOGS) {
      mPoolFailPrints++;
      BlkTracePrint (
        "BSPF: st=0x%lx mt=0x%x size=%lx\n",
        (UINT64)Status,
        (UINT32)PoolType,
        (UINT64)Size
        );
    }
  }
  BsLiveEvent ();
  return Status;
}

STATIC
EFI_STATUS
EFIAPI
TracedFreePages (
  IN EFI_PHYSICAL_ADDRESS  Memory,
  IN UINTN                 Pages
  )
{
  mFpCalls++;
  BsLiveEvent ();
  return mOrigFreePages (Memory, Pages);
}

STATIC
EFI_STATUS
EFIAPI
TracedFreePool (
  IN VOID  *Buffer
  )
{
  mFpoolCalls++;
  BsLiveEvent ();
  return mOrigFreePool (Buffer);
}

STATIC
EFI_STATUS
EFIAPI
TracedGetMemoryMap (
  IN OUT UINTN                  *MemoryMapSize,
  IN OUT EFI_MEMORY_DESCRIPTOR  *MemoryMap,
  OUT    UINTN                  *MapKey,
  OUT    UINTN                  *DescriptorSize,
  OUT    UINT32                 *DescriptorVersion
  )
{
  EFI_STATUS  Status;

  Status = mOrigGetMemoryMap (
             MemoryMapSize,
             MemoryMap,
             MapKey,
             DescriptorSize,
             DescriptorVersion
             );
  mGmmCalls++;
  if (EFI_ERROR (Status)) {
    mGmmFail++;
    /*
      EFI_BUFFER_TOO_SMALL is the normal first pass of the standard
      size-probe pattern and must not print (log flood).  Only genuinely
      anomalous GetMemoryMap failures are interesting.
    */
    if (Status != EFI_BUFFER_TOO_SMALL) {
      BlkTracePrint (
        "BSGF: st=0x%lx reqsize=%lx\n",
        (UINT64)Status,
        (UINT64)(MemoryMapSize != NULL ? *MemoryMapSize : 0)
        );
    }
  } else if ((mGmmCalls % BSLIVE_GMM_PRINT_MOD) == 0) {
    BlkTracePrint (
      "BSGM: n=%lu size=%lx\n",
      mGmmCalls,
      (UINT64)(MemoryMapSize != NULL ? *MemoryMapSize : 0)
      );
  }
  BsLiveEvent ();
  return Status;
}

/*
  Install the probes by replacing the function pointers in the boot services
  table and re-sealing the table CRC, exactly like the KernelErrataPatcher
  does for ExitBootServices.  All failures are non-fatal for the tracer.
*/
STATIC
VOID
InstallBsLivenessProbes (
  VOID
  )
{
  if (mBsHooksInstalled) {
    return;
  }

  mOrigAllocatePages = gBS->AllocatePages;
  mOrigAllocatePool  = gBS->AllocatePool;
  mOrigFreePages     = gBS->FreePages;
  mOrigFreePool      = gBS->FreePool;
  mOrigGetMemoryMap  = gBS->GetMemoryMap;

  if ((mOrigAllocatePages == NULL) || (mOrigAllocatePool == NULL) ||
      (mOrigFreePages == NULL) || (mOrigFreePool == NULL) ||
      (mOrigGetMemoryMap == NULL)) {
    BlkTracePrint ("BSHOOK-WARN: missing originals, probes not installed\n");
    return;
  }

  gBS->AllocatePages = TracedAllocatePages;
  gBS->AllocatePool  = TracedAllocatePool;
  gBS->FreePages     = TracedFreePages;
  gBS->FreePool      = TracedFreePool;
  gBS->GetMemoryMap  = TracedGetMemoryMap;

  gBS->Hdr.CRC32     = 0;
  gBS->CalculateCrc32 (gBS, sizeof (EFI_BOOT_SERVICES), &gBS->Hdr.CRC32);

  mBsHooksInstalled = TRUE;
  BlkTracePrint ("BSHOOK: bs memory probes installed\n");
}

STATIC
VOID
RemoveBsLivenessProbes (
  VOID
  )
{
  if (!mBsHooksInstalled) {
    return;
  }

  gBS->AllocatePages = mOrigAllocatePages;
  gBS->AllocatePool  = mOrigAllocatePool;
  gBS->FreePages     = mOrigFreePages;
  gBS->FreePool      = mOrigFreePool;
  gBS->GetMemoryMap  = mOrigGetMemoryMap;

  gBS->Hdr.CRC32     = 0;
  gBS->CalculateCrc32 (gBS, sizeof (EFI_BOOT_SERVICES), &gBS->Hdr.CRC32);

  mBsHooksInstalled = FALSE;

  BlkTracePrint (
    "BSEND: ev=%lu ap=%lu pool=%lu gmm=%lu fp=%lu fpool=%lu af=%lu pf=%lu gmfail=%lu\n",
    mBsEvents,
    mApCalls,
    mPoolCalls,
    mGmmCalls,
    mFpCalls,
    mFpoolCalls,
    mApFail,
    mPoolFail,
    mGmmFail
    );
}

/*
  Direct SerialPortWrite output is intentional.  On this platform the
  SerialPortLib implementation writes to the framebuffer, the memory log,
  and the ramoops/pmsg zones without depending on the DEBUG print level.
*/
STATIC
VOID
BlkTracePrint (
  IN CONST CHAR8  *Format,
  ...
  )
{
  CHAR8   Buffer[192];
  VA_LIST Marker;
  UINTN   Length;

  if (!mSerialReady) {
    return;
  }

  VA_START (Marker, Format);
  Length = AsciiVSPrint (Buffer, sizeof (Buffer), Format, Marker);
  VA_END (Marker);

  if (Length != 0) {
    SerialPortWrite ((UINT8 *)Buffer, Length);
  }
}

STATIC
BLKTRACE_HOOK *
FindHook (
  IN EFI_BLOCK_IO_PROTOCOL  *BlockIo
  )
{
  UINTN  Index;

  for (Index = 0; Index < mHookCount; Index++) {
    if (mHooks[Index].InUse && (mHooks[Index].BlockIo == BlockIo)) {
      return &mHooks[Index];
    }
  }

  return NULL;
}

/*
  USB sticks do not consistently set the SCSI/UFI removable-media bit.
  Treat a handle as USB either when its media claims to be removable or when
  its device path contains a USB messaging node.  On the observed v172 stick
  the relevant paths were Pci(0x80,0x0)/USB(0x1,0x0) plus its HD(...) child.
*/
STATIC
BOOLEAN
HasUsbDevicePathNode (
  IN EFI_HANDLE  Handle
  )
{
  EFI_STATUS                Status;
  EFI_DEVICE_PATH_PROTOCOL  *DevicePath;

  DevicePath = NULL;
  Status     = gBS->HandleProtocol (
                      Handle,
                      &gEfiDevicePathProtocolGuid,
                      (VOID **)&DevicePath
                      );
  if (EFI_ERROR (Status) || (DevicePath == NULL)) {
    return FALSE;
  }

  while (!IsDevicePathEndType (DevicePath)) {
    if ((DevicePathType (DevicePath) == MESSAGING_DEVICE_PATH) &&
        (DevicePathSubType (DevicePath) == MSG_USB_DP)) {
      return TRUE;
    }
    DevicePath = NextDevicePathNode (DevicePath);
  }

  return FALSE;
}

STATIC
VOID
HookBlockIo (
  IN EFI_HANDLE             Handle,
  IN EFI_BLOCK_IO_PROTOCOL  *BlockIo
  )
{
  BLKTRACE_HOOK       *Hook;
  EFI_BLOCK_IO_MEDIA  *Media;
  BOOLEAN             Usb;

  if ((BlockIo == NULL) || (BlockIo->Media == NULL) || (BlockIo->ReadBlocks == NULL)) {
    return;
  }

  Media = BlockIo->Media;
  Usb   = HasUsbDevicePathNode (Handle);
  if (!Media->MediaPresent || (!Media->RemovableMedia && !Usb)) {
    return;
  }

  if ((FindHook (BlockIo) != NULL) || (BlockIo->ReadBlocks == TracedReadBlocks)) {
    return;
  }

  if (mHookCount >= BLKTRACE_MAX_HOOKS) {
    if (!mTableFullPrinted) {
      mTableFullPrinted = TRUE;
      BlkTracePrint ("BLKRD-WARN: hook table full\n");
    }
    return;
  }

  Hook = &mHooks[mHookCount];
  ZeroMem (Hook, sizeof (*Hook));
  Hook->InUse              = TRUE;
  Hook->Logical            = Media->LogicalPartition;
  Hook->Usb                = Usb;
  Hook->Index              = mHookCount;
  Hook->Handle             = Handle;
  Hook->BlockIo            = BlockIo;
  Hook->OriginalReadBlocks = BlockIo->ReadBlocks;
  mHookCount++;

  if (Hook->Logical) {
    mLogicalHookCount++;
  }

  BlockIo->ReadBlocks = TracedReadBlocks;

  BlkTracePrint (
    "BLKRD-HOOK: slot=%u usb=%u removable=%u logical=%u bs=%u blocks=%lu\n",
    (UINT32)Hook->Index,
    (UINT32)(Hook->Usb ? 1 : 0),
    (UINT32)(Media->RemovableMedia ? 1 : 0),
    (UINT32)(Hook->Logical ? 1 : 0),
    Media->BlockSize,
    (UINT64)Media->LastBlock + 1
    );
}

STATIC
VOID
ScanUsbOrRemovableBlockIo (
  VOID
  )
{
  EFI_STATUS             Status;
  EFI_HANDLE             *Handles;
  UINTN                  HandleCount;
  UINTN                  Index;
  EFI_BLOCK_IO_PROTOCOL  *BlockIo;

  Handles     = NULL;
  HandleCount = 0;

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiBlockIoProtocolGuid,
                  NULL,
                  &HandleCount,
                  &Handles
                  );
  if (EFI_ERROR (Status) || (Handles == NULL)) {
    return;
  }

  for (Index = 0; Index < HandleCount; Index++) {
    BlockIo = NULL;
    Status  = gBS->HandleProtocol (
                     Handles[Index],
                     &gEfiBlockIoProtocolGuid,
                     (VOID **)&BlockIo
                     );
    if (!EFI_ERROR (Status) && (BlockIo != NULL)) {
      HookBlockIo (Handles[Index], BlockIo);
    }
  }

  FreePool (Handles);
}

/*
  Scanning uses LocateHandleBuffer/HandleProtocol and therefore must not run
  in a TPL_NOTIFY timer callback.  Both the periodic scan event and the
  BlockIo protocol-notify event are created with BLKTRACE_SCAN_TPL (callback
  level), where these boot-service calls are legal.
*/
STATIC
VOID
EFIAPI
ScanTimerNotify (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  ScanUsbOrRemovableBlockIo ();
}

/*
  Counting policy: logical partition instances are authoritative.  Raw
  removable-media instances are counted only until/unless a logical
  partition hook exists.  This avoids double-counting the usual stack where
  a partition child read is internally forwarded to its raw parent.
*/
STATIC
EFI_STATUS
EFIAPI
TracedReadBlocks (
  IN EFI_BLOCK_IO_PROTOCOL  *This,
  IN UINT32                 MediaId,
  IN EFI_LBA                Lba,
  IN UINTN                  BufferSize,
  OUT VOID                  *Buffer
  )
{
  BLKTRACE_HOOK  *Hook;
  EFI_STATUS     Status;
  BOOLEAN        CountAsPrimary;

  Hook = FindHook (This);
  if ((Hook == NULL) || (Hook->OriginalReadBlocks == NULL)) {
    return EFI_DEVICE_ERROR;
  }

  Status = Hook->OriginalReadBlocks (This, MediaId, Lba, BufferSize, Buffer);
  if (EFI_ERROR (Status)) {
    if (Hook->ErrorPrints < BLKTRACE_MAX_ERRLOGS) {
      Hook->ErrorPrints++;
      BlkTracePrint (
        "BLKRD-ERR: slot=%u st=0x%lx lba=%lu bytes=%lu\n",
        (UINT32)Hook->Index,
        (UINT64)Status,
        (UINT64)Lba,
        (UINT64)BufferSize
        );
    }
    return Status;
  }

  Hook->TotalBytes += (UINT64)BufferSize;
  Hook->TotalReads++;

  CountAsPrimary = Hook->Logical || (mLogicalHookCount == 0);
  if (!CountAsPrimary) {
    return Status;
  }

  if (!mStartPrinted) {
    mStartPrinted = TRUE;
    BlkTracePrint (
      "BLKRD-START: slot=%u lba=%lu bytes=%lu\n",
      (UINT32)Hook->Index,
      (UINT64)Lba,
      (UINT64)BufferSize
      );
  }

  mPrimaryBytes += (UINT64)BufferSize;
  mPrimaryReads++;

  while (mPrimaryBytes >= mNextReportBytes) {
    BlkTracePrint ("BLKRD: %lu MiB\n", mNextReportBytes / BLKTRACE_MIB);
    mNextReportBytes += BLKTRACE_REPORT_MIB * BLKTRACE_MIB;
  }

  return Status;
}

STATIC
VOID
EFIAPI
ExitBootServicesNotify (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  if (mEndPrinted) {
    return;
  }
  mEndPrinted = TRUE;

  if (mScanTimerEvent != NULL) {
    gBS->SetTimer (mScanTimerEvent, TimerCancel, 0);
  }

  RemoveBsLivenessProbes ();

  BlkTracePrint (
    "BLKRD-END: total=%lu bytes (%lu MiB) reads=%lu hooks=%u logical=%u notify=%u\n",
    mPrimaryBytes,
    mPrimaryBytes / BLKTRACE_MIB,
    mPrimaryReads,
    (UINT32)mHookCount,
    (UINT32)mLogicalHookCount,
    (UINT32)(mProtocolNotifyRegistered ? 1 : 0)
    );
}

EFI_STATUS
EFIAPI
BlkTraceDxeEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;
  VOID        *Registration;

  mSerialReady = !RETURN_ERROR (SerialPortInitialize ());

  BlkTracePrint ("BLKRD-INIT\n");
  InstallBsLivenessProbes ();
  ScanUsbOrRemovableBlockIo ();

  Registration = NULL;
  Status       = gBS->CreateEvent (
                        EVT_NOTIFY_SIGNAL,
                        BLKTRACE_SCAN_TPL,
                        ScanTimerNotify,
                        NULL,
                        &mProtocolNotifyEvent
                        );
  if (!EFI_ERROR (Status)) {
    Status = gBS->RegisterProtocolNotify (
                    &gEfiBlockIoProtocolGuid,
                    mProtocolNotifyEvent,
                    &Registration
                    );
    if (!EFI_ERROR (Status)) {
      mProtocolNotifyRegistered = TRUE;
    } else {
      gBS->CloseEvent (mProtocolNotifyEvent);
      mProtocolNotifyEvent = NULL;
    }
  }
  if (EFI_ERROR (Status)) {
    BlkTracePrint ("BLKRD-WARN: protocol notify unavailable st=0x%lx\n", (UINT64)Status);
  }

  Status = gBS->CreateEvent (
                  EVT_TIMER | EVT_NOTIFY_SIGNAL,
                  BLKTRACE_SCAN_TPL,
                  ScanTimerNotify,
                  NULL,
                  &mScanTimerEvent
                  );
  if (!EFI_ERROR (Status)) {
    Status = gBS->SetTimer (
                    mScanTimerEvent,
                    TimerPeriodic,
                    EFI_TIMER_PERIOD_MILLISECONDS (BLKTRACE_SCAN_MS)
                    );
    if (EFI_ERROR (Status)) {
      gBS->CloseEvent (mScanTimerEvent);
      mScanTimerEvent = NULL;
    }
  }
  if (EFI_ERROR (Status)) {
    BlkTracePrint ("BLKRD-WARN: scan timer unavailable st=0x%lx\n", (UINT64)Status);
  }

  Status = gBS->CreateEventEx (
                  EVT_NOTIFY_SIGNAL,
                  TPL_NOTIFY,
                  ExitBootServicesNotify,
                  NULL,
                  &gEfiEventExitBootServicesGuid,
                  &mExitBootServicesEvent
                  );
  if (EFI_ERROR (Status)) {
    BlkTracePrint ("BLKRD-WARN: exit event unavailable st=0x%lx\n", (UINT64)Status);
    mExitBootServicesEvent = NULL;
  }

  return EFI_SUCCESS;
}
