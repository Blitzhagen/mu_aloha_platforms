/*
  Samsung STM32 pogo keyboard DXE driver, keyboard-only first iteration.

  v174: GUID/interface layout were proven from the shipped I2CDxe.efi and
  its in-tree consumers.  Qualcomm I2C calls return i2c_status (UINT32,
  zero success), not EFI_STATUS.  See re/v174-implementation-report.md.
*/
#include <Uefi.h>
#include <Protocol/SimpleTextIn.h>
#include <Protocol/SimpleTextInEx.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>

#define QCOM_I2C_PROTOCOL_GUID \
  {0xb27ae8b1, 0x3e10, 0x4d07, {0xab, 0x5c, 0xeb, 0x9a, 0x6d, 0xc6, 0xfa, 0x8f}}

EFI_GUID  gQcomI2CProtocolGuid = QCOM_I2C_PROTOCOL_GUID;

typedef UINT32 I2C_STATUS;
#define I2C_STATUS_SUCCESS  0

typedef enum {
  I2C_MODE_STANDARD = 0
} I2C_MODE;

typedef struct {
  UINT32  BusFrequencyKhz;
  UINT32  SlaveAddress;
  UINT32  Mode;
  UINT32  SlaveMaxClockStretchUs;
  UINT32  CoreConfiguration1;
  UINT32  CoreConfiguration2;
} I2C_SLAVE_CONFIG;

/* 16-byte descriptor layout validated in I2CDxe transfer validation. */
typedef struct {
  UINT8   *Buffer;
  UINT32  Length;
  UINT32  Flags;
} I2C_DESCRIPTOR;

#define I2C_FLAG_START  0x1
#define I2C_FLAG_STOP   0x2
#define I2C_FLAG_WRITE  0x4
#define I2C_FLAG_READ   0x8
#define I2C_FLAGS_WRITE_RAW  (I2C_FLAG_START | I2C_FLAG_STOP | I2C_FLAG_WRITE)
#define I2C_FLAGS_READ_RAW   (I2C_FLAG_START | I2C_FLAG_STOP | I2C_FLAG_READ)

typedef UINT32 (EFIAPI *I2C_OPEN)(UINT32 Instance, VOID **Handle);
typedef UINT32 (EFIAPI *I2C_CLOSE)(VOID *Handle);
typedef UINT32 (EFIAPI *I2C_READ)(
  VOID *Handle, I2C_SLAVE_CONFIG *Config, UINT16 Offset, UINT16 OffsetLength,
  UINT8 *Buffer, UINT16 Length, UINT32 *Transferred, UINT32 TimeoutUs
  );
typedef UINT32 (EFIAPI *I2C_WRITE)(
  VOID *Handle, I2C_SLAVE_CONFIG *Config, UINT16 Offset, UINT16 OffsetLength,
  UINT8 *Buffer, UINT16 Length, UINT32 *Transferred, UINT32 TimeoutUs
  );
typedef UINT32 (EFIAPI *I2C_TRANSFER)(
  VOID *Handle, I2C_SLAVE_CONFIG *Config, I2C_DESCRIPTOR *Descriptors,
  UINT16 DescriptorCount, VOID *Callback, VOID *CallbackContext,
  UINT32 DelayUs, UINT32 *Transferred
  );

/* Interface exported by I2CDxe.  The leading qword is 0x10000 in the blob. */
typedef struct {
  UINT64        Revision;
  I2C_OPEN      Open;
  I2C_READ      Read;
  I2C_WRITE     Write;
  I2C_TRANSFER  Transfer;
  I2C_CLOSE     Close;
} QCOM_I2C_PROTOCOL;

#define POGO_I2C_INSTANCE  11
#define POGO_SLAVE_PRIMARY 0x2a
#define POGO_SLAVE_ALT     0x56
#define POGO_TIMEOUT_US    2500

#define ID_KEYPAD  3
#define ID_HALL    4
#define ID_MCU     1
#define CMD_CHECK_VERSION  0x02
#define SCAN(row,col)      (((row) << 5) | (col))
#define KEY_QUEUE_SIZE     64

typedef struct {
  EFI_SIMPLE_TEXT_INPUT_PROTOCOL    SimpleIn;
  EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL SimpleEx;
  EFI_EVENT                         TimerEvent;
  EFI_EVENT                         WaitEvent;
  EFI_HANDLE                        Handle;
  VOID                              *I2cHandle;
  UINT8                             Slave;
  UINT8                             Pressed[8][24];
  EFI_KEY_DATA                      Pending[KEY_QUEUE_SIZE];
  UINTN                             Head;
  UINTN                             Tail;
  EFI_KEY_TOGGLE_STATE              Toggle;
  BOOLEAN                           ProbeOk;
} POGO_KB;

STATIC QCOM_I2C_PROTOCOL  *mI2c;
STATIC I2C_SLAVE_CONFIG   mCfg = {100, 0, I2C_MODE_STANDARD, 500, 0, 0};

STATIC
I2C_STATUS
RawTransfer (
  IN POGO_KB *K,
  IN UINT8   *Buffer,
  IN UINT16  Length,
  IN UINT32  Flags,
  OUT UINT32 *Transferred OPTIONAL
  )
{
  I2C_DESCRIPTOR  Desc;
  UINT32          Done = 0;

  Desc.Buffer = Buffer;
  Desc.Length = Length;
  Desc.Flags  = Flags;
  mCfg.SlaveAddress = K->Slave;
  return mI2c->Transfer (
                K->I2cHandle,
                &mCfg,
                &Desc,
                1,
                NULL,
                NULL,
                POGO_TIMEOUT_US,
                (Transferred != NULL) ? Transferred : &Done
                );
}

STATIC
I2C_STATUS
RawWrite (
  IN POGO_KB *K,
  IN UINT8   *Buffer,
  IN UINT16  Length
  )
{
  return RawTransfer (K, Buffer, Length, I2C_FLAGS_WRITE_RAW, NULL);
}

STATIC
I2C_STATUS
RawRead (
  IN POGO_KB *K,
  IN UINT8   *Buffer,
  IN UINT16  Length
  )
{
  return RawTransfer (K, Buffer, Length, I2C_FLAGS_READ_RAW, NULL);
}

STATIC
I2C_STATUS
ProbeVersion (
  IN POGO_KB *K
  )
{
  UINT8  Request[3] = {4, 0, ID_MCU};
  UINT8  Command    = CMD_CHECK_VERSION;
  UINT8  Header[3]  = {0, 0, 0};
  I2C_STATUS Status;

  Status = RawWrite (K, Request, sizeof (Request));
  if (Status != I2C_STATUS_SUCCESS) {
    return Status;
  }
  Status = RawWrite (K, &Command, 1);
  if (Status != I2C_STATUS_SUCCESS) {
    return Status;
  }
  Status = RawRead (K, Header, sizeof (Header));
  if (Status != I2C_STATUS_SUCCESS) {
    return Status;
  }

  /* total_length is little-endian and must include the 3-byte header. */
  if ((UINTN)(Header[0] | (Header[1] << 8)) < 3) {
    return 1;
  }
  return I2C_STATUS_SUCCESS;
}

STATIC
VOID
PushKey (
  IN POGO_KB *K,
  IN UINT16  ScanCode,
  IN CHAR16  UnicodeChar
  )
{
  UINTN Next = (K->Tail + 1) % KEY_QUEUE_SIZE;

  if (Next == K->Head) {
    return;
  }
  ZeroMem (&K->Pending[K->Tail], sizeof (EFI_KEY_DATA));
  K->Pending[K->Tail].Key.ScanCode             = ScanCode;
  K->Pending[K->Tail].Key.UnicodeChar          = UnicodeChar;
  K->Pending[K->Tail].KeyState.KeyToggleState  = K->Toggle;
  K->Tail = Next;
  gBS->SignalEvent (K->WaitEvent);
}

STATIC
VOID
DecodeKeypadPayload (
  IN POGO_KB *K,
  IN UINT8   *Payload,
  IN UINTN   Length
  )
{
  UINTN  Index;

  for (Index = 0; Index + 1 < Length; Index += 2) {
    UINT16  Event   = Payload[Index] | (Payload[Index + 1] << 8);
    BOOLEAN Press   = (Event & 1) != 0;
    UINT8   Column  = (Event >> 1) & 0x1f;
    UINT8   Row     = (Event >> 6) & 0x7;
    UINT16  Scan    = (UINT16)SCAN (Row, Column);
    CHAR16  Unicode = 0;

    if ((Row >= 8) || (Column >= 24)) {
      continue;
    }
    K->Pressed[Row][Column] = Press ? 1 : 0;

    /* Conservative provisional mapping; the full DT matrix keymap is future work. */
    if ((Row == 2) && (Column >= 2) && (Column <= 11)) {
      Unicode = (CHAR16)('1' + Column - 2);
    } else if ((Row == 3) && (Column >= 2) && (Column <= 12)) {
      Unicode = (CHAR16)"qwertyuiop["[Column - 2];
    } else if ((Row == 4) && (Column >= 2) && (Column <= 11)) {
      Unicode = (CHAR16)"asdfghjkl;"[Column - 2];
    } else if ((Row == 5) && (Column >= 2) && (Column <= 10)) {
      Unicode = (CHAR16)"zxcvbnm,."[Column - 2];
    }

    /* UEFI console input expects key presses, not release events. */
    if (Press) {
      PushKey (K, Scan, Unicode);
    }
  }
}

STATIC
VOID
ReleaseAllKeys (
  IN POGO_KB *K
  )
{
  ZeroMem (K->Pressed, sizeof (K->Pressed));
}

STATIC
VOID
EFIAPI
PollPogo (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  POGO_KB *K = (POGO_KB *)Context;
  UINT8   Request[3];
  UINT8   Header[3] = {0, 0, 0};
  UINT8   Payload[100];
  UINT16  TotalLength;
  UINTN   PayloadLength;

  if ((K == NULL) || (mI2c == NULL) || (K->I2cHandle == NULL)) {
    return;
  }

  /* caps value: 1 initially, 2 when caps-lock is active. */
  Request[0] = 3;
  Request[1] = 0;
  Request[2] = ((K->Toggle & EFI_CAPS_LOCK_ACTIVE) != 0) ? 2 : 1;

  if (RawWrite (K, Request, sizeof (Request)) != I2C_STATUS_SUCCESS) {
    return;
  }
  if (RawRead (K, Header, sizeof (Header)) != I2C_STATUS_SUCCESS) {
    return;
  }

  TotalLength = (UINT16)(Header[0] | (Header[1] << 8));
  if ((TotalLength < 3) || (TotalLength > 103)) {
    return;
  }
  PayloadLength = TotalLength - 3;
  if (PayloadLength > sizeof (Payload)) {
    return;
  }
  if ((PayloadLength != 0) &&
      (RawRead (K, Payload, (UINT16)PayloadLength) != I2C_STATUS_SUCCESS)) {
    return;
  }

  if ((TotalLength == 3) && (Header[2] == 5)) {
    return;  /* documented noise frame */
  }
  if (Header[2] == ID_KEYPAD) {
    DecodeKeypadPayload (K, Payload, PayloadLength);
  } else if ((Header[2] == ID_HALL) && (PayloadLength != 0)) {
    ReleaseAllKeys (K);
  }
}

STATIC
EFI_STATUS
EFIAPI
PogoResetEx (
  IN EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This,
  IN BOOLEAN                           ExtendedVerification
  )
{
  POGO_KB *K = BASE_CR (This, POGO_KB, SimpleEx);

  K->Head = K->Tail = 0;
  ReleaseAllKeys (K);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
PogoReadKeyEx (
  IN  EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This,
  OUT EFI_KEY_DATA                      *KeyData
  )
{
  POGO_KB *K = BASE_CR (This, POGO_KB, SimpleEx);

  if (K->Head == K->Tail) {
      return EFI_NOT_READY;
  }

  CopyMem (KeyData, &K->Pending[K->Head], sizeof (EFI_KEY_DATA));
  K->Head = (K->Head + 1) % KEY_QUEUE_SIZE;
  if (K->Head == K->Tail) {
    }
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
PogoSetState (
  IN EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This,
  IN EFI_KEY_TOGGLE_STATE              *KeyToggleState
  )
{
  POGO_KB *K = BASE_CR (This, POGO_KB, SimpleEx);

  K->Toggle = *KeyToggleState;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
PogoRegisterKeyNotify (
  IN  EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This,
  IN  EFI_KEY_DATA                      *KeyData,
  IN  EFI_KEY_NOTIFY_FUNCTION           KeyNotificationFunction,
  OUT VOID                              **NotifyHandle
  )
{
  return EFI_UNSUPPORTED;
}

STATIC
EFI_STATUS
EFIAPI
PogoUnregisterKeyNotify (
  IN EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This,
  IN VOID                              *NotificationHandle
  )
{
  return EFI_UNSUPPORTED;
}

STATIC
EFI_STATUS
EFIAPI
PogoReset (
  IN EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This,
  IN BOOLEAN                        ExtendedVerification
  )
{
  POGO_KB *K = BASE_CR (This, POGO_KB, SimpleIn);

  return PogoResetEx (&K->SimpleEx, ExtendedVerification);
}

STATIC
EFI_STATUS
EFIAPI
PogoReadKey (
  IN  EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This,
  OUT EFI_INPUT_KEY                  *Key
  )
{
  POGO_KB     *K = BASE_CR (This, POGO_KB, SimpleIn);
  EFI_KEY_DATA KeyData;
  EFI_STATUS   Status;

  Status = PogoReadKeyEx (&K->SimpleEx, &KeyData);
  if (!EFI_ERROR (Status)) {
    *Key = KeyData.Key;
  }
  return Status;
}

STATIC
VOID
EFIAPI
PogoWaitEventNotify (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
}

STATIC
VOID
CloseAndFree (
  IN POGO_KB *K
  )
{
  if (K == NULL) {
    return;
  }
  if (K->TimerEvent != NULL) {
    gBS->SetTimer (K->TimerEvent, TimerCancel, 0);
    gBS->CloseEvent (K->TimerEvent);
  }
  if (K->WaitEvent != NULL) {
    gBS->CloseEvent (K->WaitEvent);
  }
  if ((K->I2cHandle != NULL) && (mI2c != NULL)) {
    mI2c->Close (K->I2cHandle);
  }
  FreePool (K);
}

EFI_STATUS
EFIAPI
PogoKbEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;
  I2C_STATUS  I2cStatus;
  POGO_KB     *K;

  Status = gBS->LocateProtocol (
                  &gQcomI2CProtocolGuid,
                  NULL,
                  (VOID **)&mI2c
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "PogoKbDxe: Qcom I2C protocol unavailable: %r\n", Status));
    return Status;
  }

  K = AllocateZeroPool (sizeof (*K));
  if (K == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  K->Slave = POGO_SLAVE_PRIMARY;
  I2cStatus = mI2c->Open (POGO_I2C_INSTANCE, &K->I2cHandle);
  if (I2cStatus != I2C_STATUS_SUCCESS) {
    DEBUG ((DEBUG_WARN, "PogoKbDxe: i2c_open(11) failed, i2c_status=0x%x\n", I2cStatus));
    CloseAndFree (K);
    return EFI_DEVICE_ERROR;
  }

  I2cStatus = ProbeVersion (K);
  if (I2cStatus != I2C_STATUS_SUCCESS) {
    UINT8 OldSlave = K->Slave;
    K->Slave = POGO_SLAVE_ALT;
    I2cStatus = ProbeVersion (K);
    if (I2cStatus != I2C_STATUS_SUCCESS) {
      K->Slave = OldSlave;
    }
  }
  K->ProbeOk = (I2cStatus == I2C_STATUS_SUCCESS);
  DEBUG ((
    DEBUG_INFO,
    "PogoKbDxe: i2c11 open, slave 0x%x, version-probe %a (status 0x%x)\n",
    K->Slave,
    K->ProbeOk ? "ok" : "failed/uncertain",
    I2cStatus
    ));

  Status = gBS->CreateEvent (
                  EVT_TIMER | EVT_NOTIFY_SIGNAL,
                  TPL_NOTIFY,
                  PollPogo,
                  K,
                  &K->TimerEvent
                  );
  if (EFI_ERROR (Status)) {
    goto Fail;
  }

  Status = gBS->CreateEvent (
                  EVT_NOTIFY_WAIT,
                  TPL_NOTIFY,
                  PogoWaitEventNotify,
                  NULL,
                  &K->WaitEvent
                  );
  if (EFI_ERROR (Status)) {
    goto Fail;
  }

  K->SimpleEx.Reset               = PogoResetEx;
  K->SimpleEx.ReadKeyStrokeEx     = PogoReadKeyEx;
  K->SimpleEx.WaitForKeyEx        = K->WaitEvent;
  K->SimpleEx.SetState            = PogoSetState;
  K->SimpleEx.RegisterKeyNotify   = PogoRegisterKeyNotify;
  K->SimpleEx.UnregisterKeyNotify = PogoUnregisterKeyNotify;

  K->SimpleIn.Reset         = PogoReset;
  K->SimpleIn.ReadKeyStroke = PogoReadKey;
  K->SimpleIn.WaitForKey    = K->WaitEvent;

  Status = gBS->InstallMultipleProtocolInterfaces (
                  &K->Handle,
                  &gEfiSimpleTextInProtocolGuid,
                  &K->SimpleIn,
                  &gEfiSimpleTextInputExProtocolGuid,
                  &K->SimpleEx,
                  NULL
                  );
  if (EFI_ERROR (Status)) {
    goto Fail;
  }

  Status = gBS->SetTimer (
                  K->TimerEvent,
                  TimerPeriodic,
                  EFI_TIMER_PERIOD_MILLISECONDS (10)
                  );
  if (EFI_ERROR (Status)) {
    goto Fail;
  }

  DEBUG ((DEBUG_INFO, "PogoKbDxe: installed SimpleTextIn/Ex on i2c11\n"));
  return EFI_SUCCESS;

Fail:
  if ((K != NULL) && (K->Handle != NULL)) {
    gBS->UninstallMultipleProtocolInterfaces (
           K->Handle,
           &gEfiSimpleTextInProtocolGuid,
           &K->SimpleIn,
           &gEfiSimpleTextInputExProtocolGuid,
           &K->SimpleEx,
           NULL
           );
  }
  CloseAndFree (K);
  return EFI_ERROR (Status) ? Status : EFI_DEVICE_ERROR;
}
