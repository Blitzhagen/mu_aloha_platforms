/*
  Samsung STM32 pogo keyboard DXE driver, keyboard-only first iteration.

  IMPORTANT integration note: gQcomI2CProtocolGuid below is the strongest
  reverse-engineering candidate, not yet conclusively proven. Do not flash
  this as a finished product before validating the GUID/protocol layout and
  DALSYS /dev/i2c11 configuration. See drivers/stm32-pogo-protocol.md.
*/
#include <Uefi.h>
#include <Protocol/SimpleTextIn.h>
#include <Protocol/SimpleTextInEx.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/TimerLib.h>

#define QCOM_I2C_PROTOCOL_GUID \
  {0x18ec9aad,0xf07b,0x4809,{0x9e,0x96,0x30,0x12,0x30,0x9f,0x3d,0xf7}}
EFI_GUID gQcomI2CProtocolGuid = QCOM_I2C_PROTOCOL_GUID;

typedef enum { I2C_MODE_STANDARD=0 } I2C_MODE;
typedef struct {
  UINT32 BusFrequencyKhz;
  UINT32 SlaveAddress;
  UINT32 Mode;
  UINT32 SlaveMaxClockStretchUs;
  UINT32 CoreConfiguration1;
  UINT32 CoreConfiguration2;
} I2C_SLAVE_CONFIG;
typedef struct {
  UINT8 *Buffer; UINT32 Length; UINT32 Flags;
} I2C_DESCRIPTOR;
typedef EFI_STATUS (EFIAPI *I2C_OPEN)(UINT32 Instance,VOID **Handle);
typedef EFI_STATUS (EFIAPI *I2C_CLOSE)(VOID *Handle);
typedef EFI_STATUS (EFIAPI *I2C_TRANSFER)(VOID *Handle,I2C_SLAVE_CONFIG *Config,I2C_DESCRIPTOR *Desc,UINT32 Count,UINT32 *Transferred,UINT32 TimeoutMs);
typedef EFI_STATUS (EFIAPI *I2C_WRITE)(VOID *Handle,I2C_SLAVE_CONFIG *Config,UINT16 Offset,UINT16 OffsetLen,UINT8 *Buffer,UINT16 Length,UINT32 *Written,UINT32 TimeoutMs);
typedef EFI_STATUS (EFIAPI *I2C_READ)(VOID *Handle,I2C_SLAVE_CONFIG *Config,UINT16 Offset,UINT16 OffsetLen,UINT8 *Buffer,UINT16 Length,UINT32 *Read,UINT32 TimeoutMs);
typedef struct {
  I2C_OPEN Open; I2C_CLOSE Close; I2C_TRANSFER Transfer; I2C_WRITE Write; I2C_READ Read;
} QCOM_I2C_PROTOCOL;

#define POGO_I2C_INSTANCE 11
#define POGO_SLAVE_PRIMARY 0x2a
#define POGO_SLAVE_ALT     0x56
#define ID_KEYPAD 3
#define ID_HALL 4
#define CMD_CHECK_VERSION 0x02
#define SCAN(row,col) (((row)<<5)|(col))

typedef struct {
  EFI_SIMPLE_TEXT_INPUT_PROTOCOL SimpleIn;
  EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL SimpleEx;
  EFI_EVENT TimerEvent;
  EFI_EVENT WaitEvent;
  VOID *I2cHandle;
  UINT8 Slave;
  UINT8 Pressed[8][24];
  EFI_KEY_DATA Pending[64];
  UINTN Head,Tail;
  EFI_KEY_TOGGLE_STATE Toggle;
} POGO_KB;
STATIC QCOM_I2C_PROTOCOL *mI2c;
STATIC I2C_SLAVE_CONFIG mCfg={100,0,0,0,0,0};

STATIC EFI_STATUS RawXfer(POGO_KB *K,UINT8 *Tx,UINT32 TxLen,UINT8 *Rx,UINT32 RxLen){
  UINT32 n=0; I2C_DESCRIPTOR d[2]; UINT32 c=0;
  if(TxLen){d[c].Buffer=Tx;d[c].Length=TxLen;d[c].Flags=0;c++;}
  if(RxLen){d[c].Buffer=Rx;d[c].Length=RxLen;d[c].Flags=1;c++;}
  return mI2c->Transfer(K->I2cHandle,&mCfg,d,c,&n,20);
}
STATIC VOID PushKey(POGO_KB *K,UINT16 Scan,CHAR16 Ch,BOOLEAN Down){
  UINTN n=(K->Tail+1)%64; if(n==K->Head)return;
  K->Pending[K->Tail].Key.ScanCode=Scan;K->Pending[K->Tail].Key.UnicodeChar=Ch;
  K->Pending[K->Tail].KeyState.ShiftState=Down?EFI_SHIFT_STATE_VALID:0;
  K->Pending[K->Tail].KeyState.KeyToggleState=K->Toggle;
  K->Tail=n; if(Down)gBS->SignalEvent(K->WaitEvent);
}
STATIC VOID DecodeEvent(POGO_KB *K,UINT8 *P,UINTN Len){
  if(Len>=3 && P[0]==3 && P[1]==0 && P[2]==5)return;
  /* Response framing already consumed by caller: this endpoint payload is u16 events. */
  for(UINTN i=0;i+1<Len;i+=2){
    UINT16 v=P[i]|(P[i+1]<<8);UINT8 down=v&1,col=(v>>1)&31,row=(v>>6)&7;
    if(row>=8||col>=24)continue;K->Pressed[row][col]=down;
    UINT16 scan=(UINT16)SCAN(row,col);CHAR16 ch=0;
    /* Conservative generic mapping: report scan code. A future revision should
       translate the complete DT matrix keymap into scan/unicode pairs. */
    if(col>=2&&col<=11&&row==2)ch=(CHAR16)('1'+col-2);
    else if(row==3&&col>=2&&col<=12)ch=(CHAR16)("qwertyuiop["[col-2]);
    else if(row==4&&col>=2&&col<=11)ch=(CHAR16)("asdfghjkl;"[col-2]);
    else if(row==5&&col>=2&&col<=10)ch=(CHAR16)("zxcvbnm,."[col-2]);
    PushKey(K,scan,ch,down);
  }
}
STATIC VOID EFIAPI Poll(IN EFI_EVENT Event,IN VOID *Context){
  POGO_KB *K=Context;UINT8 req[3]={3,0,1},h[3]={0},p[100];UINT32 n;
  mCfg.SlaveAddress=K->Slave;
  if(EFI_ERROR(mI2c->Write(K->I2cHandle,&mCfg,0,0,req,3,&n,10)))return;
  if(EFI_ERROR(mI2c->Read(K->I2cHandle,&mCfg,0,0,h,3,&n,10)))return;
  UINTN len=(h[0]|(h[1]<<8));if(len<3||len>103)return;len-=3;if(len>100)return;
  if(EFI_ERROR(mI2c->Read(K->I2cHandle,&mCfg,0,0,p,(UINT16)len,&n,10)))return;
  if(h[2]==ID_KEYPAD)DecodeEvent(K,p,len);
  else if(h[2]==ID_HALL&&len)ZeroMem(K->Pressed,sizeof(K->Pressed));
}
STATIC EFI_STATUS EFIAPI ResetEx(IN EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This,IN BOOLEAN Extended){
  POGO_KB *K=BASE_CR(This,POGO_KB,SimpleEx);K->Head=K->Tail=0;ZeroMem(K->Pressed,sizeof(K->Pressed));return EFI_SUCCESS;
}
STATIC EFI_STATUS EFIAPI ReadKeyEx(IN EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This,OUT EFI_KEY_DATA *Key){
  POGO_KB *K=BASE_CR(This,POGO_KB,SimpleEx);if(K->Head==K->Tail)return EFI_NOT_READY;
  *Key=K->Pending[K->Head];K->Head=(K->Head+1)%64;if(K->Head==K->Tail)gBS->ResetEvent(K->WaitEvent);return EFI_SUCCESS;
}
STATIC EFI_STATUS EFIAPI SetState(IN EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This,IN EFI_KEY_TOGGLE_STATE *State){
  POGO_KB *K=BASE_CR(This,POGO_KB,SimpleEx);K->Toggle=*State;return EFI_SUCCESS;
}
STATIC EFI_STATUS EFIAPI RegisterKeyNotify(IN EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This,IN EFI_KEY_DATA *KeyData,IN EFI_KEY_NOTIFY_FUNCTION Fn,OUT VOID **NotifyHandle){return EFI_UNSUPPORTED;}
STATIC EFI_STATUS EFIAPI UnregisterKeyNotify(IN EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This,IN VOID *NotifyHandle){return EFI_UNSUPPORTED;}
STATIC EFI_STATUS EFIAPI ResetOld(IN EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This,IN BOOLEAN Extended){
  return ResetEx(&BASE_CR(This,POGO_KB,SimpleIn)->SimpleEx,Extended);
}
STATIC EFI_STATUS EFIAPI ReadKeyOld(IN EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This,OUT EFI_INPUT_KEY *Key){
  EFI_KEY_DATA kd;EFI_STATUS s=ReadKeyEx(&BASE_CR(This,POGO_KB,SimpleIn)->SimpleEx,&kd);if(!EFI_ERROR(s))*Key=kd.Key;return s;
}
EFI_STATUS EFIAPI PogoKbEntry(IN EFI_HANDLE ImageHandle,IN EFI_SYSTEM_TABLE *SystemTable){
  EFI_STATUS s=gBS->LocateProtocol(&gQcomI2CProtocolGuid,NULL,(VOID**)&mI2c);if(EFI_ERROR(s))return s;
  POGO_KB *K=AllocateZeroPool(sizeof(*K));if(!K)return EFI_OUT_OF_RESOURCES;
  K->Slave=POGO_SLAVE_PRIMARY;s=mI2c->Open(POGO_I2C_INSTANCE,&K->I2cHandle);if(EFI_ERROR(s))goto fail;
  mCfg.SlaveAddress=K->Slave;UINT8 vh[3]={4,0,1},cmd=CMD_CHECK_VERSION,h[3]={0};UINT32 n;
  /* Probe version; fall back to 0x56 once. Exact Linux framing is represented
     by Write+Write+Read phases here because the public API has no write-write primitive. */
  mI2c->Write(K->I2cHandle,&mCfg,0,0,vh,3,&n,20);mI2c->Write(K->I2cHandle,&mCfg,0,0,&cmd,1,&n,20);
  if(EFI_ERROR(mI2c->Read(K->I2cHandle,&mCfg,0,0,h,3,&n,20))){K->Slave=POGO_SLAVE_ALT;mCfg.SlaveAddress=K->Slave;}
  K->TimerEvent=NULL;K->WaitEvent=NULL;
  s=gBS->CreateEvent(EVT_TIMER|EVT_NOTIFY_SIGNAL,TPL_NOTIFY,Poll,K,&K->TimerEvent);if(EFI_ERROR(s))goto fail;
  s=gBS->CreateEvent(EVT_NOTIFY_WAIT,TPL_NOTIFY,NULL,NULL,&K->WaitEvent);if(EFI_ERROR(s))goto fail;
  K->SimpleEx.Reset=ResetEx;K->SimpleEx.ReadKeyStrokeEx=ReadKeyEx;K->SimpleEx.WaitForKeyEx=K->WaitEvent;K->SimpleEx.SetState=SetState;K->SimpleEx.RegisterKeyNotify=RegisterKeyNotify;K->SimpleEx.UnregisterKeyNotify=UnregisterKeyNotify;
  K->SimpleIn.Reset=ResetOld;K->SimpleIn.ReadKeyStroke=ReadKeyOld;K->SimpleIn.WaitForKey=K->WaitEvent;
  EFI_HANDLE hOut=NULL;s=gBS->InstallMultipleProtocolInterfaces(&hOut,&gEfiSimpleTextInProtocolGuid,&K->SimpleIn,&gEfiSimpleTextInputExProtocolGuid,&K->SimpleEx,NULL);if(EFI_ERROR(s))goto fail;
  gBS->SetTimer(K->TimerEvent,TimerPeriodic,EFI_TIMER_PERIOD_MILLISECONDS(10));
  DEBUG((DEBUG_INFO,"PogoKbDxe: installed, slave 0x%x instance %u\n",K->Slave,POGO_I2C_INSTANCE));
  return EFI_SUCCESS;
fail: if(K){if(K->I2cHandle)mI2c->Close(K->I2cHandle);FreePool(K);}return s? s:EFI_DEVICE_ERROR;
}
