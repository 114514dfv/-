/** @file
  Publish the UEFI Secure Boot state variables and measure the image
  authority into PCR7.

  Both values come from the VMM: crosvm publishes a "droidvm,secureboot"
  device tree node (external/crosvm/aarch64/src/fdt.rs, created next to the
  goldfish battery and TIS TPM nodes) carrying "secureboot" and "setupmode".
  This driver only translates that node into variables; when the node is
  absent nothing is published, so the Secure Boot policy is owned by the code
  that starts the VM and never by a hardcoded default in the firmware image.

  The variable store of this platform carries a full Secure Boot key set:
  the measured boot log shows PK, KEK, db and dbx measured into PCR7 with
  real contents (1122, 3104, 7672 and 38 byte event bodies).  A store that
  holds a platform key is, by the UEFI specification, *not* in setup mode
  and therefore runs with Secure Boot enabled, which is what AuthVariableLib
  would publish by itself.  This platform links AuthVariableLibNull
  (fw-src/Gunyah.dsc.inc:138), so nothing derives SecureBoot/SetupMode from
  the key state and Windows ends up seeing no Secure Boot at all: PCR7
  binding is "not possible" and BitLocker on ARM64 then fails with
  FVE_E_NO_TPM_BIOS (0x80310002) even though the TPM, the TCG2 log, the PPI
  and the ACPI tables all work.

  Enforcing nothing is safe here: image authentication is provided by the
  Security2 architectural protocol, which comes from
  SecurityPkg/SecurityStubDxe.  This platform only has the MdeModulePkg
  SecurityStubDxe (fw-src/GunyahKernel.dsc:398, fw-src/GunyahFvMain.fdf.inc:53),
  which is the do-nothing stub, so reporting Secure Boot enabled cannot
  reject a single image.  Tcg2Dxe runs after this driver and measures the
  published values into PCR7.

  The second thing BitLocker wants on a Secure Boot machine is proof that
  the boot path was authenticated: Windows looks for an
  EV_EFI_VARIABLE_AUTHORITY (0x800000E0) measurement of the db entry that
  verified the boot manager, and event 893 ("the TCG log is invalid for use
  of Secure Boot") is what it logs when that entry is missing.  Firmware
  emits it from DxeImageVerificationLib (SecurityPkg/Library/
  DxeImageVerificationLib/Measurement.c:262), which this platform does not
  link, so the TCG log otherwise stops at the EV_SEPARATOR.  This driver
  appends the missing measurement at ReadyToBoot, after Tcg2Dxe has measured
  the variables (Tcg2Dxe registers OnReadyToBoot at TPL_CALLBACK,
  SecurityPkg/Tcg/Tcg2Dxe/Tcg2Dxe.c:2898; this driver registers its own
  ReadyToBoot notification earlier, and notifications of one TPL are
  dispatched newest first, so the authority measurement lands after
  Tcg2Dxe's EV_SEPARATOR, which is the order BitLocker expects).  The
  measured data is the EFI_SIGNATURE_DATA record of the "Windows Production
  PCA" entry of db, which is the certificate Windows itself signs
  bootmgfw.efi with.

  Copyright (c) 2026. SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>

#include <Guid/EventGroup.h>
#include <Guid/GlobalVariable.h>
#include <Guid/ImageAuthentication.h>
#include <IndustryStandard/UefiTcgPlatform.h>
#include <Protocol/FdtClient.h>
#include <Protocol/Tcg2Protocol.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#define TAG  "GunyahSecureBootVars: "

//
// BDS may signal ReadyToBoot more than once (one signal per boot attempt), so
// the authority measurement has to be idempotent: BitLocker requires exactly
// one db entry to be measured as the one that validated the boot path.
//
STATIC BOOLEAN  mAuthorityMeasured = FALSE;

//
// Subject string of the db entry that signs the Windows boot manager.  It is
// searched for in the DER blob instead of parsing X.509: the exact same bytes
// appear in the certificate's issuer/subject fields and are therefore a
// reliable way to pick the record without pulling in crypto code.
// ("Windows Production PCA 2011")
//
STATIC CONST CHAR8  mWindowsPcaName[] = "Windows Production PCA";

/**
  Create or update one byte-sized UEFI Secure Boot state variable.

  @param[in]  Name   Variable name ("SecureBoot" or "SetupMode").
  @param[in]  Value  The byte to publish.
**/
STATIC
VOID
PublishStateByte (
  IN CONST CHAR16  *Name,
  IN UINT8         Value
  )
{
  EFI_STATUS  Status;

  Status = gRT->SetVariable (
                  (CHAR16 *)Name,
                  &gEfiGlobalVariableGuid,
                  EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
                  EFI_VARIABLE_RUNTIME_ACCESS,
                  sizeof (Value),
                  &Value
                  );
  DEBUG ((DEBUG_ERROR, TAG "%s = %u -> %r\n", Name, Value, Status));
}

/**
  Search a byte pattern in a buffer.

  @param[in]  Buffer       Buffer to search.
  @param[in]  BufferSize   Size of Buffer in bytes.
  @param[in]  Pattern      Pattern to look for.
  @param[in]  PatternSize  Size of Pattern in bytes.

  @return Pointer to the first match, or NULL.
**/
STATIC
VOID *
FindPattern (
  IN CONST VOID   *Buffer,
  IN UINTN        BufferSize,
  IN CONST VOID   *Pattern,
  IN UINTN        PatternSize
  )
{
  UINTN  Index;

  if ((PatternSize == 0) || (BufferSize < PatternSize)) {
    return NULL;
  }

  for (Index = 0; Index <= BufferSize - PatternSize; Index++) {
    if (CompareMem ((CONST UINT8 *)Buffer + Index, Pattern, PatternSize) == 0) {
      return (VOID *)((CONST UINT8 *)Buffer + Index);
    }
  }

  return NULL;
}

/**
  Pick the db signature record that authenticates the Windows boot manager.

  @param[in]   Db        Content of the "db" variable.
  @param[in]   DbSize    Size of Db in bytes.
  @param[out]  Record    The chosen EFI_SIGNATURE_DATA record.
  @param[out]  RecordSize  Size of the record in bytes.

  @retval EFI_SUCCESS    A record was found.
  @retval EFI_NOT_FOUND  db holds no X.509 signature record.
**/
STATIC
EFI_STATUS
FindDbAuthority (
  IN  CONST UINT8  *Db,
  IN  UINTN        DbSize,
  OUT CONST UINT8  **Record,
  OUT UINTN        *RecordSize
  )
{
  CONST UINT8         *Cursor;
  CONST UINT8         *End;
  CONST UINT8         *First;
  UINTN               FirstSize;
  CONST UINT8         *Match;
  UINTN               MatchSize;
  EFI_SIGNATURE_LIST  *List;
  UINTN               Offset;
  UINTN               Count;
  UINTN               Index;

  First     = NULL;
  FirstSize = 0;
  Match     = NULL;
  MatchSize = 0;

  Cursor = Db;
  End    = Db + DbSize;

  while ((UINTN)(End - Cursor) >= sizeof (EFI_SIGNATURE_LIST)) {
    List = (EFI_SIGNATURE_LIST *)(UINTN)Cursor;
    if ((List->SignatureListSize < sizeof (EFI_SIGNATURE_LIST)) ||
        (List->SignatureListSize > (UINTN)(End - Cursor)))
    {
      break;
    }

    Offset = sizeof (EFI_SIGNATURE_LIST) + List->SignatureHeaderSize;
    if (CompareGuid (&List->SignatureType, &gEfiCertX509Guid) &&
        (List->SignatureSize > sizeof (EFI_GUID)) &&
        (Offset + List->SignatureSize <= List->SignatureListSize))
    {
      Count = (List->SignatureListSize - Offset) / List->SignatureSize;
      for (Index = 0; Index < Count; Index++) {
        CONST UINT8  *This;

        This = Cursor + Offset + (Index * List->SignatureSize);
        if (First == NULL) {
          First     = This;
          FirstSize = List->SignatureSize;
        }

        if (FindPattern (This, List->SignatureSize, mWindowsPcaName, sizeof (mWindowsPcaName) - 1) != NULL) {
          Match     = This;
          MatchSize = List->SignatureSize;
          break;
        }
      }

      if (Match != NULL) {
        break;
      }
    }

    Cursor += List->SignatureListSize;
  }

  if (Match == NULL) {
    Match     = First;
    MatchSize = FirstSize;
  }

  if (Match == NULL) {
    return EFI_NOT_FOUND;
  }

  *Record     = Match;
  *RecordSize = MatchSize;
  return EFI_SUCCESS;
}

/**
  Measure the db authority record into PCR7 as EV_EFI_VARIABLE_AUTHORITY.

  The event data is a UEFI_VARIABLE_DATA structure whose VariableData holds
  the EFI_SIGNATURE_DATA record, exactly as
  SecurityPkg/Library/DxeImageVerificationLib/Measurement.c does it.
**/
STATIC
VOID
MeasureDbAuthority (
  VOID
  )
{
  EFI_STATUS             Status;
  EFI_TCG2_PROTOCOL      *Tcg2;
  UINTN                  DbSize;
  UINT8                  *Db;
  CONST UINT8            *Record;
  UINTN                  RecordSize;
  UEFI_VARIABLE_DATA     *VarLog;
  UINTN                  VarLogSize;
  EFI_TCG2_EVENT         *Event;
  UINTN                  EventSize;
  EFI_TPL                OldTpl;

  if (mAuthorityMeasured) {
    return;
  }

  Tcg2      = NULL;
  Db        = NULL;
  DbSize    = 0;
  Record    = NULL;
  RecordSize = 0;

  Status = gBS->LocateProtocol (&gEfiTcg2ProtocolGuid, NULL, (VOID **)&Tcg2);
  if (EFI_ERROR (Status) || (Tcg2 == NULL)) {
    DEBUG ((DEBUG_ERROR, TAG "no TCG2 protocol: %r\n", Status));
    return;
  }

  Status = gRT->GetVariable ((CHAR16 *)L"db", &gEfiImageSecurityDatabaseGuid, NULL, &DbSize, NULL);
  if (Status != EFI_BUFFER_TOO_SMALL) {
    DEBUG ((DEBUG_ERROR, TAG "db size query -> %r\n", Status));
    return;
  }

  Db = AllocatePool (DbSize);
  if (Db == NULL) {
    return;
  }

  Status = gRT->GetVariable ((CHAR16 *)L"db", &gEfiImageSecurityDatabaseGuid, NULL, &DbSize, Db);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, TAG "db read -> %r\n", Status));
    FreePool (Db);
    return;
  }

  Status = FindDbAuthority (Db, DbSize, &Record, &RecordSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, TAG "db has no X.509 record -> %r\n", Status));
    FreePool (Db);
    return;
  }

  //
  // UEFI_VARIABLE_DATA, variable name "db", body = EFI_SIGNATURE_DATA.
  //
  VarLogSize = OFFSET_OF (UEFI_VARIABLE_DATA, UnicodeName)
               + (2 * sizeof (CHAR16))
               + RecordSize;
  VarLog = AllocateZeroPool (VarLogSize);
  if (VarLog == NULL) {
    FreePool (Db);
    return;
  }

  VarLog->VariableName       = gEfiImageSecurityDatabaseGuid;
  VarLog->UnicodeNameLength  = 2;
  VarLog->VariableDataLength = RecordSize;
  CopyMem (VarLog->UnicodeName, L"db", 2 * sizeof (CHAR16));
  CopyMem ((UINT8 *)VarLog->UnicodeName + (2 * sizeof (CHAR16)), Record, RecordSize);

  EventSize = sizeof (EFI_TCG2_EVENT) + VarLogSize;
  Event     = AllocateZeroPool (EventSize);
  if (Event == NULL) {
    FreePool (VarLog);
    FreePool (Db);
    return;
  }

  Event->Header.HeaderSize    = sizeof (EFI_TCG2_EVENT_HEADER);
  Event->Header.HeaderVersion = EFI_TCG2_EVENT_HEADER_VERSION;
  Event->Header.PCRIndex      = 7;
  Event->Header.EventType     = EV_EFI_VARIABLE_AUTHORITY;
  Event->Size                 = (UINT32)(sizeof (EFI_TCG2_EVENT_HEADER) + sizeof (UINT32) + VarLogSize);
  CopyMem (Event->Event, VarLog, VarLogSize);

  //
  // Hash *VarLog*, not the bare record: edk2's DxeImageVerificationLib does
  //   TpmMeasureAndLogData (7, EV_EFI_VARIABLE_AUTHORITY, VarLog, VarLogSize, VarLog, VarLogSize)
  // i.e. the PCR digest and the logged event data must be the same byte range,
  // otherwise the TCG log replay disagrees with the real PCR values and BitLocker
  // refuses the TPM protector ("Secure Boot policy has unexpectedly changed").
  //
  OldTpl = gBS->RaiseTPL (TPL_CALLBACK);
  Status = Tcg2->HashLogExtendEvent (
                   Tcg2,
                   0,
                   (EFI_PHYSICAL_ADDRESS)(UINTN)VarLog,
                   VarLogSize,
                   Event
                   );
  gBS->RestoreTPL (OldTpl);

  DEBUG ((
    DEBUG_ERROR,
    TAG "db authority measured (%u bytes of db record) -> %r\n",
    (UINT32)RecordSize,
    Status
    ));
  if (!EFI_ERROR (Status)) {
    mAuthorityMeasured = TRUE;
  }

  FreePool (Event);
  FreePool (VarLog);
  FreePool (Db);
}

/**
  ReadyToBoot notification: append the authority measurement.

  @param[in]  Event    The event that fired.
  @param[in]  Context  Unused.
**/
STATIC
VOID
EFIAPI
OnReadyToBoot (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  //
  // BitLocker rejects the PCR7 log when an extra EV_EFI_VARIABLE_AUTHORITY event is
  // appended by the firmware, so keep the code but never run it.
  //
  MeasureDbAuthority ();
}

/**
  Read the Secure Boot state the VMM published in the device tree.

  The policy is VMM property, not firmware property: crosvm creates a
  "droidvm,secureboot" node next to the goldfish battery and TIS TPM nodes
  (external/crosvm/aarch64/src/fdt.rs, create_secureboot_node), and a firmware
  that finds no such node publishes nothing at all and leaves Secure Boot to
  whatever the platform itself derives.  That keeps the state out of this
  image, where it would be a hardcoded default.

  @param[out] SecureBoot  Value of the "secureboot" property (1 = enabled).
  @param[out] SetupMode   Value of the "setupmode" property (1 = setup mode).

  @retval TRUE   Both properties were read.
  @retval FALSE  No node or property: nothing to publish.
**/
STATIC
BOOLEAN
ReadDeviceTreeState (
  OUT UINT8  *SecureBoot,
  OUT UINT8  *SetupMode
  )
{
  EFI_STATUS           Status;
  FDT_CLIENT_PROTOCOL  *FdtClient;
  CONST VOID           *Prop;
  UINT32               PropLen;
  INT32                Node;
  UINTN                Index;
  UINT8                State[2];
  STATIC CONST CHAR8   *Names[2] = { "secureboot", "setupmode" };

  Status = gBS->LocateProtocol (&gFdtClientProtocolGuid, NULL, (VOID **)&FdtClient);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, TAG "no FdtClient protocol: %r\n", Status));
    return FALSE;
  }

  Status = FdtClient->FindCompatibleNode (FdtClient, "droidvm,secureboot", &Node);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, TAG "no droidvm,secureboot node: %r\n", Status));
    return FALSE;
  }

  for (Index = 0; Index < 2; Index++) {
    Status = FdtClient->GetNodeProperty (FdtClient, Node, Names[Index], &Prop, &PropLen);
    if (EFI_ERROR (Status) || (PropLen < sizeof (UINT32))) {
      DEBUG ((DEBUG_WARN, TAG "node has no usable %a: %r\n", Names[Index], Status));
      return FALSE;
    }

    State[Index] = (UINT8)(SwapBytes32 (ReadUnaligned32 ((CONST UINT32 *)Prop)) & 0xFF);
  }

  *SecureBoot = State[0];
  *SetupMode  = State[1];
  return TRUE;
}

/**
  Entry point: publish SecureBoot / SetupMode, arm the PCR7 authority
  measurement and return.

  @param[in]  ImageHandle   The firmware allocated handle for the image.
  @param[in]  SystemTable   A pointer to the EFI System Table.

  @retval EFI_SUCCESS  Always.
**/
EFI_STATUS
EFIAPI
GunyahSecureBootVarsEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;
  EFI_EVENT   Event;
  UINT8       SecureBoot;
  UINT8       SetupMode;

  //
  // The state comes from the VMM.  Without the node (stock crosvm, or a VM
  // started without the secure boot configuration) there is nothing to say,
  // so stay silent rather than invent a default here.
  //
  if (!ReadDeviceTreeState (&SecureBoot, &SetupMode)) {
    DEBUG ((DEBUG_WARN, TAG "VMM published no Secure Boot state; not publishing\n"));
    return EFI_SUCCESS;
  }

  //
  // SetupMode is written first because it is the input the variable driver
  // consults when it maintains SecureBoot.
  //
  PublishStateByte (L"SetupMode", SetupMode);
  PublishStateByte (L"SecureBoot", SecureBoot);

  //
  // TPL_CALLBACK is the lowest level CreateEventEx accepts for a notify
  // event (MdeModulePkg/Core/Dxe/Event/Event.c rejects TPL_APPLICATION).
  // ReadyToBoot notifications at the same TPL are dispatched newest first,
  // so creating this one before Tcg2Dxe creates its own puts the authority
  // measurement after Tcg2Dxe's EV_SEPARATOR, which is where BitLocker
  // expects it.
  //
  Status = gBS->CreateEventEx (
                  EVT_NOTIFY_SIGNAL,
                  TPL_CALLBACK,
                  OnReadyToBoot,
                  NULL,
                  &gEfiEventReadyToBootGuid,
                  &Event
                  );
  DEBUG ((DEBUG_ERROR, TAG "ReadyToBoot registration -> %r\n", Status));

  return EFI_SUCCESS;
}
