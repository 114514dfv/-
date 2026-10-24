/** @file
  DroidVM virtual TPM 2.0 ACPI publisher.

  This driver does two things, and the second is the one Windows actually needs:

    1. builds a TPM2 ACPI table (MdePkg/Include/IndustryStandard/Tpm2Acpi.h)
       describing a TIS device, and
    2. installs an SSDT (TpmAcpi.asl, packed into the firmware volume as a raw
       section under gEfiCallerIdGuid) declaring the \_SB.TPM0 device that
       Windows' inbox tpm.sys binds to, together with the TCG physical presence
       interface (PPI) it queries through _DSM.

  Which half matters: a TPM2 table alone is not enough. Windows discovers a TPM
  through the ACPI namespace -- _HID "MSFT0101" -- and only then reads the TPM2
  table to learn which register interface to speak. Publishing either one alone
  leaves Device Manager with nothing to show.

  The TIS base is assigned by crosvm at run time and published in the device
  tree under compatible "google,goldfish-tpm", which is why the ASL carries a
  placeholder and this driver patches it rather than the ASL naming it. The
  patch is a byte-pattern search for the byte order iasl emits, which is why it
  looks for the byte-reversed constant.

  Failing to find the node is not fatal. A VM started without crosvm's
  --tis-tpm flag has no TPM, and then the right thing is to publish nothing at
  all rather than a device whose every read faults.

  Copyright (c) 2026. SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>

#include <IndustryStandard/Tpm2Acpi.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/DxeServicesLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PcdLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiDriverEntryPoint.h>

#include <Protocol/AcpiTable.h>
#include <Protocol/FdtClient.h>

//
// edk2's Tpm2Acpi.h defines the structure and the start-method values but no
// table signature macro (unlike the tables covered by Acpi50.h/Acpi60.h), so
// this one is ours. "TPM2" as it appears in the table header.
//
#define EFI_ACPI_TPM2_TABLE_SIGNATURE  SIGNATURE_32 ('T', 'P', 'M', '2')

//
// The value TpmAcpi.asl is compiled with, as iasl lays it out: little endian.
// 0xD0D0FAD0 reads as D0 FA D0 D0. Kept deliberately distinct from the battery
// driver's 0xDEAD0001 so the two ASL blobs can never be confused for one
// another.
//
#define DROIDVM_TPM_PLACEHOLDER  0xD0D0FAD0U

//
// The ASL's window-size placeholder, likewise byte-reversed in the AML as
// 00 50 DE C0.
//
#define DROIDVM_TPM_SIZE_PLACEHOLDER  0xC0DE5000U

//
// The ASL's physical-presence page, one page above the registers. Kept in step
// with TPM_TIS_PPI_OFFSET in crosvm's devices/src/libtpms/tpm_tis.c, which
// serves that page out of the same MMIO window: the SSDT's TPP2 region is the
// storage Windows' physical presence interface uses, and crosvm is what answers
// the reads and writes to it.
//
#define DROIDVM_TPM_PPI_PLACEHOLDER  0xD0D0FAD1U
#define DROIDVM_TPM_PPI_OFFSET       0x1000U
#define DROIDVM_TPM_PPI_SIZE         0x100U

//
// Smallest window worth describing. The TIS specification puts TPM_DID_VID and
// TPM_RID at 0xF00, so anything less than a page cannot even hold the
// registers the interface defines.
//
#define DROIDVM_TPM_TIS_MIN_SIZE  0x1000ULL

//
// crosvm's TIS node. devices/src/libtpms/tis.rs registers it and
// aarch64/src/fdt.rs publishes it.
//
#define DROIDVM_GOLDFISH_TPM_COMPAT  "google,goldfish-tpm"

/**
  Patch a 32-bit placeholder, already byte-reversed to match the AML's byte
  order, wherever it appears in the table.

  A byte-pattern search rather than a struct poke because iasl does not promise
  where in the AML it puts a given integer, and this same value appears at least
  twice: once inside the _CRS Memory32Fixed descriptor and once as the
  OperationRegion offset.

  @param[in] Table        Table image to patch in place.
  @param[in] TableSize    Size of Table in bytes.
  @param[in] Placeholder  Placeholder value as it appears in the AML.
  @param[in] Value        Replacement value, also in AML byte order.

  @retval EFI_SUCCESS      At least one occurrence was replaced.
  @retval EFI_NOT_FOUND    The placeholder does not appear in the table.
**/
STATIC
EFI_STATUS
DroidVMTpmPatch32 (
  IN OUT UINT8   *Table,
  IN     UINTN   TableSize,
  IN     UINT32  Placeholder,
  IN     UINT32  Value
  )
{
  UINTN   Index;
  UINTN   Hits;

  Hits = 0;

  //
  // TableSize - sizeof (UINT32) can underflow for a table shorter than one
  // dword, which no real table is, but the guard is free.
  //
  if (TableSize < sizeof (UINT32)) {
    return EFI_NOT_FOUND;
  }

  for (Index = 0; Index + sizeof (UINT32) <= TableSize; Index++) {
    if (CompareMem (Table + Index, &Placeholder, sizeof (UINT32)) == 0) {
      CopyMem (Table + Index, &Value, sizeof (UINT32));
      Hits++;
      Index += sizeof (UINT32) - 1;
    }
  }

  DEBUG ((
    DEBUG_INFO,
    "DroidVMTpm: patched %d placeholder%s (0x%08x -> 0x%08x)\n",
    Hits,
    (Hits == 1) ? "" : "s",
    Placeholder,
    Value
    ));

  return (Hits > 0) ? EFI_SUCCESS : EFI_NOT_FOUND;
}

//
// The TPM2 ACPI table as revision 4 defines it, hand-laid out.
//
// MdePkg's EFI_TPM2_ACPI_TABLE stops after StartMethod: everything past it is
// revision dependent and is only described in comments there, so a table built
// from that structure alone while claiming revision 4 or later is truncated.
// Windows' boot environment reads the log fields LAML/LASA past the end of such
// a table, fails to initialise the TPM, and then reports the TPM as unusable --
// which is exactly what this firmware used to do.
//
// Layout (TCG ACPI specification, "TCG Hardware Interface Description Table
// Format for TPM 2.0", and unchanged in QEMU's build_tpm2() and edk2's own
// Tcg2Acpi producer):
//
//   0   ACPI description header (36 bytes, revision 4)
//   36  Flags, PlatformClass in bits 0..15
//   40  Address of control area (0: there is none for TIS)
//   48  Start method (6 = TIS/FIFO)
//   52  Start method specific parameters (12 bytes, unused for TIS)
//   64  Log area minimum length (LAML)
//   68  Log area start address (LASA)
//   76  end
//
#pragma pack (1)
typedef struct {
  EFI_ACPI_DESCRIPTION_HEADER    Header;
  UINT32                         Flags;
  UINT64                         AddressOfControlArea;
  UINT32                         StartMethod;
  UINT8                          StartMethodSpecificParameters[12];
  UINT32                         Laml;
  UINT64                         Lasa;
} DROIDVM_TPM2_ACPI_TABLE;
#pragma pack ()

#define DROIDVM_TPM2_ACPI_TABLE_REVISION  4

STATIC_ASSERT (
  sizeof (DROIDVM_TPM2_ACPI_TABLE) == 76,
  "the TPM2 ACPI table revision 4 layout is fixed at 76 bytes"
  );

/**
  Build and install the TPM2 ACPI table, declaring a TIS (FIFO) device.

  @param[in] TisBase  TIS register window base, from the device tree.

  @retval EFI_SUCCESS  Table installed.
  @retval others       First error encountered.
**/
STATIC
EFI_STATUS
DroidVMTpmInstallTpm2Table (
  IN UINT32  TisBase
  )
{
  EFI_STATUS                Status;
  EFI_ACPI_TABLE_PROTOCOL   *AcpiTableProtocol;
  DROIDVM_TPM2_ACPI_TABLE   *Table;
  UINT32                    Laml;
  UINT64                    Lasa;
  UINTN                     TableKey;

  //
  // The event log Tcg2Dxe measured into. It allocates the buffer and points
  // these two PCDs at it, and the depex on the TCG2 protocol guarantees it has
  // already run. Both zero means the platform booted without a log: Windows
  // still finds the device, but its measured boot library has nothing to read,
  // so that case is worth shouting about.
  //
  Laml = PcdGet32 (PcdTpm2AcpiTableLaml);
  Lasa = PcdGet64 (PcdTpm2AcpiTableLasa);

  if ((Laml == 0) || (Lasa == 0)) {
    DEBUG ((
      DEBUG_ERROR,
      "DroidVMTpm: no TCG2 event log (Laml=0x%x Lasa=0x%lx) -- did Tcg2Dxe fail to start?\n",
      Laml,
      Lasa
      ));
  }

  Table = AllocateZeroPool (sizeof (DROIDVM_TPM2_ACPI_TABLE));
  if (Table == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Header. Signature, revision and length are ours; Checksum is filled in by
  // the ACPI table protocol, as for any DXE-installed table. The OEM fields
  // stay zero, which is what QEMU emits too.
  //
  Table->Header.Signature = EFI_ACPI_TPM2_TABLE_SIGNATURE;
  Table->Header.Length    = (UINT32)sizeof (DROIDVM_TPM2_ACPI_TABLE);
  Table->Header.Revision  = DROIDVM_TPM2_ACPI_TABLE_REVISION;

  //
  // Flags carries PlatformClass in bits 0..15 (table revision 4 and later).
  // 0 = "unspecified / client", which is what QEMU and edk2's own TPM2 table
  // producer emit and what Windows accepts.
  //
  Table->Flags = 0;

  //
  // The control area belongs to the CRB (StartMethod 7/8) interface. A TIS
  // device has no such structure, so the field is 0 -- Linux's tpm_crb and
  // tpm_tis drivers both branch on StartMethod before ever reading it.
  //
  Table->AddressOfControlArea = 0;

  //
  // StartMethod 6 = TIS (FIFO), matching the interface crosvm implements and
  // the register offsets TpmAcpi.asl describes.
  //
  Table->StartMethod = EFI_TPM2_ACPI_TABLE_START_METHOD_TIS;

  //
  // StartMethodSpecificParameters only carries meaning for the SMC and CRB
  // start methods; AllocateZeroPool has already cleared them.
  //

  Table->Laml = Laml;
  Table->Lasa = Lasa;

  Status = gBS->LocateProtocol (&gEfiAcpiTableProtocolGuid, NULL, (VOID **)&AcpiTableProtocol);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "DroidVMTpm: no AcpiTable protocol: %r\n", Status));
    FreePool (Table);
    return Status;
  }

  Status = AcpiTableProtocol->InstallAcpiTable (
                                AcpiTableProtocol,
                                Table,
                                sizeof (DROIDVM_TPM2_ACPI_TABLE),
                                &TableKey
                                );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "DroidVMTpm: TPM2 table install failed: %r\n", Status));
    FreePool (Table);
    return Status;
  }

  DEBUG ((
    DEBUG_INFO,
    "DroidVMTpm: TPM2 table rev%d installed, StartMethod=TIS(6) TISbase=0x%x "
    "Laml=0x%x Lasa=0x%lx (TableKey=0x%lx)\n",
    DROIDVM_TPM2_ACPI_TABLE_REVISION,
    TisBase,
    Laml,
    Lasa,
    TableKey
    ));

  FreePool (Table);
  return EFI_SUCCESS;
}

/**
  Find the TPM SSDT, patch crosvm's TIS MMIO base into it, and install it.

  Failing to find the node is not fatal: a VM started without crosvm's
  --tis-tpm flag has no TIS device, and then the right thing is to publish no
  TPM device rather than one whose reads fault.

  @retval EFI_SUCCESS  Table installed, or deliberately skipped.
  @retval others       First error encountered.
**/
EFI_STATUS
EFIAPI
DroidVMTpmAcpiDxeEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                   Status;
  EFI_ACPI_TABLE_PROTOCOL      *AcpiTableProtocol;
  FDT_CLIENT_PROTOCOL          *FdtClient;
  EFI_ACPI_DESCRIPTION_HEADER  *Table;
  CONST VOID                   *Prop;
  UINT32                       PropLen;
  INT32                        Node;
  UINT64                       RegBase;
  UINT64                       RegSize;
  UINT32                       Address;
  UINTN                        TableSize;
  UINTN                        TableKey;

  Table     = NULL;
  TableSize = 0;
  Node      = 0;
  RegSize   = 0;

  //
  // The device tree first: without the node there is nothing to point at.
  //
  Status = gBS->LocateProtocol (&gFdtClientProtocolGuid, NULL, (VOID **)&FdtClient);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "DroidVMTpm: no FdtClient protocol: %r\n", Status));
    return EFI_SUCCESS;
  }

  Status = FdtClient->FindCompatibleNode (
                        FdtClient,
                        DROIDVM_GOLDFISH_TPM_COMPAT,
                        &Node
                        );
  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_WARN,
      "DroidVMTpm: no %a node -- VM started without crosvm's --tis-tpm? %r\n",
      DROIDVM_GOLDFISH_TPM_COMPAT,
      Status
      ));
    return EFI_SUCCESS;
  }

  //
  // `reg` is <address size>, both 64-bit big endian in every tree crosvm
  // emits. The registers must be reachable inside 32 bits or the ResourceTemplate
  // cannot describe them, and the window must be at least a page or it does not
  // cover the registers the TIS interface defines.
  //
  Status = FdtClient->GetNodeProperty (FdtClient, Node, "reg", &Prop, &PropLen);
  if (EFI_ERROR (Status) || (PropLen < 2 * sizeof (UINT64))) {
    DEBUG ((DEBUG_ERROR, "DroidVMTpm: tpm node has no usable reg: %r\n", Status));
    return EFI_SUCCESS;
  }

  RegBase = SwapBytes64 (ReadUnaligned64 ((CONST UINT64 *)Prop));
  RegSize = SwapBytes64 (ReadUnaligned64 ((CONST UINT64 *)Prop + 1));

  if (RegBase > MAX_UINT32) {
    DEBUG ((DEBUG_ERROR, "DroidVMTpm: TIS at 0x%lx is above 4 GiB\n", RegBase));
    return EFI_SUCCESS;
  }

  if (RegSize < DROIDVM_TPM_TIS_MIN_SIZE) {
    DEBUG ((
      DEBUG_ERROR,
      "DroidVMTpm: TIS window 0x%lx is too small to hold the defined registers\n",
      RegSize
      ));
    return EFI_SUCCESS;
  }

  //
  // A Memory32Fixed descriptor is dword-sized, so a window above 4 GiB cannot
  // be described either.
  //
  if (RegSize > MAX_UINT32) {
    DEBUG ((DEBUG_WARN, "DroidVMTpm: clamping TIS window 0x%lx to 4 GiB\n", RegSize));
    RegSize = MAX_UINT32;
  }

  Address = (UINT32)RegBase;

  DEBUG ((
    DEBUG_INFO,
    "DroidVMTpm: TIS device at 0x%x, window 0x%lx\n",
    Address,
    RegSize
    ));

  //
  // The namespace device first: it is what puts an entry in Device Manager,
  // and it is the only one of the two the user can see when something is wrong.
  //
  Status = GetSectionFromFv (
             &gEfiCallerIdGuid,
             EFI_SECTION_RAW,
             0,
             (VOID **)&Table,
             &TableSize
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "DroidVMTpm: SSDT not found in FV: %r\n", Status));
    return EFI_SUCCESS;
  }

  //
  // AML encodes integer constants little-endian, which is exactly how a UINT32
  // sits in memory on this target, so both the placeholders and the
  // replacements are ordinary host values -- no byte swapping.  Swapping them
  // earlier made every search miss (the log said "patched 0 placeholders") and
  // left the _CRS pointing at the dummy 0xD0D0FAD0 address.
  //
  DroidVMTpmPatch32 (
    (UINT8 *)Table,
    TableSize,
    DROIDVM_TPM_PLACEHOLDER,
    Address
    );

  DroidVMTpmPatch32 (
    (UINT8 *)Table,
    TableSize,
    DROIDVM_TPM_SIZE_PLACEHOLDER,
    (UINT32)RegSize
    );

  //
  // The physical presence page. It has to sit inside the window the device
  // actually decodes, or Windows' PPI queries would read bus space that belongs
  // to somebody else -- the failure mode this platform already hit with the
  // battery. A window that cannot hold the page is still published, at the
  // registers, because a TPM without a working PPI is worse than one whose PPI
  // answers nonsense, but it is worth a loud line in the log.
  //
  if (RegSize < DROIDVM_TPM_PPI_OFFSET + DROIDVM_TPM_PPI_SIZE) {
    DEBUG ((
      DEBUG_ERROR,
      "DroidVMTpm: TIS window 0x%lx cannot hold the physical presence page, "
      "leaving it at the registers\n",
      RegSize
      ));
  }

  DroidVMTpmPatch32 (
    (UINT8 *)Table,
    TableSize,
    DROIDVM_TPM_PPI_PLACEHOLDER,
    Address + ((RegSize < DROIDVM_TPM_PPI_OFFSET + DROIDVM_TPM_PPI_SIZE) ? 0 : DROIDVM_TPM_PPI_OFFSET)
    );

  Status = gBS->LocateProtocol (&gEfiAcpiTableProtocolGuid, NULL, (VOID **)&AcpiTableProtocol);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "DroidVMTpm: no AcpiTable protocol: %r\n", Status));
    FreePool (Table);
    return Status;
  }

  Status = AcpiTableProtocol->InstallAcpiTable (
                                AcpiTableProtocol,
                                Table,
                                TableSize,
                                &TableKey
                                );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "DroidVMTpm: SSDT install failed: %r\n", Status));
    FreePool (Table);
    return Status;
  }

  DEBUG ((DEBUG_INFO, "DroidVMTpm: SSDT installed (TableKey=0x%lx)\n", TableKey));

  FreePool (Table);

  //
  // Only now the TPM2 table: Windows reads it once it has found the device.
  //
  Status = DroidVMTpmInstallTpm2Table (Address);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return EFI_SUCCESS;
}
