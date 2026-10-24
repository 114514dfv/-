/*
 * DroidVM virtual TPM 2.0.
 *
 * crosvm implements the TCG TIS (FIFO) register interface over an MMIO window
 * backed by libtpms. That is the same register interface a discrete TPM
 * exposes, so Windows' inbox tpm.sys drives it directly. Nothing about virtio
 * is involved: this is deliberately the TPM transport Windows already speaks.
 *
 * _HID is the string "MSFT0101", not EisaId(): MSFT is not a valid EISA PNP
 * vendor prefix, so it must be a plain ACPI string. This is exactly what QEMU
 * publishes for a TIS device on arm/virt and it is the identifier Windows binds
 * its TPM driver to. _CID repeats it for the same reason QEMU does.
 *
 * The device also has to answer the TCG physical presence interface. Windows
 * asks for it through _DSM, and a TPM device that cannot answer makes BitLocker
 * fail with FVE_E_NO_TPM_BIOS ("the BIOS did not communicate with the TPM
 * properly") even though every TPM command itself succeeds. QEMU only grew this
 * for arm/virt tpm-tis recently; the shape here follows its ASL and edk2's
 * SecurityPkg/Tcg/Tcg2Acpi/Tpm.asl, which is the version that has been in front
 * of Windows the longest.
 *
 * The interface is storage, not behaviour. The request block the OS fills in
 * lives in one page of the same MMIO window the TIS registers live in, one page
 * above them, and crosvm keeps it as plain memory -- exactly the division of
 * labour QEMU uses, where the page is guest RAM and the firmware, not the VMM,
 * is what would act on a request. Nothing on this platform acts on one, so a
 * submitted operation is reported as accepted, remembered in the block, and
 * visible in the crosvm trace as "ppi: ..." lines.
 *
 * Three placeholders, all patched by the driver before the table is installed:
 *
 *   0xD0D0FAD0  the TIS register window base, which crosvm assigns at run time
 *   0xC0DE5000  the window size, taken from the device's own device tree `reg`
 *   0xD0D0FAD1  the physical presence page, the register base plus one page
 *
 * None is hardcoded on purpose. The size in particular has to match what
 * crosvm actually maps: declaring a larger window than the device decodes
 * describes address space that belongs to somebody else, which is a mistake
 * this platform has made before with the battery.
 *
 * Copyright (c) 2026. SPDX-License-Identifier: BSD-2-Clause-Patent
 */

DefinitionBlock ("TpmAcpi.aml", "SSDT", 2, "DROIDV", "TPM2", 0x00000001)
{
    Scope (\_SB)
    {
        Device (TPM0)
        {
            Name (_HID, "MSFT0101")             // TPM 2.0, Windows' identifier
            Name (_CID, "MSFT0101")             // the same, as QEMU does
            Name (_STR, Unicode ("TPM 2.0 Device"))
            Name (_UID, 0x00)

            Method (_STA, 0, NotSerialized)     // status
            {
                Return (0x0F)                   // present, enabled, shown, functioning
            }

            Method (_CRS, 0, NotSerialized)     // the TIS register window
            {
                Return (ResourceTemplate ()
                {
                    Memory32Fixed (ReadWrite, 0xD0D0FAD0, 0xC0DE5000)
                })
            }

            OperationRegion (TREG, SystemMemory, 0xD0D0FAD0, 0xC0DE5000)
            Field (TREG, DWordAcc, NoLock, Preserve)
            {
                Offset (0x0000),
                TACC, 32,                       // TPM_ACCESS
                Offset (0x0008),
                TIEN, 32,                       // TPM_INT_ENABLE
                Offset (0x0010),
                TIST, 32,                       // TPM_INT_STATUS
                Offset (0x0014),
                TICF, 32,                       // TPM_INTF_CAPS
                Offset (0x0018),
                TSTS, 32,                       // TPM_STS
                Offset (0x0024),
                TFIF, 32,                       // TPM_DATA_FIFO
                Offset (0x0030),
                TIFI, 32,                       // TPM_INTF_ID
                Offset (0x0034),
                TIC2, 32,                       // TPM_INTF_CAPS2
                Offset (0x0038),
                TRID, 32,                       // TPM_RID
                Offset (0x0F00),
                TDID, 32,                       // TPM_DID_VID
                Offset (0x0F04),
                TRD2, 32                        // TPM_RID2
            }

            // The physical presence page: request block, then the overwrite flag.
            OperationRegion (TPP2, SystemMemory, 0xD0D0FAD1, 0x5B)
            Field (TPP2, AnyAcc, NoLock, Preserve)
            {
                PPIN, 8,                        // the interrupt the firmware would take
                PPIP, 32,                       // the function being asked of it
                PPRP, 32,                       // its result
                PPRQ, 32,                       // the operation the OS requested
                PPRM, 32,                       // that operation's argument
                LPPR, 32,                       // the result of the last operation
                UCRQ, 32,                       // the operation being confirmed
                Offset (0x5A),
                MOVV, 8                         // memory overwrite requested
            }

            // Results of the physical presence functions, as Packages the OS reads.
            Name (TPM2, Package (0x02) { Zero, Zero })
            Name (TPM3, Package (0x03) { Zero, Zero, Zero })

            // TCG hardware information.
            Method (HINF, 1, Serialized, 0, {BuffObj, PkgObj}, {UnknownObj})
            {
                Switch (ToInteger (Arg0))
                {
                    Case (0)
                    {
                        Return (Buffer () {0x03})   // functions 0 and 1 are supported
                    }
                    Case (1)
                    {
                        Name (TPMV, Package () {0x01, Package () {0x2, 0x0}})   // interface 1, TPM 2.0
                        If (LEqual (_STA (), 0x00))
                        {
                            Return (Package () {0x00})
                        }
                        Return (TPMV)
                    }
                    Default { BreakPoint }
                }
                Return (Buffer () {0})
            }

            // TCG physical presence interface.
            Method (TPPI, 2, Serialized, 0, {BuffObj, PkgObj, IntObj, StrObj}, {UnknownObj, UnknownObj})
            {
                Switch (ToInteger (Arg0))
                {
                    Case (0)
                    {
                        Return (Buffer () {0xFF, 0x01})     // functions 1 through 8
                    }
                    Case (1)
                    {
                        Return ("1.3")                      // interface version
                    }
                    Case (2)
                    {
                        Store (DerefOf (Index (Arg1, 0x00)), PPRQ)
                        Store (0, PPRM)
                        Store (0x02, PPIP)
                        Return (0)
                    }
                    Case (3)
                    {
                        Store (PPRQ, Index (TPM2, 0x01))
                        Return (TPM2)
                    }
                    Case (4)
                    {
                        Return (2)                          // reboot into the pre-OS environment
                    }
                    Case (5)
                    {
                        Store (0x05, PPIP)
                        Store (LPPR, Index (TPM3, 0x01))
                        Store (PPRP, Index (TPM3, 0x02))
                        Return (TPM3)
                    }
                    Case (6)
                    {
                        Return (3)                          // no preferred language, as edk2
                    }
                    Case (7)
                    {
                        Store (0x07, PPIP)
                        Store (DerefOf (Index (Arg1, 0x00)), PPRQ)
                        Store (0, PPRM)
                        If (LEqual (PPRQ, 23))
                        {
                            Store (DerefOf (Index (Arg1, 0x01)), PPRM)
                        }
                        Return (0)
                    }
                    Case (8)
                    {
                        Store (0x08, PPIP)
                        Store (DerefOf (Index (Arg1, 0x00)), UCRQ)
                        Return (0)
                    }
                    Default { BreakPoint }
                }
                Return (1)
            }

            Method (_DSM, 4, Serialized, 0, UnknownObj, {BuffObj, IntObj, IntObj, PkgObj})
            {
                // TCG hardware information.
                If (LEqual (Arg0, ToUUID ("cf8e16a5-c1e8-4e25-b712-4f54a96702c8")))
                {
                    Return (HINF (Arg2))
                }

                // TCG physical presence interface.
                If (LEqual (Arg0, ToUUID ("3dddfaa6-361b-4eb4-a424-8d10089d1653")))
                {
                    Return (TPPI (Arg2, Arg3))
                }

                // Memory overwrite: remember the request, as QEMU's ASL does.
                If (LEqual (Arg0, ToUUID ("376054ed-cc13-4675-901c-4756d7f2d45d")))
                {
                    If (LEqual (Arg2, 0x01))
                    {
                        Store (DerefOf (Index (Arg3, 0x00)), MOVV)
                        Return (0)
                    }
                    Return (Buffer () {0x03})
                }

                Return (Buffer () {0})
            }
        }
    }
}
