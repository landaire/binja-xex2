"""
Xbox 360 XEX2 + PE Loader for Binary Ninja

Loads XEX2-wrapped executables and Xbox 360 PowerPC PE images (e.g. xboxkrnl).
XEX2 parsing uses the `xex2` crate via its Python bindings. PPC64 lifting is
extended via an ArchitectureHook for the supervisor instructions BN does not
yet implement, plus a corrected Xbox 360 calling convention.
"""

from binaryninja import (
    Architecture, BinaryView, CallingConvention,
    Platform, Symbol, SymbolType,
    SegmentFlag, SectionSemantics,
    log_info, log_warn,
)
from binaryninja.architecture import ArchitectureHook
import os
import struct
import sys

# Binary Ninja's bundled Python doesn't see our uv venv by default. Inject the
# project venv's site-packages so we can `import xex2`. The project lives next
# to this file (either directly or via a symlink in BN's plugins dir).
_here = os.path.dirname(os.path.realpath(__file__))
# BN may run its bundled interpreter or (newer builds on Linux) the host's
# Python, so don't pin the venv's site-packages to a single minor version —
# glob whichever python3.* the local .venv was built for.
import glob
for _venv_site in glob.glob(os.path.join(_here, ".venv", "lib", "python3.*", "site-packages")):
    if os.path.isdir(_venv_site) and _venv_site not in sys.path:
        sys.path.insert(0, _venv_site)

try:
    import xex2 as _xex2_mod
except ImportError:
    _xex2_mod = None

try:
    # Loaded as a package (repo dir in BN's plugins folder): sibling module
    # is a relative import. Falls back to the absolute form when the two .py
    # files are dropped directly into the plugins folder instead.
    from .xbox360_ordinal_exports import ORDINAL_EXPORTS_BY_MODULE
except ImportError:
    try:
        from xbox360_ordinal_exports import ORDINAL_EXPORTS_BY_MODULE
    except ImportError:
        ORDINAL_EXPORTS_BY_MODULE = {}


# ============================================================================
# Xbox 360 Calling Convention & Platform
# ============================================================================

class Xbox360CallingConvention(CallingConvention):
    name = "xbox360"
    int_arg_regs = ["r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"]
    float_arg_regs = ["f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8"]
    int_return_reg = "r3"
    callee_saved_regs = [
        "r14", "r15", "r16", "r17", "r18", "r19", "r20", "r21",
        "r22", "r23", "r24", "r25", "r26", "r27", "r28", "r29",
        "r30", "r31",
    ]
    implicitly_defined_regs = ["r0", "r11", "r12"]

    def perform_get_incoming_reg_value(self, reg, func):
        from binaryninja.variable import RegisterValue
        return RegisterValue(value=0, offset=0)


class Xbox360PPC64Hook(ArchitectureHook):
    """Hook ppc64 IL lifting for Xbox 360.

    Fixes PPC64 ELF ABI assumptions (r11/r2 as call outputs) and adds
    IL for supervisor instructions the default lifter leaves unimplemented.
    """

    # Primary opcodes
    PPC_OP_TWI = 3
    PPC_OP_B = 18
    PPC_OP_BC = 16
    PPC_OP_X19 = 19   # isync, rfid, bctrl group
    PPC_OP_X31 = 31   # tw, sync, eieio, tlbiel, bctrl group

    # Extended opcodes (XO field) for opcode 19
    PPC_XO_RFID = 18
    PPC_XO_ISYNC = 150
    PPC_XO_BCCTR = 528

    # Extended opcodes (XO field) for opcode 31
    PPC_XO_TW = 4
    PPC_XO_MFMSR = 83
    PPC_XO_TLBIEL = 274
    PPC_XO_SYNC = 598
    PPC_XO_EIEIO = 854

    # Intrinsic IDs for supervisor/privileged instructions
    INTR_SYNC = 0x1000
    INTR_ISYNC = 0x1001
    INTR_EIEIO = 0x1002
    INTR_LWSYNC = 0x1003
    INTR_TLBIEL = 0x1004
    INTR_RFID = 0x1005
    INTR_MFMSR = 0x1006

    _INTRINSIC_NAMES = {
        INTR_SYNC: "__sync",
        INTR_ISYNC: "__isync",
        INTR_EIEIO: "__eieio",
        INTR_LWSYNC: "__lwsync",
        INTR_TLBIEL: "__tlbiel",
        INTR_RFID: "__rfid",
        INTR_MFMSR: "__mfmsr",
    }

    def get_intrinsic_name(self, intrinsic):
        return self._INTRINSIC_NAMES.get(
            intrinsic, super().get_intrinsic_name(intrinsic)
        )

    def get_instruction_low_level_il(self, data, addr, il):
        if len(data) < 4:
            return super().get_instruction_low_level_il(data, addr, il)

        instr = struct.unpack(">I", data[:4])[0]
        opcode = (instr >> 26) & 0x3F
        lk = instr & 1

        if opcode == self.PPC_OP_TWI:
            # twi TO, rA, SIMM - trap code is the immediate value
            simm = instr & 0xFFFF
            il.append(il.trap(simm))
            return 4

        if opcode == self.PPC_OP_B and lk == 1:
            # bl - direct call
            li = instr & 0x03FFFFFC
            if li & 0x02000000:
                li -= 0x04000000
            aa = (instr >> 1) & 1
            target = li if aa else (addr + li)
            il.append(il.call(il.const_pointer(self.address_size, target)))
            return 4

        if opcode == self.PPC_OP_X19:
            xo = (instr >> 1) & 0x3FF
            if xo == self.PPC_XO_BCCTR and lk == 1:
                # bctrl - indirect call through CTR
                il.append(il.call(il.reg(self.address_size, "ctr")))
                return 4
            if xo == self.PPC_XO_ISYNC:
                il.append(il.intrinsic([], self.INTR_ISYNC, []))
                return 4
            if xo == self.PPC_XO_RFID:
                il.append(il.intrinsic([], self.INTR_RFID, []))
                il.append(il.no_ret())
                return 4

        if opcode == self.PPC_OP_X31:
            xo = (instr >> 1) & 0x3FF
            if xo == self.PPC_XO_MFMSR:
                # mfmsr rD - read Machine State Register into rD
                rd = f"r{(instr >> 21) & 0x1F}"
                il.append(il.intrinsic(
                    [il.reg(8, rd)], self.INTR_MFMSR, []
                ))
                return 4
            if xo == self.PPC_XO_TW:
                # tw TO, rA, rB - use TO field as trap code
                to = (instr >> 21) & 0x1F
                il.append(il.trap(to))
                return 4
            if xo == self.PPC_XO_SYNC:
                # sync (L=0) or lwsync (L=1)
                l_field = (instr >> 21) & 0x3
                intr = self.INTR_LWSYNC if l_field == 1 else self.INTR_SYNC
                il.append(il.intrinsic([], intr, []))
                return 4
            if xo == self.PPC_XO_EIEIO:
                il.append(il.intrinsic([], self.INTR_EIEIO, []))
                return 4
            if xo == self.PPC_XO_TLBIEL:
                il.append(il.intrinsic([], self.INTR_TLBIEL, []))
                return 4

        return super().get_instruction_low_level_il(data, addr, il)


_xbox360_platform = None

try:
    _arch = Architecture["ppc64"]
    # Both loader packages share the Xbox 360 convention and architecture hook.
    _cc = _arch.calling_conventions.get("xbox360")
    if _cc is None:
        _cc = Xbox360CallingConvention(_arch, "xbox360")
        _arch.register_calling_convention(_cc)
        Xbox360PPC64Hook(_arch).register()
    _arch.default_calling_convention = _cc

    # Platform() construction changed across BN versions. Try each known
    # shape; fall back to the arch's standalone platform if none work.
    for _attempt in (
        lambda: Platform(_arch, "Xbox 360"),
        lambda: Platform.create(_arch, "Xbox 360"),
        lambda: _arch.standalone_platform,
    ):
        try:
            _xbox360_platform = _attempt()
            break
        except Exception:
            continue
    if _xbox360_platform is not None:
        try:
            _xbox360_platform.default_calling_convention = _cc
            _xbox360_platform.register("xbox360")
        except Exception:
            pass
    log_info("Registered Xbox 360 platform with architecture hook")
except Exception as e:
    log_warn(f"Failed to register Xbox 360 platform: {e}")


# ============================================================================
# PE Header Constants
# ============================================================================

PE_OFFSET_FIELD = 0x3C
PE_NUM_SECTIONS_OFF = 6
PE_OPT_HDR_SIZE_OFF = 20
PE_SECTION_HDRS_BASE = 24
PE_SECTION_HDR_SIZE = 40
PE_SEC_VSIZE_OFF = 8
PE_SEC_RVA_OFF = 12
PE_SEC_FLAGS_OFF = 36
PE_SCN_CNT_CODE = 0x00000020
PE_SCN_CNT_DATA = 0x00000040
PE_SCN_MEM_EXECUTE = 0x20000000
PE_SCN_MEM_READ = 0x40000000
PE_SCN_MEM_WRITE = 0x80000000

# COFF/Optional header offsets relative to the PE signature
PE_MACHINE_OFF = 4
PE_OPT_HDR_OFF = 24       # COFF header is 24 bytes
PE_OPT_MAGIC_PE32 = 0x10B
PE_OPT_MAGIC_PE32P = 0x20B
PE_OPT_IMAGE_BASE_OFF_PE32 = 28   # within optional header
PE_OPT_IMAGE_BASE_OFF_PE32P = 24
IMAGE_FILE_MACHINE_POWERPCBE = 0x01F2

# Xbox 360 Kernel Export Table
XEDATA_MAGIC0 = 0x48000000
XEDATA_MAGIC1 = 0x00485645
XEDATA_MAGIC2 = 0x48000000
XEDATA_EXPORT_COUNT_OFF = 36
XEDATA_BASE_ORDINAL_OFF = 40
XEDATA_ENTRIES_OFF = 44


# ============================================================================
# Kernel Data Tables
# ============================================================================

KERNEL_EXPORTS = [
    "DbgBreakPoint",
    "DbgBreakPointWithStatus",
    "DbgPrint",
    "DbgPrompt",
    "DumpGetRawDumpInfo",
    "DumpWriteDump",
    "ExAcquireReadWriteLockExclusive",
    "ExAcquireReadWriteLockShared",
    "ExAllocatePool",
    "ExAllocatePoolWithTag",
    "ExAllocatePoolTypeWithTag",
    "ExConsoleGameRegion",
    "ExCreateThread",
    "ExEventObjectType",
    "ExFreePool",
    "ExGetXConfigSetting",
    "ExInitializeReadWriteLock",
    "ExMutantObjectType",
    "ExQueryPoolBlockSize",
    "ExRegisterThreadNotification",
    "ExRegisterTitleTerminateNotification",
    "ExReleaseReadWriteLock",
    "ExSemaphoreObjectType",
    "ExSetXConfigSetting",
    "ExTerminateThread",
    "ExTerminateTitleProcess",
    "ExThreadObjectType",
    "ExTimerObjectType",
    "MmDoubleMapMemory",
    "MmUnmapMemory",
    "XeKeysGetConsoleCertificate",
    "FscGetCacheElementCount",
    "FscSetCacheElementCount",
    "HalGetCurrentAVPack",
    "HalGpioControl",
    "HalOpenCloseODDTray",
    "HalReadWritePCISpace",
    "HalRegisterPowerDownNotification",
    "HalRegisterSMCNotification",
    "HalReturnToFirmware",
    "HalSendSMCMessage",
    "HalSetAudioEnable",
    "InterlockedFlushSList",
    "InterlockedPopEntrySList",
    "InterlockedPushEntrySList",
    "IoAcquireDeviceObjectLock",
    "IoAllocateIrp",
    "IoBuildAsynchronousFsdRequest",
    "IoBuildDeviceIoControlRequest",
    "IoBuildSynchronousFsdRequest",
    "IoCallDriver",
    "IoCheckShareAccess",
    "IoCompleteRequest",
    "IoCompletionObjectType",
    "IoCreateDevice",
    "IoCreateFile",
    "IoDeleteDevice",
    "IoDeviceObjectType",
    "IoDismountVolume",
    "IoDismountVolumeByFileHandle",
    "IoDismountVolumeByName",
    "IoFileObjectType",
    "IoFreeIrp",
    "IoInitializeIrp",
    "IoInvalidDeviceRequest",
    "ExSetBetaFeaturesEnabled",
    "IoQueueThreadIrp",
    "IoReleaseDeviceObjectLock",
    "IoRemoveShareAccess",
    "IoSetIoCompletion",
    "IoSetShareAccess",
    "IoStartNextPacket",
    "IoStartNextPacketByKey",
    "IoStartPacket",
    "IoSynchronousDeviceIoControlRequest",
    "IoSynchronousFsdRequest",
    "KeAcquireSpinLockAtRaisedIrql",
    "KeAlertResumeThread",
    "KeAlertThread",
    "KeBlowFuses",
    "KeBoostPriorityThread",
    "KeBugCheck",
    "KeBugCheckEx",
    "KeCancelTimer",
    "KeConnectInterrupt",
    "KeContextFromKframes",
    "KeContextToKframes",
    "KeCreateUserMode",
    "KeDebugMonitorData",
    "KeDelayExecutionThread",
    "KeDeleteUserMode",
    "KeDisconnectInterrupt",
    "KeEnableFpuExceptions",
    "KeEnablePPUPerformanceMonitor",
    "KeEnterCriticalRegion",
    "KeEnterUserMode",
    "KeFlushCacheRange",
    "KeFlushCurrentEntireTb",
    "KeFlushEntireTb",
    "KeFlushUserModeCurrentTb",
    "KeFlushUserModeTb",
    "KeGetCurrentProcessType",
    "KeGetPMWRegister",
    "KeGetPRVRegister",
    "KeGetSocRegister",
    "KeGetSpecialPurposeRegister",
    "KeLockL2",
    "KeUnlockL2",
    "KeInitializeApc",
    "KeInitializeDeviceQueue",
    "KeInitializeDpc",
    "KeInitializeEvent",
    "KeInitializeInterrupt",
    "KeInitializeMutant",
    "KeInitializeQueue",
    "KeInitializeSemaphore",
    "KeInitializeTimerEx",
    "KeInsertByKeyDeviceQueue",
    "KeInsertDeviceQueue",
    "KeInsertHeadQueue",
    "KeInsertQueue",
    "KeInsertQueueApc",
    "KeInsertQueueDpc",
    "KeIpiGenericCall",
    "KeLeaveCriticalRegion",
    "KeLeaveUserMode",
    "KePulseEvent",
    "KeQueryBackgroundProcessors",
    "KeQueryBasePriorityThread",
    "KeQueryInterruptTime",
    "KeQueryPerformanceFrequency",
    "KeQuerySystemTime",
    "KeRaiseIrqlToDpcLevel",
    "KeRegisterDriverNotification",
    "KeReleaseMutant",
    "KeReleaseSemaphore",
    "KeReleaseSpinLockFromRaisedIrql",
    "KeRemoveByKeyDeviceQueue",
    "KeRemoveDeviceQueue",
    "KeRemoveEntryDeviceQueue",
    "KeRemoveQueue",
    "KeRemoveQueueDpc",
    "KeResetEvent",
    "KeRestoreFloatingPointState",
    "KeRestoreVectorUnitState",
    "KeResumeThread",
    "KeRetireDpcList",
    "KeRundownQueue",
    "KeSaveFloatingPointState",
    "KeSaveVectorUnitState",
    "KeSetAffinityThread",
    "KeSetBackgroundProcessors",
    "KeSetBasePriorityThread",
    "KeSetCurrentProcessType",
    "KeSetCurrentStackPointers",
    "KeSetDisableBoostThread",
    "KeSetEvent",
    "KeSetEventBoostPriority",
    "KeSetPMWRegister",
    "KeSetPowerMode",
    "KeSetPRVRegister",
    "KeSetPriorityClassThread",
    "KeSetPriorityThread",
    "KeSetSocRegister",
    "KeSetSpecialPurposeRegister",
    "KeSetTimer",
    "KeSetTimerEx",
    "KeStallExecutionProcessor",
    "KeSuspendThread",
    "KeSweepDcacheRange",
    "KeSweepIcacheRange",
    "KeTestAlertThread",
    "KeTimeStampBundle",
    "KeTryToAcquireSpinLockAtRaisedIrql",
    "KeWaitForMultipleObjects",
    "KeWaitForSingleObject",
    "KfAcquireSpinLock",
    "KfRaiseIrql",
    "KfLowerIrql",
    "KfReleaseSpinLock",
    "KiBugCheckData",
    "LDICreateDecompression",
    "LDIDecompress",
    "LDIDestroyDecompression",
    "MmAllocatePhysicalMemory",
    "MmAllocatePhysicalMemoryEx",
    "MmCreateKernelStack",
    "MmDeleteKernelStack",
    "MmFreePhysicalMemory",
    "MmGetPhysicalAddress",
    "MmIsAddressValid",
    "MmLockAndMapSegmentArray",
    "MmLockUnlockBufferPages",
    "MmMapIoSpace",
    "MmPersistPhysicalMemoryAllocation",
    "MmQueryAddressProtect",
    "MmQueryAllocationSize",
    "MmQueryStatistics",
    "MmSetAddressProtect",
    "MmSplitPhysicalMemoryAllocation",
    "MmUnlockAndUnmapSegmentArray",
    "MmUnmapIoSpace",
    "Nls844UnicodeCaseTable",
    "NtAllocateVirtualMemory",
    "NtCancelTimer",
    "NtClearEvent",
    "NtClose",
    "NtCreateDirectoryObject",
    "NtCreateEvent",
    "NtCreateFile",
    "NtCreateIoCompletion",
    "NtCreateMutant",
    "NtCreateSemaphore",
    "NtCreateSymbolicLinkObject",
    "NtCreateTimer",
    "NtDeleteFile",
    "NtDeviceIoControlFile",
    "NtDuplicateObject",
    "NtFlushBuffersFile",
    "NtFreeVirtualMemory",
    "NtMakeTemporaryObject",
    "NtOpenDirectoryObject",
    "NtOpenFile",
    "NtOpenSymbolicLinkObject",
    "NtProtectVirtualMemory",
    "NtPulseEvent",
    "NtQueueApcThread",
    "NtQueryDirectoryFile",
    "NtQueryDirectoryObject",
    "NtQueryEvent",
    "NtQueryFullAttributesFile",
    "NtQueryInformationFile",
    "NtQueryIoCompletion",
    "NtQueryMutant",
    "NtQuerySemaphore",
    "NtQuerySymbolicLinkObject",
    "NtQueryTimer",
    "NtQueryVirtualMemory",
    "NtQueryVolumeInformationFile",
    "NtReadFile",
    "NtReadFileScatter",
    "NtReleaseMutant",
    "NtReleaseSemaphore",
    "NtRemoveIoCompletion",
    "NtResumeThread",
    "NtSetEvent",
    "NtSetInformationFile",
    "NtSetIoCompletion",
    "NtSetSystemTime",
    "NtSetTimerEx",
    "NtSignalAndWaitForSingleObjectEx",
    "NtSuspendThread",
    "NtWaitForSingleObjectEx",
    "NtWaitForMultipleObjectsEx",
    "NtWriteFile",
    "NtWriteFileGather",
    "NtYieldExecution",
    "ObCreateObject",
    "ObCreateSymbolicLink",
    "ObDeleteSymbolicLink",
    "ObDereferenceObject",
    "ObDirectoryObjectType",
    "ObGetWaitableObject",
    "ObInsertObject",
    "ObIsTitleObject",
    "ObLookupAnyThreadByThreadId",
    "ObLookupThreadByThreadId",
    "ObMakeTemporaryObject",
    "ObOpenObjectByName",
    "ObOpenObjectByPointer",
    "ObReferenceObject",
    "ObReferenceObjectByHandle",
    "ObReferenceObjectByName",
    "ObSymbolicLinkObjectType",
    "ObTranslateSymbolicLink",
    "RtlAnsiStringToUnicodeString",
    "RtlAppendStringToString",
    "RtlAppendUnicodeStringToString",
    "RtlAppendUnicodeToString",
    "RtlAssert",
    "RtlCaptureContext",
    "RtlCompareMemory",
    "RtlCompareMemoryUlong",
    "RtlCompareString",
    "RtlCompareStringN",
    "RtlCompareUnicodeString",
    "RtlCompareUnicodeStringN",
    "RtlCompareUtf8ToUnicode",
    "RtlCopyString",
    "RtlCopyUnicodeString",
    "RtlCreateUnicodeString",
    "RtlDowncaseUnicodeChar",
    "RtlEnterCriticalSection",
    "RtlFillMemoryUlong",
    "RtlFreeAnsiString",
    "RtlFreeAnsiString",
    "RtlGetCallersAddress",
    "RtlGetStackLimits",
    "RtlImageXexHeaderField",
    "RtlInitAnsiString",
    "RtlInitUnicodeString",
    "RtlInitializeCriticalSection",
    "RtlInitializeCriticalSectionAndSpinCount",
    "RtlLeaveCriticalSection",
    "RtlLookupFunctionEntry",
    "RtlLowerChar",
    "RtlMultiByteToUnicodeN",
    "RtlMultiByteToUnicodeSize",
    "RtlNtStatusToDosError",
    "RtlRaiseException",
    "RtlRaiseStatus",
    "RtlRip",
    "_scprintf",
    "_snprintf",
    "sprintf",
    "_scwprintf",
    "_snwprintf",
    "_swprintf",
    "RtlTimeFieldsToTime",
    "RtlTimeToTimeFields",
    "RtlTryEnterCriticalSection",
    "RtlUnicodeStringToAnsiString",
    "RtlUnicodeToMultiByteN",
    "RtlUnicodeToMultiByteSize",
    "RtlUnicodeToUtf8",
    "RtlUnicodeToUtf8Size",
    "RtlUnwind",
    "RtlUnwind2",
    "RtlUpcaseUnicodeChar",
    "RtlUpperChar",
    "RtlVirtualUnwind",
    "_vscprintf",
    "_vsnprintf",
    "vsprintf",
    "_vscwprintf",
    "_vsnwprintf",
    "_vswprintf",
    "KeTlsAlloc",
    "KeTlsFree",
    "KeTlsGetValue",
    "KeTlsSetValue",
    "XboxHardwareInfo",
    "XboxKrnlBaseVersion",
    "XboxKrnlVersion",
    "XeCryptAesKey",
    "XeCryptAesEcb",
    "XeCryptAesCbc",
    "XeCryptBnDwLeDhEqualBase",
    "XeCryptBnDwLeDhInvalBase",
    "XeCryptBnDwLeDhModExp",
    "XeCryptBnDw_Copy",
    "XeCryptBnDw_SwapLeBe",
    "XeCryptBnDw_Zero",
    "XeCryptBnDwLePkcs1Format",
    "XeCryptBnDwLePkcs1Verify",
    "XeCryptBnQwBeSigCreate",
    "XeCryptBnQwBeSigFormat",
    "XeCryptBnQwBeSigVerify",
    "XeCryptBnQwNeModExp",
    "XeCryptBnQwNeModExpRoot",
    "XeCryptBnQwNeModInv",
    "XeCryptBnQwNeModMul",
    "XeCryptBnQwNeRsaKeyGen",
    "XeCryptBnQwNeRsaPrvCrypt",
    "XeCryptBnQwNeRsaPubCrypt",
    "XeCryptBnQw_Copy",
    "XeCryptBnQw_SwapDwQw",
    "XeCryptBnQw_SwapDwQwLeBe",
    "XeCryptBnQw_SwapLeBe",
    "XeCryptBnQw_Zero",
    "XeCryptChainAndSumMac",
    "XeCryptDesParity",
    "XeCryptDesKey",
    "XeCryptDesEcb",
    "XeCryptDesCbc",
    "XeCryptDes3Key",
    "XeCryptDes3Ecb",
    "XeCryptDes3Cbc",
    "XeCryptHmacMd5Init",
    "XeCryptHmacMd5Update",
    "XeCryptHmacMd5Final",
    "XeCryptHmacMd5",
    "XeCryptHmacShaInit",
    "XeCryptHmacShaUpdate",
    "XeCryptHmacShaFinal",
    "XeCryptHmacSha",
    "XeCryptHmacShaVerify",
    "XeCryptMd5Init",
    "XeCryptMd5Update",
    "XeCryptMd5Final",
    "XeCryptMd5",
    "XeCryptParveEcb",
    "XeCryptParveCbcMac",
    "XeCryptRandom",
    "XeCryptRc4Key",
    "XeCryptRc4Ecb",
    "XeCryptRc4",
    "XeCryptRotSumSha",
    "XeCryptShaInit",
    "XeCryptShaUpdate",
    "XeCryptShaFinal",
    "XeCryptSha",
    "XexExecutableModuleHandle",
    "XexCheckExecutablePrivilege",
    "XexGetModuleHandle",
    "XexGetModuleSection",
    "XexGetProcedureAddress",
    "XexLoadExecutable",
    "XexLoadImage",
    "XexLoadImageFromMemory",
    "XexLoadImageHeaders",
    "XexPcToFileHeader",
    "KiApcNormalRoutineNop",
    "XexRegisterPatchDescriptor",
    "XexSendDeferredNotifications",
    "XexStartExecutable",
    "XexUnloadImage",
    "XexUnloadImageAndExitThread",
    "XexUnloadTitleModules",
    "XexVerifyImageHeaders",
    "__C_specific_handler",
    "DbgLoadImageSymbols",
    "DbgUnLoadImageSymbols",
    "RtlImageDirectoryEntryToData",
    "RtlImageNtHeader",
    "ExDebugMonitorService",
    "MmDbgReadCheck",
    "MmDbgReleaseAddress",
    "MmDbgWriteCheck",
    "ExLoadedCommandLine",
    "ExLoadedImageName",
    "VdBlockUntilGUIIdle",
    "VdCallGraphicsNotificationRoutines",
    "VdDisplayFatalError",
    "VdEnableClosedCaption",
    "VdEnableDisableClockGating",
    "VdEnableDisablePowerSavingMode",
    "VdEnableRingBufferRPtrWriteBack",
    "VdGenerateGPUCSCCoefficients",
    "VdGetClosedCaptionReadyStatus",
    "VdGetCurrentDisplayGamma",
    "VdGetCurrentDisplayInformation",
    "VdGetDisplayModeOverride",
    "VdGetGraphicsAsicID",
    "VdGetSystemCommandBuffer",
    "VdGlobalDevice",
    "VdGlobalXamDevice",
    "VdGpuClockInMHz",
    "VdHSIOCalibrationLock",
    "VdInitializeEngines",
    "VdInitializeRingBuffer",
    "VdInitializeScaler",
    "VdInitializeScalerCommandBuffer",
    "VdIsHSIOTrainingSucceeded",
    "VdPersistDisplay",
    "VdQuerySystemCommandBuffer",
    "VdQueryVideoFlags",
    "VdQueryVideoMode",
    "VdReadDVERegisterUlong",
    "VdReadWriteHSIOCalibrationFlag",
    "VdRegisterGraphicsNotification",
    "VdRegisterXamGraphicsNotification",
    "VdSendClosedCaptionData",
    "VdSetCGMSOption",
    "VdSetColorProfileAdjustment",
    "VdSetCscMatricesOverride",
    "VdSetDisplayMode",
    "VdSetDisplayModeOverride",
    "VdSetGraphicsInterruptCallback",
    "VdSetHDCPOption",
    "VdSetMacrovisionOption",
    "VdSetSystemCommandBuffer",
    "VdSetSystemCommandBufferGpuIdentifierAddress",
    "VdSetWSSData",
    "VdSetWSSOption",
    "VdShutdownEngines",
    "VdTurnDisplayOff",
    "VdTurnDisplayOn",
    "KiApcNormalRoutineNop",
    "VdWriteDVERegisterUlong",
    "XVoicedHeadsetPresent",
    "XVoicedSubmitPacket",
    "XVoicedClose",
    "XVoicedActivate",
    "XInputdGetCapabilities",
    "XInputdReadState",
    "XInputdWriteState",
    "XInputdNotify",
    "XInputdRawState",
    "HidGetCapabilities",
    "HidReadKeys",
    "XInputdGetDeviceStats",
    "XInputdResetDevice",
    "XInputdSetRingOfLight",
    "XInputdSetRFPowerMode",
    "XInputdSetRadioFrequency",
    "HidGetLastInputTime",
    "XAudioRenderDriverInitialize",
    "XAudioRegisterRenderDriverClient",
    "XAudioUnregisterRenderDriverClient",
    "XAudioSubmitRenderDriverFrame",
    "XAudioRenderDriverLock",
    "XAudioGetVoiceCategoryVolumeChangeMask",
    "XAudioGetVoiceCategoryVolume",
    "XAudioSetVoiceCategoryVolume",
    "XAudioBeginDigitalBypassMode",
    "XAudioEndDigitalBypassMode",
    "XAudioSubmitDigitalPacket",
    "XAudioQueryDriverPerformance",
    "XAudioGetRenderDriverThread",
    "XAudioGetSpeakerConfig",
    "XAudioSetSpeakerConfig",
    "NicSetUnicastAddress",
    "NicAttach",
    "NicDetach",
    "NicXmit",
    "NicUpdateMcastMembership",
    "NicFlushXmitQueue",
    "NicShutdown",
    "NicGetLinkState",
    "NicGetStats",
    "NicGetOpt",
    "NicSetOpt",
    "DrvSetSysReqCallback",
    "DrvSetUserBindingCallback",
    "DrvSetContentStorageCallback",
    "DrvSetAutobind",
    "DrvGetContentStorageNotification",
    "MtpdBeginTransaction",
    "MtpdCancelTransaction",
    "MtpdEndTransaction",
    "MtpdGetCurrentDevices",
    "MtpdReadData",
    "MtpdReadEvent",
    "MtpdResetDevice",
    "MtpdSendData",
    "MtpdVerifyProximity",
    "XUsbcamSetCaptureMode",
    "XUsbcamGetConfig",
    "XUsbcamSetConfig",
    "XUsbcamGetState",
    "XUsbcamReadFrame",
    "XUsbcamSnapshot",
    "XUsbcamSetView",
    "XUsbcamGetView",
    "XUsbcamCreate",
    "XUsbcamDestroy",
    "XMACreateContext",
    "XMAInitializeContext",
    "XMAReleaseContext",
    "XMAEnableContext",
    "XMADisableContext",
    "XMAGetOutputBufferWriteOffset",
    "XMASetOutputBufferReadOffset",
    "XMAGetOutputBufferReadOffset",
    "XMASetOutputBufferValid",
    "XMAIsOutputBufferValid",
    "XMASetInputBuffer0Valid",
    "XMAIsInputBuffer0Valid",
    "XMASetInputBuffer1Valid",
    "XMAIsInputBuffer1Valid",
    "XMASetInputBuffer0",
    "XMASetInputBuffer1",
    "XMAGetPacketMetadata",
    "XMABlockWhileInUse",
    "XMASetLoopData",
    "XMASetInputBufferReadOffset",
    "XMAGetInputBufferReadOffset",
    "ExIsBetaFeatureEnabled",
    "XeKeysGetFactoryChallenge",
    "XeKeysSetFactoryResponse",
    "XeKeysInitializeFuses",
    "XeKeysSaveBootLoader",
    "XeKeysSaveKeyVault",
    "XeKeysGetStatus",
    "XeKeysGeneratePrivateKey",
    "XeKeysGetKeyProperties",
    "XeKeysSetKey",
    "XeKeysGenerateRandomKey",
    "XeKeysGetKey",
    "XeKeysGetDigest",
    "XeKeysGetConsoleID",
    "XeKeysGetConsoleType",
    "XeKeysQwNeRsaPrvCrypt",
    "XeKeysHmacSha",
    "XInputdPassThroughRFCommand",
    "XeKeysAesCbc",
    "XeKeysDes2Cbc",
    "XeKeysDesCbc",
    "XeKeysObscureKey",
    "XeKeysHmacShaUsingKey",
    "XeKeysSaveBootLoaderEx",
    "XeKeysAesCbcUsingKey",
    "XeKeysDes2CbcUsingKey",
    "XeKeysDesCbcUsingKey",
    "XeKeysObfuscate",
    "XeKeysUnObfuscate",
    "XeKeysConsolePrivateKeySign",
    "XeKeysConsoleSignatureVerification",
    "XeKeysVerifyRSASignature",
    "StfsCreateDevice",
    "StfsControlDevice",
    "VdSwap",
    "HalFsbInterruptCount",
    "XeKeysSaveSystemUpdate",
    "XeKeysLockSystemUpdate",
    "XeKeysExecute",
    "XeKeysGetVersions",
    "XInputdPowerDownDevice",
    "AniBlockOnAnimation",
    "AniTerminateAnimation",
    "XUsbcamReset",
    "AniSetLogo",
    "KeCertMonitorData",
    "HalIsExecutingPowerDownDpc",
    "VdInitializeEDRAM",
    "VdRetrainEDRAM",
    "VdRetrainEDRAMWorker",
    "VdHSIOTrainCount",
    "HalGetPowerUpCause",
    "VdHSIOTrainingStatus",
    "RgcBindInfo",
    "VdReadEEDIDBlock",
    "VdEnumerateVideoModes",
    "VdEnableHDCP",
    "VdRegisterHDCPNotification",
    "HidReadMouseChanges",
    "DumpSetCollectionFacility",
    "XexTransformImageKey",
    "XAudioOverrideSpeakerConfig",
    "XInputdReadTextKeystroke",
    "DrvXenonButtonPressed",
    "DrvBindToUser",
    "XexGetModuleImportVersions",
    "RtlComputeCrc32",
    "XeKeysSetRevocationList",
    "HalRegisterPowerDownCallback",
    "VdGetDisplayDiscoveryData",
    "XInputdSendStayAliveRequest",
    "XVoicedSendVPort",
    "XVoicedGetBatteryStatus",
    "XInputdFFGetDeviceInfo",
    "XInputdFFSetEffect",
    "XInputdFFUpdateEffect",
    "XInputdFFEffectOperation",
    "XInputdFFDeviceControl",
    "XInputdFFSetDeviceGain",
    "XInputdFFCancelIo",
    "XInputdFFSetRumble",
    "NtAllocateEncryptedMemory",
    "NtFreeEncryptedMemory",
    "XeKeysExSaveKeyVault",
    "XeKeysExSetKey",
    "XeKeysExGetKey",
    "DrvSetDeviceConfigChangeCallback",
    "DrvDeviceConfigChange",
    "HalRegisterHdDvdRomNotification",
    "XeKeysSecurityInitialize",
    "XeKeysSecurityLoadSettings",
    "XeKeysSecuritySaveSettings",
    "XeKeysSecuritySetDetected",
    "XeKeysSecurityGetDetected",
    "XeKeysSecuritySetActivated",
    "XeKeysSecurityGetActivated",
    "XeKeysDvdAuthAP25InstallTable",
    "XeKeysDvdAuthAP25GetTableVersion",
    "XeKeysGetProtectedFlag",
    "XeKeysSetProtectedFlag",
    "KeEnablePFMInterrupt",
    "KeDisablePFMInterrupt",
    "KeSetProfilerISR",
    "VdStartDisplayDiscovery",
    "VdSetHDCPRevocationList",
    "XeKeysGetUpdateSequence",
    "XeKeysDvdAuthExActivate",
    "KeGetImagePageTableEntry",
    "HalRegisterBackgroundModeTransitionCallback",
    "AniStartBootAnimation",
    "HalClampUnclampOutputDACs",
    "HalPowerDownToBackgroundMode",
    "HalNotifyAddRemoveBackgroundTask",
    "HalCallBackgroundModeNotificationRoutines",
    "HalFsbResetCount",
    "HalGetMemoryInformation",
    "XInputdGetLastTextInputTime",
    "VdEnableWMAProOverHDMI",
    "XeKeysRevokeSaveSettings",
    "XInputdSetTextMessengerIndicator",
    "MicDeviceRequest",
    "XeKeysGetMediaID",
    "XeKeysLoadKeyVault",
    "KeGetVidInfo",
    "HalNotifyBackgroundModeTransitionComplete",
    "IoAcquireCancelSpinLock",
    "IoReleaseCancelSpinLock",
    "NtCancelIoFile",
    "NtCancelIoFileEx",
    "HalFinalizePowerLossRecovery",
    "HalSetPowerLossRecovery",
    "ExReadModifyWriteXConfigSettingUlong",
    "HalRegisterXamPowerDownCallback",
    "ExCancelAlarm",
    "ExInitializeAlarm",
    "ExSetAlarm",
    "XexActivationGetNonce",
    "XexActivationSetLicense",
    "IptvSetBoundaryKey",
    "IptvSetSessionKey",
    "IptvVerifyOmac1Signature",
    "IptvGetAesCtrTransform",
    "SataCdRomRecordReset",
    "XInputdSetTextDeviceKeyLocks",
    "XInputdGetTextDeviceKeyLocks",
    "XexActivationVerifyOwnership",
    "XexDisableVerboseDbgPrint",
    "SvodCreateDevice",
    "RtlCaptureStackBackTrace",
    "XeKeysRevokeUpdateDynamic",
    "XexImportTraceEnable",
    "ExRegisterXConfigNotification",
    "XeKeysSecuritySetStat",
    "VdQueryRealVideoMode",
    "XexSetExecutablePrivilege",
    "XAudioSuspendRenderDriverClients",
    "IptvGetSessionKeyHash",
    "VdSetCGMSState",
    "VdSetSCMSState",
    "KeFlushMultipleTb",
    "VdGetOption",
    "VdSetOption",
    "UsbdBootEnumerationDoneEvent",
    "StfsDeviceErrorEvent",
    "ExTryToAcquireReadWriteLockExclusive",
    "ExTryToAcquireReadWriteLockShared",
    "XexSetLastKdcTime",
    "XInputdControl",
    "RmcDeviceRequest",
    "LDIResetDecompression",
    "NicRegisterDevice",
    "UsbdAddDeviceComplete",
    "UsbdCancelAsyncTransfer",
    "UsbdGetDeviceSpeed",
    "UsbdGetDeviceTopology",
    "UsbdGetEndpointDescriptor",
    "UsbdIsDeviceAuthenticated",
    "UsbdOpenDefaultEndpoint",
    "UsbdOpenEndpoint",
    "UsbdQueueAsyncTransfer",
    "UsbdQueueCloseDefaultEndpoint",
    "UsbdQueueCloseEndpoint",
    "UsbdRemoveDeviceComplete",
    "KeRemoveQueueApc",
    "UsbdDriverLoadRequiredEvent",
    "UsbdGetRequiredDrivers",
    "UsbdRegisterDriverObject",
    "UsbdUnregisterDriverObject",
    "UsbdCallAndBlockOnDpcRoutine",
    "UsbdResetDevice",
    "UsbdGetDeviceDescriptor",
    "NomnilGetExtension",
    "NomnilStartCloseDevice",
    "WifiBeginAuthentication",
    "WifiCheckCounterMeasures",
    "WifiChooseAuthenCipherSetFromBSSID",
    "WifiCompleteAuthentication",
    "WifiGetAssociationIE",
    "WifiOnMICError",
    "WifiPrepareAuthenticationContext",
    "WifiRecvEAPOLPacket",
    "WifiDeduceNetworkType",
    "NicUnregisterDevice",
    "DumpXitThread",
    "XInputdSetWifiChannel",
    "NomnilSetLed",
    "WifiCalculateRegulatoryDomain",
    "WifiSelectAdHocChannel",
    "WifiChannelToFrequency",
    "MmGetPoolPagesType",
    "ExExpansionInstall",
    "ExExpansionCall",
    "PsCamDeviceRequest",
    "McaDeviceRequest",
    "DetroitDeviceRequest",
    "XeCryptSha256Init",
    "XeCryptSha256Update",
    "XeCryptSha256Final",
    "XeCryptSha256",
    "XeCryptSha384Init",
    "XeCryptSha384Update",
    "XInputdGetDevicePid",
    "HalGetNotedArgonErrors",
    "XeCryptSha384Final",
    "HalReadArgonEeprom",
    "HalWriteArgonEeprom",
    "XeKeysFcrtLoad",
    "XeKeysFcrtSave",
    "XeKeysFcrtSet",
    "XeCryptSha384",
    "XeCryptSha512Init",
    "XAudioRegisterRenderDriverMECClient",
    "XAudioUnregisterRenderDriverMECClient",
    "XAudioCaptureRenderDriverFrame",
    "XeCryptSha512Update",
    "XeCryptSha512Final",
    "XeCryptSha512",
    "XeCryptBnQwNeCompare",
    "XVoicedGetDirectionalData",
    "DrvSetMicArrayStartCallback",
    "DevAuthGetStatistics",
    "NullCableRequest",
    "XeKeysRevokeIsDeviceRevoked",
    "DumpUpdateDumpSettings",
    "EtxConsumerDisableEventType",
    "EtxConsumerEnableEventType",
    "EtxConsumerProcessLogs",
    "EtxConsumerRegister",
    "EtxConsumerUnregister",
    "EtxProducerLog",
    "EtxProducerLogV",
    "EtxProducerRegister",
    "EtxProducerUnregister",
    "EtxConsumerFlushBuffers",
    "EtxProducerLogXwpp",
    "EtxProducerLogXwppV",
    "UsbdEnableDisableRootHubPort",
    "EtxBufferRegister",
    "EtxBufferUnregister",
    "DumpRegisterDedicatedDataBlock",
    "XeKeysDvdAuthExSave",
    "XeKeysDvdAuthExInstall",
    "XexShimDisable",
    "XexShimEnable",
    "XexShimEntryDisable",
    "XexShimEntryEnable",
    "XexShimEntryRegister",
    "XexShimLock",
    "XboxKrnlVersion4Digit",
    "XeKeysObfuscateEx",
    "XeKeysUnObfuscateEx",
    "XexTitleHash",
    "XexTitleHashClose",
    "XexTitleHashContinue",
    "XexTitleHashOpen",
    "XAudioGetRenderDriverTic",
    "XAudioEnableDucker",
    "XAudioSetDuckerLevel",
    "XAudioIsDuckerEnabled",
    "XAudioGetDuckerLevel",
    "XAudioGetDuckerThreshold",
    "XAudioSetDuckerThreshold",
    "XAudioGetDuckerAttackTime",
    "XAudioSetDuckerAttackTime",
    "XAudioGetDuckerReleaseTime",
    "XAudioSetDuckerReleaseTime",
    "XAudioGetDuckerHoldTime",
    "XAudioSetDuckerHoldTime",
    "DevAuthShouldAlwaysEnforce",
    "XAudioGetUnderrunCount",
    "",
    "XVoicedIsActiveProcess",
]

KERNEL_DATA_EXPORTS = {
    "ExEventObjectType",
    "ExMutantObjectType",
    "ExSemaphoreObjectType",
    "ExThreadObjectType",
    "ExTimerObjectType",
    "IoCompletionObjectType",
    "IoDeviceObjectType",
    "IoFileObjectType",
    "ObDirectoryObjectType",
    "ObSymbolicLinkObjectType",
    "XboxHardwareInfo",
    "XboxKrnlBaseVersion",
    "XboxKrnlVersion",
    "XboxKrnlVersion4Digit",
    "KiBugCheckData",
    "KeDebugMonitorData",
    "KeCertMonitorData",
    "KeTimeStampBundle",
    "Nls844UnicodeCaseTable",
    "ExLoadedCommandLine",
    "ExLoadedImageName",
    "VdGlobalDevice",
    "VdGlobalXamDevice",
    "VdGpuClockInMHz",
    "VdHSIOCalibrationLock",
    "VdHSIOTrainCount",
    "VdHSIOTrainingStatus",
    "HalFsbInterruptCount",
    "HalFsbResetCount",
    "XexExecutableModuleHandle",
    "RgcBindInfo",
    "UsbdBootEnumerationDoneEvent",
    "StfsDeviceErrorEvent",
}

KERNEL_DATA_EXPORT_TYPES = {
    "XboxKrnlVersion": "struct XBOX_KRNL_VERSION",
    "XboxKrnlBaseVersion": "struct XBOX_KRNL_VERSION",
    "XboxKrnlVersion4Digit": "struct XBOX_KRNL_VERSION",
    "XboxHardwareInfo": "struct XBOX_HARDWARE_INFO",
    "KiBugCheckData": "uint32_t[5]",
    "ExEventObjectType": "void*",
    "ExMutantObjectType": "void*",
    "ExSemaphoreObjectType": "void*",
    "ExThreadObjectType": "void*",
    "ExTimerObjectType": "void*",
    "IoCompletionObjectType": "void*",
    "IoDeviceObjectType": "void*",
    "IoFileObjectType": "void*",
    "ObDirectoryObjectType": "void*",
    "ObSymbolicLinkObjectType": "void*",
    "KeDebugMonitorData": "void*",
    "KeCertMonitorData": "void*",
    "ExLoadedCommandLine": "char*",
    "ExLoadedImageName": "char*",
    "VdGlobalDevice": "void*",
    "VdGlobalXamDevice": "void*",
    "VdGpuClockInMHz": "uint32_t",
    "VdHSIOCalibrationLock": "uint32_t",
    "VdHSIOTrainCount": "uint32_t",
    "VdHSIOTrainingStatus": "uint32_t",
    "HalFsbInterruptCount": "uint32_t",
    "HalFsbResetCount": "uint32_t",
    "XexExecutableModuleHandle": "void*",
    "Nls844UnicodeCaseTable": "void*",
    "KeTimeStampBundle": "uint64_t",
}


# ============================================================================
# Xbox 360 Type Definitions (C source for Binary Ninja type parser)
# ============================================================================

XBOX360_CRYPTO_TYPES_C = """
struct XECRYPT_SHA_STATE {
    uint32_t count;
    uint32_t state[5];
    uint8_t buffer[64];
};

struct XECRYPT_HMACSHA_STATE {
    struct XECRYPT_SHA_STATE ShaState[2];
};

struct XECRYPT_MD5_STATE {
    uint32_t count;
    uint32_t state[4];
    uint8_t buffer[64];
};

struct XECRYPT_AES_STATE {
    uint8_t keytabenc[176];
    uint8_t keytabdec[176];
};

struct XECRYPT_RC4_STATE {
    uint8_t S[256];
    uint8_t i;
    uint8_t j;
};

struct XECRYPT_DES_STATE {
    uint32_t keytab[32];
};

struct XECRYPT_DES3_STATE {
    struct XECRYPT_DES_STATE aDesState[3];
};

struct XECRYPT_SHA256_STATE {
    uint32_t count;
    uint32_t state[8];
    uint8_t buffer[64];
};

struct XECRYPT_SHA384_STATE {
    uint64_t count;
    uint64_t state[8];
    uint8_t buffer[128];
};

struct XECRYPT_SHA512_STATE {
    uint64_t count;
    uint64_t state[8];
    uint8_t buffer[128];
};
"""


# ============================================================================
# Function Signatures
# ============================================================================

XCRYPT_SIGNATURES = {
    # SHA-1
    "XeCryptShaInit": "void XeCryptShaInit(struct XECRYPT_SHA_STATE* pShaState)",
    "XeCryptShaUpdate": "void XeCryptShaUpdate(struct XECRYPT_SHA_STATE* pShaState, void* pData, uint32_t cbData)",
    "XeCryptShaFinal": "void XeCryptShaFinal(struct XECRYPT_SHA_STATE* pShaState, uint8_t* pbOut, uint32_t cbOut)",
    "XeCryptSha": "void XeCryptSha(void* pData1, uint32_t cbData1, void* pData2, uint32_t cbData2, void* pData3, uint32_t cbData3, uint8_t* pbOut, uint32_t cbOut)",
    # HMAC-SHA
    "XeCryptHmacShaInit": "void XeCryptHmacShaInit(struct XECRYPT_HMACSHA_STATE* pHmacShaState, uint8_t* pbKey, uint32_t cbKey)",
    "XeCryptHmacShaUpdate": "void XeCryptHmacShaUpdate(struct XECRYPT_HMACSHA_STATE* pHmacShaState, void* pData, uint32_t cbData)",
    "XeCryptHmacShaFinal": "void XeCryptHmacShaFinal(struct XECRYPT_HMACSHA_STATE* pHmacShaState, uint8_t* pbOut, uint32_t cbOut)",
    "XeCryptHmacSha": "void XeCryptHmacSha(uint8_t* pbKey, uint32_t cbKey, void* pData1, uint32_t cbData1, void* pData2, uint32_t cbData2, void* pData3, uint32_t cbData3, uint8_t* pbOut, uint32_t cbOut)",
    "XeCryptHmacShaVerify": "BOOLEAN XeCryptHmacShaVerify(uint8_t* pbKey, uint32_t cbKey, void* pData1, uint32_t cbData1, void* pData2, uint32_t cbData2, void* pData3, uint32_t cbData3, uint8_t* pbHash, uint32_t cbHash)",
    # MD5
    "XeCryptMd5Init": "void XeCryptMd5Init(struct XECRYPT_MD5_STATE* pMd5State)",
    "XeCryptMd5Update": "void XeCryptMd5Update(struct XECRYPT_MD5_STATE* pMd5State, void* pData, uint32_t cbData)",
    "XeCryptMd5Final": "void XeCryptMd5Final(struct XECRYPT_MD5_STATE* pMd5State, uint8_t* pbOut, uint32_t cbOut)",
    "XeCryptMd5": "void XeCryptMd5(void* pData1, uint32_t cbData1, void* pData2, uint32_t cbData2, void* pData3, uint32_t cbData3, uint8_t* pbOut, uint32_t cbOut)",
    # HMAC-MD5
    "XeCryptHmacMd5Init": "void XeCryptHmacMd5Init(void* pHmacMd5State, uint8_t* pbKey, uint32_t cbKey)",
    "XeCryptHmacMd5Update": "void XeCryptHmacMd5Update(void* pHmacMd5State, void* pData, uint32_t cbData)",
    "XeCryptHmacMd5Final": "void XeCryptHmacMd5Final(void* pHmacMd5State, uint8_t* pbOut, uint32_t cbOut)",
    "XeCryptHmacMd5": "void XeCryptHmacMd5(uint8_t* pbKey, uint32_t cbKey, void* pData1, uint32_t cbData1, void* pData2, uint32_t cbData2, void* pData3, uint32_t cbData3, uint8_t* pbOut, uint32_t cbOut)",
    # AES
    "XeCryptAesKey": "void XeCryptAesKey(struct XECRYPT_AES_STATE* pAesState, uint8_t* pbKey)",
    "XeCryptAesEcb": "void XeCryptAesEcb(struct XECRYPT_AES_STATE* pAesState, void* pbIn, void* pbOut, BOOLEAN fEncrypt)",
    "XeCryptAesCbc": "void XeCryptAesCbc(struct XECRYPT_AES_STATE* pAesState, void* pbIn, uint32_t cbIn, void* pbOut, uint8_t* pbFeed, BOOLEAN fEncrypt)",
    # RC4
    "XeCryptRc4Key": "void XeCryptRc4Key(struct XECRYPT_RC4_STATE* pRc4State, uint8_t* pbKey, uint32_t cbKey)",
    "XeCryptRc4Ecb": "void XeCryptRc4Ecb(struct XECRYPT_RC4_STATE* pRc4State, void* pData, uint32_t cbData)",
    "XeCryptRc4": "void XeCryptRc4(uint8_t* pbKey, uint32_t cbKey, void* pData, uint32_t cbData)",
    # DES
    "XeCryptDesParity": "void XeCryptDesParity(uint8_t* pbKey, uint32_t cbKey)",
    "XeCryptDesKey": "void XeCryptDesKey(struct XECRYPT_DES_STATE* pDesState, uint8_t* pbKey)",
    "XeCryptDesEcb": "void XeCryptDesEcb(struct XECRYPT_DES_STATE* pDesState, void* pbIn, void* pbOut, BOOLEAN fEncrypt)",
    "XeCryptDesCbc": "void XeCryptDesCbc(struct XECRYPT_DES_STATE* pDesState, void* pbIn, uint32_t cbIn, void* pbOut, uint8_t* pbFeed, BOOLEAN fEncrypt)",
    "XeCryptDes3Key": "void XeCryptDes3Key(struct XECRYPT_DES3_STATE* pDes3State, uint8_t* pbKey)",
    "XeCryptDes3Ecb": "void XeCryptDes3Ecb(struct XECRYPT_DES3_STATE* pDes3State, void* pbIn, void* pbOut, BOOLEAN fEncrypt)",
    "XeCryptDes3Cbc": "void XeCryptDes3Cbc(struct XECRYPT_DES3_STATE* pDes3State, void* pbIn, uint32_t cbIn, void* pbOut, uint8_t* pbFeed, BOOLEAN fEncrypt)",
    # Bignum
    "XeCryptBnDw_Copy": "void XeCryptBnDw_Copy(uint32_t* pdwOut, uint32_t* pdwIn, uint32_t cdw)",
    "XeCryptBnDw_SwapLeBe": "void XeCryptBnDw_SwapLeBe(uint32_t* pdwInOut, uint32_t cdw)",
    "XeCryptBnDw_Zero": "void XeCryptBnDw_Zero(uint32_t* pdw, uint32_t cdw)",
    "XeCryptBnQw_Copy": "void XeCryptBnQw_Copy(uint64_t* pqwOut, uint64_t* pqwIn, uint32_t cqw)",
    "XeCryptBnQw_SwapLeBe": "void XeCryptBnQw_SwapLeBe(uint64_t* pqwInOut, uint32_t cqw)",
    "XeCryptBnQw_SwapDwQwLeBe": "void XeCryptBnQw_SwapDwQwLeBe(uint64_t* pqwInOut, uint32_t cqw)",
    "XeCryptBnQw_SwapDwQw": "void XeCryptBnQw_SwapDwQw(uint64_t* pqwInOut, uint32_t cqw)",
    "XeCryptBnQw_Zero": "void XeCryptBnQw_Zero(uint64_t* pqw, uint32_t cqw)",
    "XeCryptBnQwNeModExp": "uint32_t XeCryptBnQwNeModExp(uint64_t* pqwOut, uint64_t* pqwIn, uint64_t* pqwExp, uint32_t cqwExp, uint64_t* pqwMod, uint32_t cqwMod)",
    "XeCryptBnQwNeRsaPubCrypt": "BOOLEAN XeCryptBnQwNeRsaPubCrypt(uint64_t* pqwOut, uint64_t* pqwIn, void* pRsaPub)",
    "XeCryptBnQwNeRsaPrvCrypt": "BOOLEAN XeCryptBnQwNeRsaPrvCrypt(uint64_t* pqwOut, uint64_t* pqwIn, void* pRsaPrv)",
    "XeCryptBnQwNeModMul": "void XeCryptBnQwNeModMul(uint64_t* pqwOut, uint64_t* pqwA, uint64_t* pqwB, uint64_t* pqwMod, uint32_t cqw)",
    "XeCryptBnQwNeModInv": "BOOLEAN XeCryptBnQwNeModInv(uint64_t* pqwOut, uint64_t* pqwIn, uint64_t* pqwMod, uint32_t cqw)",
    "XeCryptBnDwLePkcs1Format": "BOOLEAN XeCryptBnDwLePkcs1Format(uint32_t* pdwHash, uint32_t dwType, uint32_t* pdwOut, uint32_t cdwOut)",
    "XeCryptBnDwLePkcs1Verify": "BOOLEAN XeCryptBnDwLePkcs1Verify(uint32_t* pdwHash, uint32_t* pdwSig, uint32_t cdwSig)",
    "XeCryptBnQwBeSigFormat": "BOOLEAN XeCryptBnQwBeSigFormat(void* pSig, uint8_t* pbHash, uint32_t cbHash, uint8_t* pbSalt, uint32_t cbSalt)",
    "XeCryptBnQwBeSigVerify": "BOOLEAN XeCryptBnQwBeSigVerify(void* pSig, uint8_t* pbHash, uint32_t cbHash, uint8_t* pbSalt, uint32_t cbSalt)",
    "XeCryptBnQwBeSigCreate": "BOOLEAN XeCryptBnQwBeSigCreate(void* pSig, uint8_t* pbHash, uint32_t cbHash, uint8_t* pbSalt, uint32_t cbSalt, void* pRsaPrv)",
    "XeCryptBnQwNeCompare": "int32_t XeCryptBnQwNeCompare(uint64_t* pqwA, uint64_t* pqwB, uint32_t cqw)",
    # Misc crypto
    "XeCryptRandom": "void XeCryptRandom(uint8_t* pb, uint32_t cb)",
    "XeCryptRotSumSha": "void XeCryptRotSumSha(void* pData1, uint32_t cbData1, void* pData2, uint32_t cbData2, uint8_t* pbOut, uint32_t cbOut)",
    # SHA-256/384/512
    "XeCryptSha256Init": "void XeCryptSha256Init(struct XECRYPT_SHA256_STATE* pShaState)",
    "XeCryptSha256Update": "void XeCryptSha256Update(struct XECRYPT_SHA256_STATE* pShaState, void* pData, uint32_t cbData)",
    "XeCryptSha256Final": "void XeCryptSha256Final(struct XECRYPT_SHA256_STATE* pShaState, uint8_t* pbOut, uint32_t cbOut)",
    "XeCryptSha256": "void XeCryptSha256(void* pData1, uint32_t cbData1, void* pData2, uint32_t cbData2, void* pData3, uint32_t cbData3, uint8_t* pbOut, uint32_t cbOut)",
    "XeCryptSha384Init": "void XeCryptSha384Init(struct XECRYPT_SHA384_STATE* pShaState)",
    "XeCryptSha384Update": "void XeCryptSha384Update(struct XECRYPT_SHA384_STATE* pShaState, void* pData, uint32_t cbData)",
    "XeCryptSha384Final": "void XeCryptSha384Final(struct XECRYPT_SHA384_STATE* pShaState, uint8_t* pbOut, uint32_t cbOut)",
    "XeCryptSha384": "void XeCryptSha384(void* pData1, uint32_t cbData1, void* pData2, uint32_t cbData2, void* pData3, uint32_t cbData3, uint8_t* pbOut, uint32_t cbOut)",
    "XeCryptSha512Init": "void XeCryptSha512Init(struct XECRYPT_SHA512_STATE* pShaState)",
    "XeCryptSha512Update": "void XeCryptSha512Update(struct XECRYPT_SHA512_STATE* pShaState, void* pData, uint32_t cbData)",
    "XeCryptSha512Final": "void XeCryptSha512Final(struct XECRYPT_SHA512_STATE* pShaState, uint8_t* pbOut, uint32_t cbOut)",
    "XeCryptSha512": "void XeCryptSha512(void* pData1, uint32_t cbData1, void* pData2, uint32_t cbData2, void* pData3, uint32_t cbData3, uint8_t* pbOut, uint32_t cbOut)",
}

XBOX360_SIGNATURES = {
    # -- Dbg -----------------------------------------------------------------
    "DbgBreakPoint": "void DbgBreakPoint()",
    "DbgBreakPointWithStatus": "void DbgBreakPointWithStatus(NTSTATUS Status)",
    "DbgPrint": "ULONG DbgPrint(char* Format)",

    # -- Ex ------------------------------------------------------------------
    "ExAllocatePool": "void* ExAllocatePool(ULONG Size)",
    "ExAllocatePoolWithTag": "void* ExAllocatePoolWithTag(ULONG Size, ULONG Tag)",
    "ExAllocatePoolTypeWithTag": "void* ExAllocatePoolTypeWithTag(ULONG Size, ULONG Tag, POOL_TYPE Type)",
    "ExFreePool": "void ExFreePool(void* P)",
    "ExQueryPoolBlockSize": "uint32_t ExQueryPoolBlockSize(void* PoolBlock)",
    "ExCreateThread": "NTSTATUS ExCreateThread(HANDLE* pHandle, uint32_t StackSize, uint32_t* pThreadId, void* ApiThreadStartup, void* StartAddress, void* StartContext, uint32_t CreateFlags)",
    "ExTerminateThread": "void ExTerminateThread(NTSTATUS ExitStatus)",
    "ExTerminateTitleProcess": "void ExTerminateTitleProcess(NTSTATUS ExitStatus)",
    "ExGetXConfigSetting": "NTSTATUS ExGetXConfigSetting(uint16_t Category, uint16_t Setting, void* pBuffer, uint16_t cbBuffer, uint16_t* pRequired)",
    "ExSetXConfigSetting": "NTSTATUS ExSetXConfigSetting(uint16_t Category, uint16_t Setting, void* pBuffer, uint16_t cbBuffer)",
    "ExAcquireReadWriteLockExclusive": "void ExAcquireReadWriteLockExclusive(PERWLOCK Lock)",
    "ExAcquireReadWriteLockShared": "void ExAcquireReadWriteLockShared(PERWLOCK Lock)",
    "ExReleaseReadWriteLock": "void ExReleaseReadWriteLock(PERWLOCK Lock)",
    "ExTryToAcquireReadWriteLockExclusive": "BOOLEAN ExTryToAcquireReadWriteLockExclusive(PERWLOCK Lock)",
    "ExTryToAcquireReadWriteLockShared": "BOOLEAN ExTryToAcquireReadWriteLockShared(PERWLOCK Lock)",
    "ExInitializeReadWriteLock": "void ExInitializeReadWriteLock(PERWLOCK Lock)",
    "ExRegisterThreadNotification": "NTSTATUS ExRegisterThreadNotification(void* pNotification, BOOLEAN Register)",
    "ExRegisterTitleTerminateNotification": "NTSTATUS ExRegisterTitleTerminateNotification(void* pNotification, BOOLEAN Register)",

    # -- Ke ------------------------------------------------------------------
    "KeAcquireSpinLockAtRaisedIrql": "void KeAcquireSpinLockAtRaisedIrql(uint32_t* SpinLock)",
    "KeReleaseSpinLockFromRaisedIrql": "void KeReleaseSpinLockFromRaisedIrql(uint32_t* SpinLock)",
    "KfAcquireSpinLock": "KIRQL KfAcquireSpinLock(uint32_t* SpinLock)",
    "KfReleaseSpinLock": "void KfReleaseSpinLock(uint32_t* SpinLock, KIRQL OldIrql)",
    "KfRaiseIrql": "KIRQL KfRaiseIrql(KIRQL NewIrql)",
    "KfLowerIrql": "void KfLowerIrql(KIRQL NewIrql)",
    "KeRaiseIrqlToDpcLevel": "KIRQL KeRaiseIrqlToDpcLevel()",
    "KeBugCheck": "void KeBugCheck(uint32_t BugCheckCode)",
    "KeBugCheckEx": "void KeBugCheckEx(uint32_t BugCheckCode, uint32_t Param1, uint32_t Param2, uint32_t Param3, uint32_t Param4)",
    "KeDelayExecutionThread": "NTSTATUS KeDelayExecutionThread(int32_t WaitMode, BOOLEAN Alertable, LARGE_INTEGER* Interval)",
    "KeWaitForSingleObject": "NTSTATUS KeWaitForSingleObject(void* Object, uint32_t WaitReason, int32_t WaitMode, BOOLEAN Alertable, LARGE_INTEGER* Timeout)",
    "KeWaitForMultipleObjects": "NTSTATUS KeWaitForMultipleObjects(uint32_t Count, void** Objects, uint32_t WaitType, uint32_t WaitReason, int32_t WaitMode, BOOLEAN Alertable, LARGE_INTEGER* Timeout, void* WaitBlockArray)",
    "KeInitializeEvent": "void KeInitializeEvent(void* Event, uint32_t Type, BOOLEAN State)",
    "KeSetEvent": "LONG KeSetEvent(KEVENT* Event, ULONG Increment, BOOLEAN Wait)",
    "KeResetEvent": "LONG KeResetEvent(void* Event)",
    "KePulseEvent": "LONG KePulseEvent(void* Event, KPRIORITY Increment, BOOLEAN Wait)",
    "KeInitializeDpc": "void KeInitializeDpc(void* Dpc, void* DeferredRoutine, void* DeferredContext)",
    "KeInsertQueueDpc": "BOOLEAN KeInsertQueueDpc(void* Dpc, void* SystemArgument1, void* SystemArgument2)",
    "KeRemoveQueueDpc": "BOOLEAN KeRemoveQueueDpc(void* Dpc)",
    "KeInitializeTimerEx": "void KeInitializeTimerEx(void* Timer, uint32_t Type)",
    "KeSetTimer": "BOOLEAN KeSetTimer(void* Timer, LARGE_INTEGER DueTime, void* Dpc)",
    "KeSetTimerEx": "BOOLEAN KeSetTimerEx(void* Timer, LARGE_INTEGER DueTime, LONG Period, void* Dpc)",
    "KeCancelTimer": "BOOLEAN KeCancelTimer(void* Timer)",
    "KeInitializeSemaphore": "void KeInitializeSemaphore(void* Semaphore, LONG Count, LONG Limit)",
    "KeReleaseSemaphore": "LONG KeReleaseSemaphore(void* Semaphore, KPRIORITY Increment, LONG Adjustment, BOOLEAN Wait)",
    "KeInitializeMutant": "void KeInitializeMutant(void* Mutant, BOOLEAN InitialOwner)",
    "KeReleaseMutant": "LONG KeReleaseMutant(void* Mutant, KPRIORITY Increment, BOOLEAN Abandoned, BOOLEAN Wait)",
    "KeInitializeQueue": "void KeInitializeQueue(void* Queue, uint32_t Count)",
    "KeInsertQueue": "LONG KeInsertQueue(void* Queue, void* Entry)",
    "KeInsertHeadQueue": "LONG KeInsertHeadQueue(void* Queue, void* Entry)",
    "KeRemoveQueue": "void* KeRemoveQueue(void* Queue, int32_t WaitMode, LARGE_INTEGER* Timeout)",
    "KeRundownQueue": "void* KeRundownQueue(void* Queue)",
    "KeInitializeApc": "void KeInitializeApc(void* Apc, void* Thread, void* KernelRoutine, void* RundownRoutine, void* NormalRoutine, int32_t ApcMode, void* NormalContext)",
    "KeInsertQueueApc": "BOOLEAN KeInsertQueueApc(void* Apc, void* SystemArgument1, void* SystemArgument2, KPRIORITY Increment)",
    "KeInitializeDeviceQueue": "void KeInitializeDeviceQueue(void* DeviceQueue)",
    "KeInsertDeviceQueue": "BOOLEAN KeInsertDeviceQueue(void* DeviceQueue, void* DeviceQueueEntry)",
    "KeInsertByKeyDeviceQueue": "BOOLEAN KeInsertByKeyDeviceQueue(void* DeviceQueue, void* DeviceQueueEntry, uint32_t SortKey)",
    "KeRemoveDeviceQueue": "void* KeRemoveDeviceQueue(void* DeviceQueue)",
    "KeRemoveByKeyDeviceQueue": "void* KeRemoveByKeyDeviceQueue(void* DeviceQueue, uint32_t SortKey)",
    "KeRemoveEntryDeviceQueue": "BOOLEAN KeRemoveEntryDeviceQueue(void* DeviceQueue, void* DeviceQueueEntry)",
    "KeConnectInterrupt": "BOOLEAN KeConnectInterrupt(void* Interrupt)",
    "KeDisconnectInterrupt": "BOOLEAN KeDisconnectInterrupt(void* Interrupt)",
    "KeEnterCriticalRegion": "void KeEnterCriticalRegion()",
    "KeLeaveCriticalRegion": "void KeLeaveCriticalRegion()",
    "KeSetBasePriorityThread": "LONG KeSetBasePriorityThread(void* Thread, LONG Increment)",
    "KeSetPriorityThread": "KPRIORITY KeSetPriorityThread(void* Thread, KPRIORITY Priority)",
    "KeSetAffinityThread": "uint32_t KeSetAffinityThread(void* Thread, uint32_t Affinity)",
    "KeSetDisableBoostThread": "void KeSetDisableBoostThread(void* Thread, BOOLEAN Disable)",
    "KeResumeThread": "uint32_t KeResumeThread(void* Thread)",
    "KeSuspendThread": "uint32_t KeSuspendThread(void* Thread)",
    "KeAlertThread": "BOOLEAN KeAlertThread(void* Thread, int32_t AlertMode)",
    "KeAlertResumeThread": "uint32_t KeAlertResumeThread(void* Thread)",
    "KeBoostPriorityThread": "void KeBoostPriorityThread(void* Thread, KPRIORITY Increment)",
    "KeQueryBasePriorityThread": "LONG KeQueryBasePriorityThread(void* Thread)",
    "KeQueryInterruptTime": "uint64_t KeQueryInterruptTime()",
    "KeQueryPerformanceFrequency": "uint64_t KeQueryPerformanceFrequency()",
    "KeQuerySystemTime": "void KeQuerySystemTime(LARGE_INTEGER* CurrentTime)",
    "KeStallExecutionProcessor": "void KeStallExecutionProcessor(uint32_t MicroSeconds)",
    "KeFlushCacheRange": "void KeFlushCacheRange(void* Address, uint32_t Length)",
    "KeFlushEntireTb": "void KeFlushEntireTb()",
    "KeFlushCurrentEntireTb": "void KeFlushCurrentEntireTb()",
    "KeSweepDcacheRange": "void KeSweepDcacheRange(void* Address, uint32_t Length)",
    "KeSweepIcacheRange": "void KeSweepIcacheRange(void* Address, uint32_t Length)",
    "KeIpiGenericCall": "uint32_t KeIpiGenericCall(void* BroadcastFunction, uint32_t Context)",
    "KeSaveFloatingPointState": "NTSTATUS KeSaveFloatingPointState(void* FloatingPointState)",
    "KeRestoreFloatingPointState": "NTSTATUS KeRestoreFloatingPointState(void* FloatingPointState)",
    "KeSetPowerMode": "void KeSetPowerMode(uint32_t PowerMode)",
    "KeGetCurrentProcessType": "uint32_t KeGetCurrentProcessType()",
    "KeSetCurrentProcessType": "void KeSetCurrentProcessType(uint32_t ProcessType)",
    "KeTlsAlloc": "uint32_t KeTlsAlloc()",
    "KeTlsFree": "BOOLEAN KeTlsFree(uint32_t TlsIndex)",
    "KeTlsGetValue": "void* KeTlsGetValue(uint32_t TlsIndex)",
    "KeTlsSetValue": "BOOLEAN KeTlsSetValue(uint32_t TlsIndex, void* TlsValue)",

    # -- Mm ------------------------------------------------------------------
    "MmAllocatePhysicalMemory": "uint32_t MmAllocatePhysicalMemory(uint32_t ulFlags, uint32_t ulSize, uint32_t ulProtect)",
    "MmAllocatePhysicalMemoryEx": "uint32_t MmAllocatePhysicalMemoryEx(uint32_t ulFlags, uint32_t ulSize, uint32_t ulProtect, uint32_t ulMinAddr, uint32_t ulMaxAddr, uint32_t ulAlignment)",
    "MmFreePhysicalMemory": "void MmFreePhysicalMemory(uint32_t ulType, uint32_t ulBase)",
    "MmGetPhysicalAddress": "uint32_t MmGetPhysicalAddress(void* BaseAddress)",
    "MmIsAddressValid": "BOOLEAN MmIsAddressValid(void* VirtualAddress)",
    "MmMapIoSpace": "void* MmMapIoSpace(uint32_t PhysicalAddress, uint32_t NumberOfBytes, uint32_t Protect)",
    "MmUnmapIoSpace": "void MmUnmapIoSpace(void* BaseAddress, uint32_t NumberOfBytes)",
    "MmCreateKernelStack": "void* MmCreateKernelStack(uint32_t StackSize, uint32_t Unknown)",
    "MmDeleteKernelStack": "void MmDeleteKernelStack(void* StackBase, uint32_t Unknown)",
    "MmQueryAddressProtect": "uint32_t MmQueryAddressProtect(void* VirtualAddress)",
    "MmSetAddressProtect": "void MmSetAddressProtect(void* VirtualAddress, uint32_t NumberOfBytes, uint32_t NewProtect)",
    "MmQueryAllocationSize": "uint32_t MmQueryAllocationSize(void* BaseAddress)",
    "MmQueryStatistics": "NTSTATUS MmQueryStatistics(void* pStatistics)",
    "MmLockUnlockBufferPages": "void MmLockUnlockBufferPages(void* BaseAddress, uint32_t NumberOfBytes, uint32_t Lock)",

    # -- Io ------------------------------------------------------------------
    "IoAllocateIrp": "PIRP IoAllocateIrp(CHAR StackSize)",
    "IoFreeIrp": "void IoFreeIrp(PIRP Irp)",
    "IoInitializeIrp": "void IoInitializeIrp(PIRP Irp, USHORT PacketSize, CHAR StackSize)",
    "IoCallDriver": "NTSTATUS IoCallDriver(PDEVICE_OBJECT DeviceObject, PIRP Irp)",
    "IoCompleteRequest": "void IoCompleteRequest(PIRP Irp, IO_PRIORITY_BOOST PriorityBoost)",
    "IoCreateDevice": "NTSTATUS IoCreateDevice(PDRIVER_OBJECT DriverObject, ULONG DeviceExtensionSize, PANSI_STRING DeviceName, ULONG DeviceType, BOOLEAN Exclusive, PDEVICE_OBJECT* DeviceObject)",
    "IoDeleteDevice": "void IoDeleteDevice(PDEVICE_OBJECT DeviceObject)",
    "IoCreateFile": "NTSTATUS IoCreateFile(HANDLE* FileHandle, FILE_ACCESS_RIGHTS DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, LARGE_INTEGER* AllocationSize, uint32_t FileAttributes, FILE_SHARE_FLAGS ShareAccess, FILE_CREATE_DISPOSITION Disposition, FILE_CREATE_OPTIONS CreateOptions, uint32_t Options)",
    "IoCheckShareAccess": "NTSTATUS IoCheckShareAccess(FILE_ACCESS_RIGHTS DesiredAccess, FILE_SHARE_FLAGS DesiredShareAccess, void* FileObject, void* ShareAccess, BOOLEAN Update)",
    "IoSetShareAccess": "void IoSetShareAccess(FILE_ACCESS_RIGHTS DesiredAccess, FILE_SHARE_FLAGS DesiredShareAccess, void* FileObject, void* ShareAccess)",
    "IoRemoveShareAccess": "void IoRemoveShareAccess(void* FileObject, void* ShareAccess)",
    "IoBuildAsynchronousFsdRequest": "void* IoBuildAsynchronousFsdRequest(IRP_MAJOR_FUNCTION MajorFunction, void* DeviceObject, void* Buffer, uint32_t Length, LARGE_INTEGER* StartingOffset, PIO_STATUS_BLOCK IoStatusBlock)",
    "IoBuildDeviceIoControlRequest": "void* IoBuildDeviceIoControlRequest(uint32_t IoControlCode, void* DeviceObject, void* InputBuffer, uint32_t InputBufferLength, void* OutputBuffer, uint32_t OutputBufferLength, BOOLEAN InternalDeviceIoControl, void* Event, PIO_STATUS_BLOCK IoStatusBlock)",
    "IoBuildSynchronousFsdRequest": "void* IoBuildSynchronousFsdRequest(IRP_MAJOR_FUNCTION MajorFunction, void* DeviceObject, void* Buffer, uint32_t Length, LARGE_INTEGER* StartingOffset, void* Event, PIO_STATUS_BLOCK IoStatusBlock)",
    "IoStartPacket": "void IoStartPacket(void* DeviceObject, void* Irp, uint32_t* Key, void* CancelFunction)",
    "IoStartNextPacket": "void IoStartNextPacket(void* DeviceObject, BOOLEAN Cancelable)",
    "IoStartNextPacketByKey": "void IoStartNextPacketByKey(void* DeviceObject, BOOLEAN Cancelable, uint32_t Key)",
    "IoSynchronousDeviceIoControlRequest": "NTSTATUS IoSynchronousDeviceIoControlRequest(uint32_t IoControlCode, void* DeviceObject, void* InputBuffer, uint32_t InputBufferLength, void* OutputBuffer, uint32_t OutputBufferLength, uint32_t* pBytesReturned, BOOLEAN InternalDeviceIoControl)",
    "IoInvalidDeviceRequest": "NTSTATUS IoInvalidDeviceRequest(PDEVICE_OBJECT DeviceObject, PIRP Irp)",
    "IoAcquireDeviceObjectLock": "void IoAcquireDeviceObjectLock(void* DeviceObject)",
    "IoReleaseDeviceObjectLock": "void IoReleaseDeviceObjectLock(void* DeviceObject)",
    "IoSetIoCompletion": "NTSTATUS IoSetIoCompletion(void* IoCompletion, void* KeyContext, void* ApcContext, NTSTATUS IoStatus, uint32_t IoStatusInformation)",

    # -- Nt ------------------------------------------------------------------
    "NtAllocateVirtualMemory": "NTSTATUS NtAllocateVirtualMemory(void** BaseAddress, uint32_t* RegionSize, uint32_t AllocationType, uint32_t Protect)",
    "NtFreeVirtualMemory": "NTSTATUS NtFreeVirtualMemory(void** BaseAddress, uint32_t* RegionSize, uint32_t FreeType)",
    "NtProtectVirtualMemory": "NTSTATUS NtProtectVirtualMemory(void** BaseAddress, uint32_t* RegionSize, uint32_t NewProtect, uint32_t* OldProtect)",
    "NtQueryVirtualMemory": "NTSTATUS NtQueryVirtualMemory(void* BaseAddress, void* Buffer, uint32_t Length, uint32_t* ReturnLength)",
    "NtClose": "NTSTATUS NtClose(HANDLE Handle)",
    "NtCreateFile": "NTSTATUS NtCreateFile(HANDLE* FileHandle, FILE_ACCESS_RIGHTS DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, LARGE_INTEGER* AllocationSize, uint32_t FileAttributes, FILE_SHARE_FLAGS ShareAccess, FILE_CREATE_DISPOSITION CreateDisposition, FILE_CREATE_OPTIONS CreateOptions)",
    "NtOpenFile": "NTSTATUS NtOpenFile(HANDLE* FileHandle, FILE_ACCESS_RIGHTS DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, FILE_SHARE_FLAGS ShareAccess, FILE_CREATE_OPTIONS OpenOptions)",
    "NtReadFile": "NTSTATUS NtReadFile(HANDLE FileHandle, HANDLE Event, void* ApcRoutine, void* ApcContext, PIO_STATUS_BLOCK IoStatusBlock, void* Buffer, uint32_t Length, LARGE_INTEGER* ByteOffset)",
    "NtWriteFile": "NTSTATUS NtWriteFile(HANDLE FileHandle, HANDLE Event, void* ApcRoutine, void* ApcContext, PIO_STATUS_BLOCK IoStatusBlock, void* Buffer, uint32_t Length, LARGE_INTEGER* ByteOffset)",
    "NtReadFileScatter": "NTSTATUS NtReadFileScatter(HANDLE FileHandle, HANDLE Event, void* ApcRoutine, void* ApcContext, PIO_STATUS_BLOCK IoStatusBlock, void* SegmentArray, uint32_t Length, LARGE_INTEGER* ByteOffset)",
    "NtWriteFileGather": "NTSTATUS NtWriteFileGather(HANDLE FileHandle, HANDLE Event, void* ApcRoutine, void* ApcContext, PIO_STATUS_BLOCK IoStatusBlock, void* SegmentArray, uint32_t Length, LARGE_INTEGER* ByteOffset)",
    "NtDeleteFile": "NTSTATUS NtDeleteFile(POBJECT_ATTRIBUTES ObjectAttributes)",
    "NtDeviceIoControlFile": "NTSTATUS NtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, void* ApcRoutine, void* ApcContext, PIO_STATUS_BLOCK IoStatusBlock, uint32_t IoControlCode, void* InputBuffer, uint32_t InputBufferLength, void* OutputBuffer, uint32_t OutputBufferLength)",
    "NtQueryInformationFile": "NTSTATUS NtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, void* FileInformation, uint32_t Length, FILE_INFORMATION_CLASS FileInformationClass)",
    "NtSetInformationFile": "NTSTATUS NtSetInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, void* FileInformation, uint32_t Length, FILE_INFORMATION_CLASS FileInformationClass)",
    "NtQueryVolumeInformationFile": "NTSTATUS NtQueryVolumeInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, void* FsInformation, uint32_t Length, FS_INFORMATION_CLASS FsInformationClass)",
    "NtQueryFullAttributesFile": "NTSTATUS NtQueryFullAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes, void* FileInformation)",
    "NtQueryDirectoryFile": "NTSTATUS NtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, void* ApcRoutine, void* ApcContext, PIO_STATUS_BLOCK IoStatusBlock, void* FileInformation, uint32_t Length, FILE_INFORMATION_CLASS FileInformationClass, PANSI_STRING FileName, BOOLEAN RestartScan)",
    "NtFlushBuffersFile": "NTSTATUS NtFlushBuffersFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock)",
    "NtDuplicateObject": "NTSTATUS NtDuplicateObject(HANDLE SourceHandle, HANDLE* TargetHandle, uint32_t Options)",
    "NtCreateEvent": "NTSTATUS NtCreateEvent(HANDLE* EventHandle, POBJECT_ATTRIBUTES ObjectAttributes, uint32_t EventType, BOOLEAN InitialState)",
    "NtSetEvent": "NTSTATUS NtSetEvent(HANDLE EventHandle, LONG* PreviousState)",
    "NtClearEvent": "NTSTATUS NtClearEvent(HANDLE EventHandle)",
    "NtPulseEvent": "NTSTATUS NtPulseEvent(HANDLE EventHandle, LONG* PreviousState)",
    "NtQueryEvent": "NTSTATUS NtQueryEvent(HANDLE EventHandle, void* EventInformation, uint32_t EventInformationLength, uint32_t* ReturnLength)",
    "NtCreateMutant": "NTSTATUS NtCreateMutant(HANDLE* MutantHandle, POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN InitialOwner)",
    "NtReleaseMutant": "NTSTATUS NtReleaseMutant(HANDLE MutantHandle, LONG* PreviousCount)",
    "NtQueryMutant": "NTSTATUS NtQueryMutant(HANDLE MutantHandle, void* MutantInformation, uint32_t MutantInformationLength, uint32_t* ReturnLength)",
    "NtCreateSemaphore": "NTSTATUS NtCreateSemaphore(HANDLE* SemaphoreHandle, POBJECT_ATTRIBUTES ObjectAttributes, LONG InitialCount, LONG MaximumCount)",
    "NtReleaseSemaphore": "NTSTATUS NtReleaseSemaphore(HANDLE SemaphoreHandle, LONG ReleaseCount, LONG* PreviousCount)",
    "NtQuerySemaphore": "NTSTATUS NtQuerySemaphore(HANDLE SemaphoreHandle, void* SemaphoreInformation, uint32_t SemaphoreInformationLength, uint32_t* ReturnLength)",
    "NtCreateTimer": "NTSTATUS NtCreateTimer(HANDLE* TimerHandle, POBJECT_ATTRIBUTES ObjectAttributes, uint32_t TimerType)",
    "NtSetTimerEx": "NTSTATUS NtSetTimerEx(HANDLE TimerHandle, LARGE_INTEGER* DueTime, void* TimerApcRoutine, void* TimerContext, BOOLEAN WakeTimer, LONG Period, BOOLEAN* PreviousState)",
    "NtCancelTimer": "NTSTATUS NtCancelTimer(HANDLE TimerHandle, BOOLEAN* CurrentState)",
    "NtQueryTimer": "NTSTATUS NtQueryTimer(HANDLE TimerHandle, void* TimerInformation, uint32_t TimerInformationLength, uint32_t* ReturnLength)",
    "NtCreateDirectoryObject": "NTSTATUS NtCreateDirectoryObject(HANDLE* DirectoryHandle, POBJECT_ATTRIBUTES ObjectAttributes)",
    "NtOpenDirectoryObject": "NTSTATUS NtOpenDirectoryObject(HANDLE* DirectoryHandle, POBJECT_ATTRIBUTES ObjectAttributes)",
    "NtQueryDirectoryObject": "NTSTATUS NtQueryDirectoryObject(HANDLE DirectoryHandle, void* Buffer, uint32_t Length, BOOLEAN RestartScan, uint32_t* Context, uint32_t* ReturnLength)",
    "NtCreateSymbolicLinkObject": "NTSTATUS NtCreateSymbolicLinkObject(HANDLE* LinkHandle, POBJECT_ATTRIBUTES ObjectAttributes, PANSI_STRING LinkTarget)",
    "NtOpenSymbolicLinkObject": "NTSTATUS NtOpenSymbolicLinkObject(HANDLE* LinkHandle, POBJECT_ATTRIBUTES ObjectAttributes)",
    "NtQuerySymbolicLinkObject": "NTSTATUS NtQuerySymbolicLinkObject(HANDLE LinkHandle, PANSI_STRING LinkTarget, uint32_t* ReturnedLength)",
    "NtMakeTemporaryObject": "NTSTATUS NtMakeTemporaryObject(HANDLE Handle)",
    "NtCreateIoCompletion": "NTSTATUS NtCreateIoCompletion(HANDLE* IoCompletionHandle, FILE_ACCESS_RIGHTS DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, uint32_t Count)",
    "NtRemoveIoCompletion": "NTSTATUS NtRemoveIoCompletion(HANDLE IoCompletionHandle, void** KeyContext, void** ApcContext, PIO_STATUS_BLOCK IoStatusBlock, LARGE_INTEGER* Timeout)",
    "NtSetIoCompletion": "NTSTATUS NtSetIoCompletion(HANDLE IoCompletionHandle, void* KeyContext, void* ApcContext, NTSTATUS IoStatus, uint32_t IoStatusInformation)",
    "NtQueryIoCompletion": "NTSTATUS NtQueryIoCompletion(HANDLE IoCompletionHandle, void* IoCompletionInformation, uint32_t IoCompletionInformationLength, uint32_t* ReturnLength)",
    "NtResumeThread": "NTSTATUS NtResumeThread(HANDLE ThreadHandle, uint32_t* PreviousSuspendCount)",
    "NtSuspendThread": "NTSTATUS NtSuspendThread(HANDLE ThreadHandle, uint32_t* PreviousSuspendCount)",
    "NtSetSystemTime": "NTSTATUS NtSetSystemTime(LARGE_INTEGER* SystemTime, LARGE_INTEGER* PreviousTime)",
    "NtWaitForSingleObjectEx": "NTSTATUS NtWaitForSingleObjectEx(HANDLE Handle, int32_t WaitMode, BOOLEAN Alertable, LARGE_INTEGER* Timeout)",
    "NtWaitForMultipleObjectsEx": "NTSTATUS NtWaitForMultipleObjectsEx(uint32_t Count, HANDLE* Handles, uint32_t WaitType, int32_t WaitMode, BOOLEAN Alertable, LARGE_INTEGER* Timeout)",
    "NtSignalAndWaitForSingleObjectEx": "NTSTATUS NtSignalAndWaitForSingleObjectEx(HANDLE SignalHandle, HANDLE WaitHandle, int32_t WaitMode, BOOLEAN Alertable, LARGE_INTEGER* Timeout)",
    "NtYieldExecution": "NTSTATUS NtYieldExecution()",
    "NtQueueApcThread": "NTSTATUS NtQueueApcThread(HANDLE ThreadHandle, void* ApcRoutine, void* ApcArgument1, void* ApcArgument2, void* ApcArgument3)",

    # -- Ob ------------------------------------------------------------------
    "ObCreateObject": "NTSTATUS ObCreateObject(void* ObjectType, POBJECT_ATTRIBUTES ObjectAttributes, uint32_t ObjectBodySize, void** Object)",
    "ObInsertObject": "NTSTATUS ObInsertObject(void* Object, POBJECT_ATTRIBUTES ObjectAttributes, uint32_t ObjectPointerBias, HANDLE* Handle)",
    "ObReferenceObject": "void ObReferenceObject(void* Object)",
    "ObDereferenceObject": "void ObDereferenceObject(void* Object)",
    "ObReferenceObjectByHandle": "NTSTATUS ObReferenceObjectByHandle(HANDLE Handle, void* ObjectType, void** Object)",
    "ObReferenceObjectByName": "NTSTATUS ObReferenceObjectByName(PANSI_STRING ObjectName, OBJECT_ATTRIBUTE_FLAGS Attributes, void* ObjectType, void* ParseContext, void** Object)",
    "ObOpenObjectByName": "NTSTATUS ObOpenObjectByName(POBJECT_ATTRIBUTES ObjectAttributes, void* ObjectType, void* ParseContext, HANDLE* Handle)",
    "ObOpenObjectByPointer": "NTSTATUS ObOpenObjectByPointer(void* Object, void* ObjectType, HANDLE* Handle)",
    "ObCreateSymbolicLink": "NTSTATUS ObCreateSymbolicLink(PANSI_STRING SymbolicLinkName, PANSI_STRING DeviceName)",
    "ObDeleteSymbolicLink": "NTSTATUS ObDeleteSymbolicLink(PANSI_STRING SymbolicLinkName)",
    "ObMakeTemporaryObject": "void ObMakeTemporaryObject(void* Object)",
    "ObLookupThreadByThreadId": "NTSTATUS ObLookupThreadByThreadId(uint32_t ThreadId, void** Thread)",
    "ObLookupAnyThreadByThreadId": "NTSTATUS ObLookupAnyThreadByThreadId(uint32_t ThreadId, void** Thread)",
    "ObTranslateSymbolicLink": "NTSTATUS ObTranslateSymbolicLink(PANSI_STRING FullPath)",

    # -- Rtl -----------------------------------------------------------------
    "RtlInitUnicodeString": "void RtlInitUnicodeString(PUNICODE_STRING DestinationString, uint16_t* SourceString)",
    "RtlInitAnsiString": "void RtlInitAnsiString(PANSI_STRING DestinationString, char* SourceString)",
    "RtlAnsiStringToUnicodeString": "NTSTATUS RtlAnsiStringToUnicodeString(PUNICODE_STRING DestinationString, PANSI_STRING SourceString, BOOLEAN AllocateDestinationString)",
    "RtlUnicodeStringToAnsiString": "NTSTATUS RtlUnicodeStringToAnsiString(PANSI_STRING DestinationString, PUNICODE_STRING SourceString, BOOLEAN AllocateDestinationString)",
    "RtlFreeAnsiString": "void RtlFreeAnsiString(PANSI_STRING AnsiString)",
    "RtlCreateUnicodeString": "BOOLEAN RtlCreateUnicodeString(PUNICODE_STRING DestinationString, uint16_t* SourceString)",
    "RtlCopyString": "void RtlCopyString(PANSI_STRING DestinationString, PANSI_STRING SourceString)",
    "RtlCopyUnicodeString": "void RtlCopyUnicodeString(PUNICODE_STRING DestinationString, PUNICODE_STRING SourceString)",
    "RtlAppendStringToString": "NTSTATUS RtlAppendStringToString(PANSI_STRING Destination, PANSI_STRING Source)",
    "RtlAppendUnicodeStringToString": "NTSTATUS RtlAppendUnicodeStringToString(PUNICODE_STRING Destination, PUNICODE_STRING Source)",
    "RtlAppendUnicodeToString": "NTSTATUS RtlAppendUnicodeToString(PUNICODE_STRING Destination, uint16_t* Source)",
    "RtlCompareString": "LONG RtlCompareString(PANSI_STRING String1, PANSI_STRING String2, BOOLEAN CaseInSensitive)",
    "RtlCompareUnicodeString": "LONG RtlCompareUnicodeString(PUNICODE_STRING String1, PUNICODE_STRING String2, BOOLEAN CaseInSensitive)",
    "RtlCompareMemory": "uint32_t RtlCompareMemory(void* Source1, void* Source2, uint32_t Length)",
    "RtlCompareMemoryUlong": "uint32_t RtlCompareMemoryUlong(void* Source, uint32_t Length, uint32_t Pattern)",
    "RtlFillMemoryUlong": "void RtlFillMemoryUlong(void* Destination, uint32_t Length, uint32_t Pattern)",
    "RtlCaptureContext": "void RtlCaptureContext(void* ContextRecord)",
    "RtlCaptureStackBackTrace": "uint16_t RtlCaptureStackBackTrace(uint32_t FramesToSkip, uint32_t FramesToCapture, void** BackTrace, uint32_t* BackTraceHash)",
    "RtlNtStatusToDosError": "uint32_t RtlNtStatusToDosError(NTSTATUS Status)",
    "RtlRaiseException": "void RtlRaiseException(void* ExceptionRecord)",
    "RtlRaiseStatus": "void RtlRaiseStatus(NTSTATUS Status)",
    "RtlUnwind": "void RtlUnwind(void* TargetFrame, void* TargetIp, void* ExceptionRecord, void* ReturnValue)",
    "RtlImageXexHeaderField": "void* RtlImageXexHeaderField(void* XexHeader, uint32_t HeaderField)",
    "RtlImageNtHeader": "void* RtlImageNtHeader(void* Base)",
    "RtlImageDirectoryEntryToData": "void* RtlImageDirectoryEntryToData(void* Base, BOOLEAN MappedAsImage, uint16_t DirectoryEntry, uint32_t* Size)",
    "RtlLookupFunctionEntry": "void* RtlLookupFunctionEntry(uint32_t ControlPc, void** ImageBase, void* HistoryTable)",
    "RtlVirtualUnwind": "void* RtlVirtualUnwind(uint32_t HandlerType, uint32_t ImageBase, uint32_t ControlPc, void* FunctionEntry, void* ContextRecord, void** HandlerData, uint32_t* EstablisherFrame, void* ContextPointers)",
    "RtlMultiByteToUnicodeN": "NTSTATUS RtlMultiByteToUnicodeN(uint16_t* UnicodeString, uint32_t MaxBytesInUnicodeString, uint32_t* BytesInUnicodeString, char* MultiByteString, uint32_t BytesInMultiByteString)",
    "RtlUnicodeToMultiByteN": "NTSTATUS RtlUnicodeToMultiByteN(char* MultiByteString, uint32_t MaxBytesInMultiByteString, uint32_t* BytesInMultiByteString, uint16_t* UnicodeString, uint32_t BytesInUnicodeString)",
    "RtlTimeFieldsToTime": "BOOLEAN RtlTimeFieldsToTime(void* TimeFields, LARGE_INTEGER* Time)",
    "RtlTimeToTimeFields": "void RtlTimeToTimeFields(LARGE_INTEGER* Time, void* TimeFields)",
    "RtlComputeCrc32": "uint32_t RtlComputeCrc32(uint32_t InitialCrc, void* Buffer, uint32_t Length)",
    "RtlInitializeCriticalSection": "NTSTATUS RtlInitializeCriticalSection(void* CriticalSection)",
    "RtlInitializeCriticalSectionAndSpinCount": "NTSTATUS RtlInitializeCriticalSectionAndSpinCount(void* CriticalSection, uint32_t SpinCount)",
    "RtlEnterCriticalSection": "NTSTATUS RtlEnterCriticalSection(void* CriticalSection)",
    "RtlLeaveCriticalSection": "NTSTATUS RtlLeaveCriticalSection(void* CriticalSection)",
    "RtlTryEnterCriticalSection": "BOOLEAN RtlTryEnterCriticalSection(void* CriticalSection)",
    "RtlAssert": "void RtlAssert(char* FailedAssertion, char* FileName, uint32_t LineNumber, char* Message)",
    "RtlGetStackLimits": "void RtlGetStackLimits(uint32_t* LowLimit, uint32_t* HighLimit)",
    "RtlDowncaseUnicodeChar": "uint16_t RtlDowncaseUnicodeChar(uint16_t SourceCharacter)",
    "RtlUpcaseUnicodeChar": "uint16_t RtlUpcaseUnicodeChar(uint16_t SourceCharacter)",
    "RtlLowerChar": "char RtlLowerChar(char Character)",
    "RtlUpperChar": "char RtlUpperChar(char Character)",
    "sprintf": "int32_t sprintf(char* buffer, char* format)",
    "_snprintf": "int32_t _snprintf(char* buffer, uint32_t count, char* format)",
    "vsprintf": "int32_t vsprintf(char* buffer, char* format, void* argptr)",

    # -- Xex -----------------------------------------------------------------
    "XexCheckExecutablePrivilege": "BOOLEAN XexCheckExecutablePrivilege(uint32_t Privilege)",
    "XexGetModuleHandle": "NTSTATUS XexGetModuleHandle(char* ModuleName, HANDLE* ModuleHandle)",
    "XexGetModuleSection": "NTSTATUS XexGetModuleSection(HANDLE ModuleHandle, char* SectionName, void** SectionData, uint32_t* SectionSize)",
    "XexGetProcedureAddress": "NTSTATUS XexGetProcedureAddress(HANDLE ModuleHandle, uint32_t Ordinal, void** ProcAddress)",
    "XexLoadImage": "NTSTATUS XexLoadImage(char* ImageName, uint32_t TypeFlags, uint32_t MinVersion, HANDLE* ModuleHandle)",
    "XexUnloadImage": "NTSTATUS XexUnloadImage(HANDLE ModuleHandle)",
    "XexLoadImageFromMemory": "NTSTATUS XexLoadImageFromMemory(void* ImageBuffer, uint32_t ImageSize, char* ImageName, uint32_t TypeFlags, uint32_t MinVersion, HANDLE* ModuleHandle)",
    "XexLoadImageHeaders": "NTSTATUS XexLoadImageHeaders(char* ImageName, void* HeaderBuffer, uint32_t HeaderBufferSize)",
    "XexPcToFileHeader": "void* XexPcToFileHeader(void* PcValue, void** BaseOfImage)",

    # -- Hal -----------------------------------------------------------------
    "HalReturnToFirmware": "void HalReturnToFirmware(uint32_t PowerDownMode)",
    "HalSendSMCMessage": "NTSTATUS HalSendSMCMessage(void* pRequest, void* pResponse)",
    "HalGetCurrentAVPack": "uint32_t HalGetCurrentAVPack()",

    # -- Misc ----------------------------------------------------------------
    "memcmp": "int32_t memcmp(void* s1, void* s2, uint32_t n)",
    "memcpy": "void* memcpy(void* dest, void* src, uint32_t n)",
    "memset": "void* memset(void* s, int32_t c, uint32_t n)",
    "InterlockedFlushSList": "void* InterlockedFlushSList(void* ListHead)",
    "InterlockedPopEntrySList": "void* InterlockedPopEntrySList(void* ListHead)",
    "InterlockedPushEntrySList": "void* InterlockedPushEntrySList(void* ListHead, void* ListEntry)",
    "__C_specific_handler": "int32_t __C_specific_handler(void* ExceptionRecord, void* EstablisherFrame, void* ContextRecord, void* DispatcherContext)",

    # -- XeKeys --------------------------------------------------------------
    "XeKeysGetKey": "NTSTATUS XeKeysGetKey(uint32_t KeyIndex, void* KeyBuffer, uint32_t* KeyBufferSize)",
    "XeKeysSetKey": "NTSTATUS XeKeysSetKey(uint32_t KeyIndex, void* KeyBuffer, uint32_t KeyBufferSize)",
    "XeKeysGetKeyProperties": "NTSTATUS XeKeysGetKeyProperties(uint32_t KeyIndex, uint32_t* KeyProperties)",
    "XeKeysGetDigest": "NTSTATUS XeKeysGetDigest(uint32_t KeyIndex, void* Data, uint32_t DataSize, uint8_t* Digest, uint32_t* DigestSize)",
    "XeKeysHmacSha": "NTSTATUS XeKeysHmacSha(uint32_t KeyIndex, void* Data1, uint32_t Data1Size, void* Data2, uint32_t Data2Size, void* Data3, uint32_t Data3Size, uint8_t* Digest, uint32_t DigestSize)",
    "XeKeysAesCbc": "NTSTATUS XeKeysAesCbc(uint32_t KeyIndex, void* InBuffer, uint32_t InSize, void* OutBuffer, uint8_t* Feed, BOOLEAN Encrypt)",
    "XeKeysDes2Cbc": "NTSTATUS XeKeysDes2Cbc(uint32_t KeyIndex, void* InBuffer, uint32_t InSize, void* OutBuffer, uint8_t* Feed, BOOLEAN Encrypt)",
    "XeKeysDesCbc": "NTSTATUS XeKeysDesCbc(uint32_t KeyIndex, void* InBuffer, uint32_t InSize, void* OutBuffer, uint8_t* Feed, BOOLEAN Encrypt)",
    "XeKeysObscureKey": "NTSTATUS XeKeysObscureKey(uint32_t KeyIndex, void* InBuffer, uint32_t InSize, void* OutBuffer)",
    "XeKeysGetConsoleID": "NTSTATUS XeKeysGetConsoleID(uint8_t* ConsoleId)",
    "XeKeysGetConsoleType": "NTSTATUS XeKeysGetConsoleType(uint32_t* ConsoleType)",
    "XeKeysGetConsoleCertificate": "NTSTATUS XeKeysGetConsoleCertificate(void* CertBuffer)",
    "XeKeysGetStatus": "NTSTATUS XeKeysGetStatus(uint32_t* Status)",
    "XeKeysGenerateRandomKey": "NTSTATUS XeKeysGenerateRandomKey(uint32_t KeyIndex, void* KeyBuffer)",
    "XeKeysConsolePrivateKeySign": "NTSTATUS XeKeysConsolePrivateKeySign(void* Hash, uint32_t HashSize, void* Signature, uint32_t* SignatureSize)",
    "XeKeysVerifyRSASignature": "BOOLEAN XeKeysVerifyRSASignature(void* Hash, uint32_t HashSize, void* Signature, uint32_t SignatureSize, void* PublicKey)",
    "XeKeysObfuscate": "NTSTATUS XeKeysObfuscate(void* InBuffer, uint32_t InSize, void* OutBuffer, uint32_t* OutSize)",
    "XeKeysUnObfuscate": "NTSTATUS XeKeysUnObfuscate(void* InBuffer, uint32_t InSize, void* OutBuffer, uint32_t* OutSize)",

    # -- Dump ----------------------------------------------------------------
    "DumpGetRawDumpInfo": "NTSTATUS DumpGetRawDumpInfo(void* DumpInfo)",
    "DumpWriteDump": "NTSTATUS DumpWriteDump(void* DumpInfo)",
}

# Merge crypto signatures into kernel signatures
XBOX360_SIGNATURES.update(XCRYPT_SIGNATURES)

# Merge crypto signatures into the Xbox 360 signature table
XBOX360_SIGNATURES.update(XCRYPT_SIGNATURES)


# ============================================================================
# Type/Signature Application Helpers
# ============================================================================

def _load_ntos_headers():
    """Load and preprocess Xbox 360 NTOS headers from the ntos/ directory."""
    import os
    import re

    plugin_dir = os.path.dirname(os.path.realpath(__file__))
    ntos_dir = os.path.join(plugin_dir, "ntos")

    if not os.path.isdir(ntos_dir):
        return None

    # Read headers in dependency order (xtl.h defines base types,
    # then each header builds on prior ones).
    header_order = [
        "xtl.h",
        "NtStatus.h",
        "Ob.h",
        "Ioctl.h",
        "Io.h",
        "Sata.h",
        "NtosKernel.h",
    ]

    # Counters for naming anonymous unions/structs (global across all files)
    anon_open_counter = [0]
    anon_close_counter = [0]

    source_parts = []
    for name in header_order:
        path = os.path.join(ntos_dir, name)
        if not os.path.isfile(path):
            continue
        content = open(path, "r").read()

        # Strip constructs Binary Ninja's type parser can't handle
        content = re.sub(r"#pragma\s+.*", "", content)
        content = re.sub(r'#include\s+[<"].*?[>"]', "", content)
        content = re.sub(
            r"#ifdef\s+__cplusplus.*?#endif",
            "",
            content,
            flags=re.DOTALL,
        )
        content = re.sub(
            r"#ifdef\s+_OBJLINK.*?#endif",
            "",
            content,
            flags=re.DOTALL,
        )
        content = re.sub(r"SPECIAL_LINKAGE", "", content)
        # Strip zero-sized array placeholders like BYTE _[0];
        content = re.sub(r"\w+\s+_\s*\[\s*0\s*\]\s*;", "uint8_t _placeholder;", content)
        # Replace macro constants used in struct array sizes
        content = re.sub(
            r"IRP_MJ_MAXIMUM_FUNCTION\s*\+\s*1", "11", content
        )
        # Strip __forceinline function bodies entirely
        content = re.sub(
            r"__forceinline\s+[^{]*\{[^}]*\}", "", content, flags=re.DOTALL
        )
        # Name anonymous unions/structs (Binary Ninja parser requires names)
        def _name_anon_open(m):
            anon_open_counter[0] += 1
            keyword = m.group(1)
            return f"{keyword} _an{anon_open_counter[0]} {{"
        content = re.sub(r"\b(union|struct)\s*\{", _name_anon_open, content)
        def _name_anon_close(m):
            anon_close_counter[0] += 1
            return f"}} _m{anon_close_counter[0]};"
        content = re.sub(r"\}\s*;", _name_anon_close, content)
        # Strip only multi-line #define macros (keep simple constants)
        lines = content.split("\n")
        filtered = []
        in_continuation = False
        for line in lines:
            stripped = line.rstrip()
            if in_continuation:
                if not stripped.endswith("\\"):
                    in_continuation = False
                continue
            if stripped.lstrip().startswith("#define"):
                if stripped.endswith("\\"):
                    in_continuation = True
                continue
            filtered.append(line)
        content = "\n".join(filtered)

        source_parts.append(content)

    return "\n".join(source_parts)


# Enums whose natural integer field width is smaller than int. BN's C parser
# accepts no underlying-type syntax (`enum X : uint8_t`) and rejects it as a
# SyntaxError that would drop the whole header parse, so these are declared
# as default int-width enums and resized in Python after parse_types_from_source.
_ENUM_WIDTH_OVERRIDES = {
    "IO_STACK_LOCATION_FLAGS":  1,
    "IRP_MAJOR_FUNCTION":       1,
    "FILE_OBJECT_FLAGS":        1,
    "FILE_DEVICE_TYPE":         1,
    "IO_PRIORITY_BOOST":        1,
    "FILE_SHARE_FLAGS":         2,
}

# Struct fields to retype after parse. Each entry: (struct_name, field_name,
# enum_type_name). Used for fields whose ABI width disagrees with the
# default int-width enum, where a header-level retype would change struct
# layout. The enum is resized first (above), so the retyped field matches
# the original ABI byte width.
_STRUCT_FIELD_ENUM_RETYPES = [
    ("_IO_STACK_LOCATION", "MajorFunction", "IRP_MAJOR_FUNCTION"),
    ("_IO_STACK_LOCATION", "Control",       "IO_STACK_LOCATION_FLAGS"),
    ("_DEVICE_OBJECT",     "DeviceType",    "FILE_DEVICE_TYPE"),
    ("_FILE_OBJECT",       "Flags",         "FILE_OBJECT_FLAGS"),
]


def _resize_enum(bv, types_dict, name, width):
    """Rebuild `name` in `types_dict` as a `width`-byte enum."""
    from binaryninja import EnumerationBuilder, Type, TypeClass

    t = types_dict.get(name)
    if t is None or t.type_class != TypeClass.EnumerationTypeClass:
        return False
    eb = EnumerationBuilder.create(width=width)
    for m in t.enumeration.members:
        eb.append(m.name, int(m.value))
    types_dict[name] = Type.enumeration_type(bv.arch, eb, width=width)
    return True


def _retype_struct_field(bv, types_dict, struct_name, field_name, enum_name):
    """Replace `struct_name.field_name`'s type with `enum_name` (a named ref)."""
    from binaryninja import StructureBuilder, Type, TypeClass

    s = types_dict.get(struct_name)
    if s is None or s.type_class != TypeClass.StructureTypeClass:
        return False
    enum_ref = Type.named_type_from_registered_type(bv, enum_name)
    if enum_ref is None:
        return False
    sb = StructureBuilder.create()
    sb.packed = s.packed
    sb.alignment = s.alignment
    replaced = False
    for m in s.members:
        if m.name == field_name:
            sb.add_member_at_offset(field_name, enum_ref, m.offset)
            replaced = True
        else:
            sb.add_member_at_offset(m.name, m.type, m.offset)
    if not replaced:
        return False
    types_dict[struct_name] = Type.structure_type(sb)
    return True


def _define_xbox360_types(bv):
    header_source = _load_ntos_headers()
    if header_source:
        source = header_source + "\n" + XBOX360_CRYPTO_TYPES_C
        log_info("Loading Xbox 360 types from ntos/ headers")
    else:
        source = XBOX360_CRYPTO_TYPES_C
        log_warn("ntos/ headers not found, using crypto types only")

    try:
        result = bv.platform.parse_types_from_source(source)
    except Exception as e:
        log_warn(f"Failed to parse Xbox 360 types: {e}")
        return

    types_dict = dict(result.types)

    for ename, width in _ENUM_WIDTH_OVERRIDES.items():
        if not _resize_enum(bv, types_dict, ename, width):
            log_warn(f"Could not resize enum {ename} to {width}-byte")

    # Define enums first so struct rebuilds can resolve named refs to them.
    for name, type_obj in types_dict.items():
        bv.define_user_type(name, type_obj)

    for sname, fname, ename in _STRUCT_FIELD_ENUM_RETYPES:
        if _retype_struct_field(bv, types_dict, sname, fname, ename):
            bv.define_user_type(sname, types_dict[sname])
        else:
            log_warn(f"Could not retype {sname}.{fname} to {ename}")

    log_info(f"Registered {len(types_dict)} Xbox 360 types")


def _apply_func_signatures(bv, sig_dict):
    applied = 0
    for func_name, proto in sig_dict.items():
        funcs = bv.get_functions_by_name(func_name)
        if not funcs:
            continue
        try:
            func_type, _ = bv.parse_type_string(proto)
            for func in funcs:
                func.type = func_type
            applied += 1
        except Exception as e:
            log_warn(f"Failed to parse signature for {func_name}: {e}")
    log_info(f"Applied {applied} function signatures")



# ============================================================================
# PPC Instruction Helpers
# ============================================================================

def _rd8(raw, off):
    d = raw.read(off, 1)
    return d[0] if d and len(d) >= 1 else 0


def _rd16(raw, off):
    d = raw.read(off, 2)
    return struct.unpack(">H", d)[0] if d and len(d) >= 2 else 0


def _rd32(raw, off):
    d = raw.read(off, 4)
    return struct.unpack(">I", d)[0] if d and len(d) >= 4 else 0


def _rd16_le(raw, off):
    d = raw.read(off, 2)
    return struct.unpack("<H", d)[0] if d and len(d) >= 2 else 0


def _rd32_le(raw, off):
    d = raw.read(off, 4)
    return struct.unpack("<I", d)[0] if d and len(d) >= 4 else 0


# ============================================================================
# Shared PE image mapping
# ============================================================================

def _map_pe_image(view, pe_bytes, base):
    """Lay out PE sections of `pe_bytes` at `base` in `view`.

    `view`'s parent_view must serve `pe_bytes` starting at offset 0.
    """
    pe_off = struct.unpack_from("<I", pe_bytes, PE_OFFSET_FIELD)[0]
    sec_count = struct.unpack_from("<H", pe_bytes, pe_off + PE_NUM_SECTIONS_OFF)[0]
    opt_hdr_size = struct.unpack_from(
        "<H", pe_bytes, pe_off + PE_OPT_HDR_SIZE_OFF
    )[0]
    sec_hdrs_off = pe_off + PE_SECTION_HDRS_BASE + opt_hdr_size

    first_section_rva = 0xFFFFFFFF
    for i in range(sec_count):
        ptr = sec_hdrs_off + i * PE_SECTION_HDR_SIZE
        rva = struct.unpack_from("<I", pe_bytes, ptr + PE_SEC_RVA_OFF)[0]
        if rva < first_section_rva:
            first_section_rva = rva

    if 0 < first_section_rva <= len(pe_bytes):
        view.add_auto_segment(
            base, first_section_rva, 0, first_section_rva,
            SegmentFlag.SegmentReadable | SegmentFlag.SegmentContainsData,
        )
        view.add_auto_section(
            ".header", base, first_section_rva,
            SectionSemantics.ReadOnlyDataSectionSemantics,
        )

    sections = []
    for i in range(sec_count):
        ptr = sec_hdrs_off + i * PE_SECTION_HDR_SIZE
        name = pe_bytes[ptr:ptr + 8].rstrip(b"\x00").decode(
            "ascii", errors="replace"
        )
        vsize = struct.unpack_from("<I", pe_bytes, ptr + PE_SEC_VSIZE_OFF)[0]
        rva = struct.unpack_from("<I", pe_bytes, ptr + PE_SEC_RVA_OFF)[0]
        flags = struct.unpack_from("<I", pe_bytes, ptr + PE_SEC_FLAGS_OFF)[0]
        va = base + rva
        fsize = min(vsize, max(0, len(pe_bytes) - rva))

        seg_flags = SegmentFlag.SegmentReadable
        if flags & PE_SCN_MEM_EXECUTE:
            seg_flags |= SegmentFlag.SegmentExecutable
        if flags & PE_SCN_MEM_WRITE:
            seg_flags |= SegmentFlag.SegmentWritable

        is_code = bool(flags & PE_SCN_CNT_CODE)
        if is_code:
            seg_flags |= SegmentFlag.SegmentContainsCode
        else:
            seg_flags |= SegmentFlag.SegmentContainsData

        view.add_auto_segment(va, vsize, rva, fsize, seg_flags)
        sem = (
            SectionSemantics.ReadOnlyCodeSectionSemantics
            if is_code
            else SectionSemantics.ReadWriteDataSectionSemantics
        )
        view.add_auto_section(name, va, vsize, sem)
        sections.append((name, va, vsize, is_code))
        log_info(f"  Section {name}: 0x{va:08X} size=0x{vsize:X}")

    return sections


# ============================================================================
# Xbox 360 PE BinaryView (kernel + extracted basefiles)
# ============================================================================

class Xbox360PeView(BinaryView):
    """Loader for raw Xbox 360 PowerPC PE images.

    Primary use is the Xbox 360 kernel (xboxkrnl), which is shipped as a
    plain PE32 image with a `.xedata` export table. Also handles any other
    Xbox 360 PE blob (e.g. an XEX2 basefile that's already been extracted).
    Detection keys on the PE Machine field being PowerPC big-endian; the
    kernel-specific export-table labeling fires only when `.xedata` is
    present.
    """

    name = "Xbox360PE"
    long_name = "Xbox 360 PE"

    DEFAULT_BASE = 0x80040000

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.raw = data

    @classmethod
    def is_valid_for_data(cls, data):
        if data.length < 0x200:
            return False

        pe_off_bytes = data.read(PE_OFFSET_FIELD, 4)
        if not pe_off_bytes or len(pe_off_bytes) < 4:
            return False
        pe_off = struct.unpack("<I", pe_off_bytes)[0]
        if pe_off == 0 or pe_off >= data.length - 40:
            return False

        sig = data.read(pe_off, 4)
        if sig != b"PE\x00\x00":
            return False

        machine_bytes = data.read(pe_off + PE_MACHINE_OFF, 2)
        if not machine_bytes or len(machine_bytes) < 2:
            return False
        machine = struct.unpack("<H", machine_bytes)[0]
        if machine != IMAGE_FILE_MACHINE_POWERPCBE:
            return False

        sc_bytes = data.read(pe_off + PE_NUM_SECTIONS_OFF, 2)
        if not sc_bytes or len(sc_bytes) < 2:
            return False
        sec_count = struct.unpack("<H", sc_bytes)[0]
        if sec_count < 1 or sec_count > 96:
            return False

        return True

    def init(self):
        self.arch = Architecture["ppc64"]
        self.platform = _xbox360_platform or self.arch.standalone_platform

        pe_off = _rd32_le(self.raw, PE_OFFSET_FIELD)
        opt_hdr_off = pe_off + PE_OPT_HDR_OFF
        opt_magic = _rd16_le(self.raw, opt_hdr_off)
        if opt_magic == PE_OPT_MAGIC_PE32P:
            ib_off = opt_hdr_off + PE_OPT_IMAGE_BASE_OFF_PE32P
            image_base = struct.unpack(
                "<Q", self.raw.read(ib_off, 8)
            )[0] if self.raw.read(ib_off, 8) else self.DEFAULT_BASE
        else:
            ib_off = opt_hdr_off + PE_OPT_IMAGE_BASE_OFF_PE32
            image_base = _rd32_le(self.raw, ib_off) or self.DEFAULT_BASE

        base = image_base
        self._base = base

        sec_count = _rd16_le(self.raw, pe_off + PE_NUM_SECTIONS_OFF)
        opt_hdr_size = _rd16_le(self.raw, pe_off + PE_OPT_HDR_SIZE_OFF)
        sec_hdrs_off = pe_off + PE_SECTION_HDRS_BASE + opt_hdr_size

        log_info(f"Xbox 360 PE: {sec_count} sections, base=0x{base:08X}")

        first_section_rva = 0xFFFFFFFF
        for i in range(sec_count):
            ptr = sec_hdrs_off + i * PE_SECTION_HDR_SIZE
            rva = _rd32_le(self.raw, ptr + PE_SEC_RVA_OFF)
            if rva < first_section_rva:
                first_section_rva = rva

        if 0 < first_section_rva < self.raw.length:
            self.add_auto_segment(
                base, first_section_rva, 0, first_section_rva,
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentContainsData,
            )
            self.add_auto_section(
                ".header", base, first_section_rva,
                SectionSemantics.ReadOnlyDataSectionSemantics,
            )

        xedata_va = None
        for i in range(sec_count):
            ptr = sec_hdrs_off + i * PE_SECTION_HDR_SIZE
            name_bytes = self.raw.read(ptr, 8)
            sec_name = name_bytes.rstrip(b"\x00").decode("ascii", errors="replace")
            sec_vsize = _rd32_le(self.raw, ptr + PE_SEC_VSIZE_OFF)
            sec_rva = _rd32_le(self.raw, ptr + PE_SEC_RVA_OFF)
            sec_flags = _rd32_le(self.raw, ptr + PE_SEC_FLAGS_OFF)
            va = base + sec_rva

            if sec_name == ".xedata":
                xedata_va = va

            seg_flags = SegmentFlag.SegmentReadable
            if sec_flags & PE_SCN_MEM_EXECUTE:
                seg_flags |= SegmentFlag.SegmentExecutable
            if sec_flags & PE_SCN_MEM_READ:
                seg_flags |= SegmentFlag.SegmentReadable
            if sec_flags & PE_SCN_MEM_WRITE:
                seg_flags |= SegmentFlag.SegmentWritable

            is_code = bool(sec_flags & PE_SCN_CNT_CODE)
            if is_code:
                seg_flags |= SegmentFlag.SegmentContainsCode
            else:
                seg_flags |= SegmentFlag.SegmentContainsData

            self.add_auto_segment(va, sec_vsize, sec_rva, sec_vsize, seg_flags)

            sem = (
                SectionSemantics.ReadOnlyCodeSectionSemantics
                if is_code
                else SectionSemantics.ReadWriteDataSectionSemantics
            )
            self.add_auto_section(sec_name, va, sec_vsize, sem)
            log_info(f"  Section {sec_name}: 0x{va:08X} size=0x{sec_vsize:X}")

        _define_xbox360_types(self)

        if xedata_va is not None:
            self._label_xedata_exports(base, xedata_va)

        _apply_func_signatures(self, XBOX360_SIGNATURES)
        return True

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return self._base

    def perform_get_address_size(self):
        return 8

    def _label_xedata_exports(self, base, xedata_va):
        xedata_off = xedata_va - base

        magic0 = _rd32(self.raw, xedata_off)
        magic1 = _rd32(self.raw, xedata_off + 4)
        magic2 = _rd32(self.raw, xedata_off + 8)
        if magic0 != XEDATA_MAGIC0 or magic1 != XEDATA_MAGIC1 or magic2 != XEDATA_MAGIC2:
            log_warn("Export table has invalid signature")
            return

        export_count = _rd32(self.raw, xedata_off + XEDATA_EXPORT_COUNT_OFF)
        base_ordinal = _rd32(self.raw, xedata_off + XEDATA_BASE_ORDINAL_OFF)
        log_info(
            f"Kernel export table: {export_count} exports, "
            f"base ordinal={base_ordinal}"
        )

        for i in range(export_count):
            export_rva = _rd32(self.raw, xedata_off + XEDATA_ENTRIES_OFF + i * 4)
            export_addr = base + export_rva
            name = KERNEL_EXPORTS[i] if i < len(KERNEL_EXPORTS) else ""

            if name in KERNEL_DATA_EXPORTS:
                self.define_auto_symbol(
                    Symbol(SymbolType.DataSymbol, export_addr, name)
                )
                if name in KERNEL_DATA_EXPORT_TYPES:
                    try:
                        t, _ = self.parse_type_string(
                            f"{KERNEL_DATA_EXPORT_TYPES[name]} _v"
                        )
                        self.define_data_var(export_addr, t)
                    except Exception:
                        pass
            else:
                self.add_function(export_addr)
                if name:
                    self.define_auto_symbol(
                        Symbol(SymbolType.FunctionSymbol, export_addr, name)
                    )


# ============================================================================
# Xbox 360 XEX2 BinaryView
# ============================================================================

class Xbox360Xex2View(BinaryView):
    name = "Xbox360XEX2"
    long_name = "Xbox 360 XEX2"

    def __init__(self, data):
        # BinaryView.__init__ runs last here; seed these so a failure before
        # it doesn't mask the real error in __del__/_cleanup.
        self._notifications = {}
        self._handle = None
        # BN 6 exposes a read-only property; older releases store a public
        # handle attribute, which their cleanup code also needs on failure.
        handle_descriptor = getattr(BinaryView, "handle", None)
        if not isinstance(handle_descriptor, property) or handle_descriptor.fset is not None:
            self.handle = None

        raw = bytes(data.read(0, data.length))
        if _xex2_mod is None:
            raise RuntimeError(
                "xex2 module not available; "
                "run `uv sync` in the project directory"
            )
        self._xex = _xex2_mod.Xex2.parse(raw)
        self._base = self._xex.load_address
        basefile = bytearray(self._xex.extract_basefile())

        # Decode every import record BEFORE we patch the basefile: the
        # descriptor DWORDs encoding library+ordinal live inside the
        # thunks, and we're about to overwrite them with nops for clean
        # disassembly.
        self._import_records = []  # list of (rec_va, type_byte, lib_name, ordinal)
        imports_api = self._xex.imports()
        for i in range(imports_api.len):
            lib = imports_api.get(i)
            for r in range(lib.record_count):
                rec_va = lib.record_at(r)
                off = rec_va - self._base
                if off < 0 or off + 4 > len(basefile):
                    continue
                desc = (
                    (basefile[off] << 24) | (basefile[off+1] << 16)
                    | (basefile[off+2] << 8) | basefile[off+3]
                )
                type_byte = (desc >> 24) & 0xFF
                ordinal = desc & 0xFFFF
                self._import_records.append(
                    (rec_va, type_byte, lib.name, ordinal)
                )

        # PEView.is_valid_for_data matches on "MZ" at offset 0 of any BV.
        # Our parent BV has to contain the basefile bytes to back segments,
        # and the basefile starts with an MZ header — so PEView would
        # auto-attach and steal the active view. Clobbering the single
        # magic byte defeats that match without shifting any offsets; the
        # byte lives in our .header section and isn't read by analysis.
        if len(basefile) >= 2 and basefile[0] == 0x4D and basefile[1] == 0x5A:
            basefile[0] = 0

        # Rewrite each thunk's two descriptor DWORDs into the `lis/addi`
        # pair the hypervisor's HvxResolveImports writes at load time:
        #     lis  r11, ((addr + 0x8000) >> 16) & 0xffff    ; 0x3D60_XXXX
        #     addi r11, r11, addr & 0xffff                  ; 0x396B_XXXX
        # `addr` targets the IAT slot for this import — the kernel would
        # normally patch these with the resolved import address, but we
        # don't have that. Targeting the IAT gives BN a symbol at the
        # jump destination so HLIL renders the body as `jump(__imp_X)`.
        # BN's auto-thunk-rename then adopts the `__imp_` PE convention
        # for the thunk function itself, matching standard disassembler
        # behaviour.
        #
        # XEX import records only list the type-0x01 descriptor per thunk;
        # the type-0x02 descriptor lives at thunk+4 and isn't recorded.
        # Patch both slots off each type-0x01 record.
        iat_by_ord = {
            (lib, ordinal): va
            for (va, tb, lib, ordinal) in self._import_records
            if tb == 0x00
        }
        for rec_va, type_byte, lib_name, ordinal in self._import_records:
            if type_byte != 0x01:
                continue
            target = iat_by_ord.get((lib_name, ordinal), ordinal)
            off = rec_va - self._base
            hi = ((target + 0x8000) >> 16) & 0xFFFF
            lo = target & 0xFFFF
            basefile[off:off+4] = struct.pack(">I", 0x3D600000 | hi)
            basefile[off+4:off+8] = struct.pack(">I", 0x396B0000 | lo)

        self._basefile = bytes(basefile)
        # Attach the parent Raw BV to the XEX's FileMetadata so BN doesn't
        # treat it as a second file. Without this, the inner BV's
        # separately-allocated FileMetadata shows up as a phantom tab and
        # steals "current binary view" selection.
        self._parent_bv = BinaryView.new(data=self._basefile, file_metadata=data.file)
        BinaryView.__init__(
            self, parent_view=self._parent_bv, file_metadata=data.file
        )

    @classmethod
    def is_valid_for_data(cls, data):
        return data.read(0, 4) == b"XEX2"

    def init(self):
        self.arch = Architecture["ppc64"]
        self.platform = _xbox360_platform or self.arch.standalone_platform

        base = self._base
        entry = self._xex.entry_point
        title = self._xex.title_id
        log_info(
            f"XEX2 load=0x{base:08X} entry=0x{entry:08X} "
            f"title=0x{title:08X} image=0x{self._xex.image_size:X}"
        )

        _map_pe_image(self, self._basefile, base)
        _define_xbox360_types(self)
        self._label_xex_imports()
        _apply_func_signatures(self, XBOX360_SIGNATURES)

        if entry:
            self.add_function(entry)
            self.add_entry_point(entry)
            self.define_auto_symbol(
                Symbol(SymbolType.FunctionSymbol, entry, "_start")
            )

        return True

    def _label_xex_imports(self):
        """Name every XEX import thunk and IAT entry by ordinal.

        XEX2 import records are flat u32 VAs pointing into the image. The
        DWORD at each VA is a big-endian descriptor:
          [31:24] type: 0x00 = IAT entry, 0x01 = thunk function start
          [23:16] library index (matches position in xex.imports())
          [15:0]  ordinal in that library

        We look the ordinal up in ORDINAL_EXPORTS_BY_MODULE (keyed by the
        library's declared name, e.g. "xboxkrnl.exe" / "xam.xex") and name
        the thunk / IAT accordingly.
        """
        func_ptr_type = None
        try:
            func_ptr_type, _ = self.parse_type_string("void* _v")
        except Exception:
            pass

        thunks = 0
        iats = 0
        unresolved = []
        libraries = set()
        # self._import_records was captured from the pristine basefile in
        # __init__; the basefile has since been patched with lis/addi
        # instructions, so we can't re-decode descriptors from it here.
        for rec_va, type_byte, lib_name, ordinal in self._import_records:
            libraries.add(lib_name)
            ord_map = ORDINAL_EXPORTS_BY_MODULE.get(lib_name, {})
            name = ord_map.get(ordinal)
            if name is None:
                unresolved.append((lib_name, ordinal))
                name = f"{lib_name}_ord_{ordinal}"
            if type_byte == 0x00:
                # IAT slot in .rdata — the runtime patches this with the
                # resolved function address. Use the PE-style `__imp_<name>`
                # so it doesn't collide with the thunk function symbol.
                self.define_auto_symbol(
                    Symbol(
                        SymbolType.ImportAddressSymbol, rec_va,
                        f"__imp_{name}",
                    )
                )
                if func_ptr_type is not None:
                    try:
                        self.define_data_var(rec_va, func_ptr_type)
                    except Exception:
                        pass
                iats += 1
            elif type_byte == 0x01:
                # Thunk stub in .text. Descriptor-type-0x01 is the first
                # DWORD of the thunk (rewritten to `lis r11, hi` above);
                # it's the call target. Type 0x02 is the second DWORD
                # (the `addi`); we don't need a symbol there.
                self.add_function(rec_va)
                self.define_auto_symbol(
                    Symbol(SymbolType.FunctionSymbol, rec_va, name)
                )
                thunks += 1
        log_info(
            f"Labeled {thunks} import thunks and {iats} IAT entries "
            f"across {len(libraries)} libraries "
            f"({len(unresolved)} unresolved ordinals)"
        )
        for lib_name, ordinal in unresolved[:20]:
            log_info(f"  unresolved: {lib_name} ord {ordinal}")

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return self._xex.entry_point or self._xex.load_address

    def perform_get_address_size(self):
        return 8


# ============================================================================
# Register views
# ============================================================================

Xbox360PeView.register()
Xbox360Xex2View.register()
