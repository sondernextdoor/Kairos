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

PG_CONTEXT_ENTRY g_PgContextArray[MAX_PG_CONTEXTS];
ULONG g_NumPgContexts = 0;
PVOID g_SharedMemoryBase = NULL;
HANDLE g_PgMonitorThreadHandle = NULL;
BOOLEAN g_StopPgMonitorThread = FALSE;

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

// --- DriverEntry ---
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

UCHAR OriginalBytes[16] = {0};
UCHAR PatchedBytes[16]  = { /* your hook or patch */ };
PVOID PatchAddress      = NULL;  // Set this!

VOID RevertKernelPatch() {
    if (PatchAddress && MmIsAddressValid(PatchAddress)) {
        RtlCopyMemory(PatchAddress, OriginalBytes, sizeof(OriginalBytes));
        DebugLog("Patch reverted.\n");
    }
}

VOID ReapplyKernelPatch() {
    if (PatchAddress && MmIsAddressValid(PatchAddress)) {
        RtlCopyMemory(PatchAddress, PatchedBytes, sizeof(PatchedBytes));
        DebugLog("Patch reapplied.\n");
    }
}
