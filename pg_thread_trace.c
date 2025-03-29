typedef struct _DETECTED_PG_THREAD {
    PETHREAD Thread;
    PVOID StartAddress;
    ULONG StackHash;
} DETECTED_PG_THREAD;

#define MAX_PG_THREADS 16
DETECTED_PG_THREAD g_PgThreads[MAX_PG_THREADS];
ULONG g_NumDetectedThreads = 0;

VOID TracePatchGuardThreads() {
    PVOID systemProcess = PsInitialSystemProcess;
    if (!systemProcess) return;

    PLIST_ENTRY threadList = (PLIST_ENTRY)((PUCHAR)systemProcess + 0x488);  // EPROCESS->ThreadListHead (version-dependent)
    PLIST_ENTRY current = threadList->Flink;

    while (current != threadList) {
        PETHREAD thread = CONTAINING_RECORD(current, ETHREAD, ThreadListEntry);
        current = current->Flink;

        if (!MmIsAddressValid(thread)) continue;

        // Get thread start address
        PVOID startAddress = PsGetThreadStartAddress(thread);
        if (!MmIsAddressValid(startAddress)) continue;

        // Fingerprint the stack trace
        PVOID stack[16] = { 0 };
        USHORT captured = RtlCaptureStackBackTrace(0, 16, stack, NULL);
        ULONG hash = 0;
        for (int i = 0; i < captured; i++) hash ^= (ULONG)(ULONG_PTR)stack[i];

        // Match known PG behavior (can add hash database later)
        if (hash && g_NumDetectedThreads < MAX_PG_THREADS) {
            g_PgThreads[g_NumDetectedThreads].Thread = thread;
            g_PgThreads[g_NumDetectedThreads].StartAddress = startAddress;
            g_PgThreads[g_NumDetectedThreads].StackHash = hash;
            g_NumDetectedThreads++;

            DebugLog("PG-like worker thread detected: %p (start: %p)", thread, startAddress);
        }
    }
}

typedef NTSTATUS(*PFN_PsCreateSystemThread)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PCLIENT_ID, PKSTART_ROUTINE, PVOID
);

PFN_PsCreateSystemThread OriginalCreateThread = NULL;

NTSTATUS HookedPsCreateSystemThread(
    PHANDLE ThreadHandle,
    ACCESS_MASK AccessMask,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PCLIENT_ID ClientId,
    PKSTART_ROUTINE StartRoutine,
    PVOID Context
) {
    if (MmIsAddressValid(StartRoutine)) {
        const char* name = GetSymbolNameFromAddress(StartRoutine);
        if (name && strstr(name, "PatchGuard")) {
            DebugLog("PatchGuard thread being created: %p", StartRoutine);
        }
    }

    return OriginalCreateThread(ThreadHandle, AccessMask, ObjectAttributes, ProcessHandle, ClientId, StartRoutine, Context);
}
