#define TIMER_TABLE_SIZE 0x100  // 256 timer slots

typedef struct _DETECTED_PG_TIMER {
    PKTIMER Timer;
    PKDPC Dpc;
    PVOID DeferredRoutine;
} DETECTED_PG_TIMER;

#define MAX_PG_TIMERS 16
DETECTED_PG_TIMER g_PgTimers[MAX_PG_TIMERS];
ULONG g_NumDetectedTimers = 0;

extern KTIMER_TABLE_ENTRY* KiTimerTableListHead;  // kernel offset

VOID ScanForPatchGuardTimers() {
    for (int i = 0; i < TIMER_TABLE_SIZE; i++) {
        PLIST_ENTRY head = &KiTimerTableListHead[i].Entry;
        PLIST_ENTRY current = head->Flink;

        while (current != head) {
            PKTIMER timer = CONTAINING_RECORD(current, KTIMER, TimerListEntry);
            current = current->Flink;

            if (!MmIsAddressValid(timer)) continue;

            PKDPC dpc = (PKDPC)timer->Dpc;
            if (!MmIsAddressValid(dpc)) continue;

            if (dpc->Type != 0x13 || !MmIsAddressValid(dpc->DeferredRoutine)) continue;

            const char* name = GetSymbolNameFromAddress(dpc->DeferredRoutine);
            if (name && strstr(name, "PatchGuard")) {
                if (g_NumDetectedTimers < MAX_PG_TIMERS) {
                    g_PgTimers[g_NumDetectedTimers].Timer = timer;
                    g_PgTimers[g_NumDetectedTimers].Dpc = dpc;
                    g_PgTimers[g_NumDetectedTimers].DeferredRoutine = dpc->DeferredRoutine;
                    g_NumDetectedTimers++;

                    DebugLog("PG Timer found: %p (Routine: %p)", timer, dpc->DeferredRoutine);
                }
            }
        }
    }
}

typedef NTSTATUS(*KE_SETTIMER_EX)(
    PKTIMER, PLARGE_INTEGER, LONG, PKDPC
);

KE_SETTIMER_EX OriginalKeSetTimerEx = NULL;

NTSTATUS HookedKeSetTimerEx(PKTIMER Timer, PLARGE_INTEGER DueTime, LONG Period, PKDPC Dpc) {
    if (Dpc && MmIsAddressValid(Dpc->DeferredRoutine)) {
        const char* name = GetSymbolNameFromAddress(Dpc->DeferredRoutine);
        if (name && strstr(name, "PatchGuard")) {
            DebugLog("PG timer set with DPC: %p", Dpc->DeferredRoutine);
        }
    }

    return OriginalKeSetTimerEx(Timer, DueTime, Period, Dpc);
}