VOID SetPgBreakpoint(PVOID target) {
    __try {
        __writecr4(__readcr4() & ~0x10000);  // Disable interrupts

        __asm {
            mov eax, target
            mov dr0, eax           // Set DR0 to target address
            mov eax, 0x00000001    // Enable DR0 local exact match
            mov dr7, eax
        }

        __writecr4(__readcr4() | 0x10000);  // Re-enable interrupts
        DebugLog("HW Breakpoint set on: %p", target);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DebugLog("Failed to set DR0.");
    }
}

VOID PgTrapHandler() {
    DebugLog(">> PG Trap Triggered (INT 1)");

    RevertEncryptedPatches();  // Clean up before PG checks
    LogPgTrace();              // Optional: Capture stack / telemetry

    LARGE_INTEGER delay;
    delay.QuadPart = -10 * 1000 * 1000;  // 1s sleep
    KeDelayExecutionThread(KernelMode, FALSE, &delay);

    ApplyEncryptedPatches();  // Re-stealth

    DebugLog("<< PG Trap Handled");
}
