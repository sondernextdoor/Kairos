#define MAX_STACK_FRAMES 32

typedef struct _STACK_SIGNATURE {
    ULONG Hash;
    PVOID Frames[MAX_STACK_FRAMES];
    USHORT FrameCount;
} STACK_SIGNATURE;

#define MAX_KNOWN_SIGNATURES 32
STACK_SIGNATURE g_KnownPgStacks[MAX_KNOWN_SIGNATURES];
ULONG g_NumKnownPgStacks = 0;

ULONG HashStackTrace(PVOID* stack, USHORT count) {
    ULONG hash = 0xDEADC0DE;
    for (USHORT i = 0; i < count; i++) {
        hash ^= (ULONG)(ULONG_PTR)stack[i];
        hash = _rotl(hash, 5) + i;
    }
    return hash;
}

BOOLEAN IsKnownPatchGuardStack(PVOID* stack, USHORT count) {
    ULONG hash = HashStackTrace(stack, count);

    for (ULONG i = 0; i < g_NumKnownPgStacks; i++) {
        if (g_KnownPgStacks[i].Hash == hash)
            return TRUE;
    }

    return FALSE;
}

VOID CaptureAndFingerprintStack(const char* tag) {
    PVOID stack[MAX_STACK_FRAMES] = { 0 };
    USHORT frames = RtlCaptureStackBackTrace(0, MAX_STACK_FRAMES, stack, NULL);
    ULONG hash = HashStackTrace(stack, frames);

    DebugLog("Stack (%s) Hash = 0x%08X (%u frames)", tag, hash, frames);

    for (USHORT i = 0; i < frames; i++) {
        DebugLog("  [%02u] %p", i, stack[i]);
    }

    if (g_NumKnownPgStacks < MAX_KNOWN_SIGNATURES) {
        g_KnownPgStacks[g_NumKnownPgStacks].Hash = hash;
        RtlCopyMemory(g_KnownPgStacks[g_NumKnownPgStacks].Frames, stack, sizeof(PVOID) * frames);
        g_KnownPgStacks[g_NumKnownPgStacks].FrameCount = frames;
        g_NumKnownPgStacks++;
    }
}
