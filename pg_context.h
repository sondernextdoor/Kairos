#pragma once

#include <ntddk.h>

#define PG_KEY_DERIVATION_OFFSET 0x100
#define PG_CTX_ENCRYPTED_OFFSET  0x40

NTSTATUS FindPatchGuardContext(PVOID* Context);
VOID ExtractPgEncryptionKey(PVOID Context, PUCHAR KeyBuffer);
NTSTATUS DecryptPatchGuardContext(PUCHAR Key, ULONG KeySize, PVOID Encrypted, PVOID Decrypted, ULONG Size);
PVOID ValidatePgContext(PVOID Address);

typedef struct _DECRYPTED_PG_CONTEXT {
    PVOID ValidationRoutine;
    ULONGLONG LastCheckTime;
    ULONGLONG NextCheckTime;
} DECRYPTED_PG_CONTEXT, *PDECRYPTED_PG_CONTEXT;
