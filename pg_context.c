#include "pg_context.h"
#include "../common/utilities.h"
#include <bcrypt.h>

PVOID ValidatePgContext(PVOID Address) {
    if (MmIsAddressValid(Address)) {
        return Address;
    }
    return NULL;
}

NTSTATUS FindPatchGuardContext(PVOID* Context) {
    if (!Context) return STATUS_INVALID_PARAMETER;
    DebugLog("Scanning for PatchGuard context...\n");
    *Context = ResolveKernelSymbol("NtAllocateVirtualMemory");
    return (*Context && ValidatePgContext(*Context)) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

VOID ExtractPgEncryptionKey(PVOID Context, PUCHAR KeyBuffer) {
    RtlFillMemory(KeyBuffer, 32, 0xAA);  // Stubbed key extraction
    DebugLog("Key extracted from context %p\n", Context);
}

NTSTATUS DecryptPatchGuardContext(PUCHAR Key, ULONG KeySize, PVOID Encrypted, PVOID Decrypted, ULONG Size) {
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_KEY_HANDLE hKey;
    NTSTATUS status;
    ULONG result;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) return status;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_XTS, sizeof(BCRYPT_CHAIN_MODE_XTS), 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return status;
    }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, Key, KeySize, 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return status;
    }

    status = BCryptDecrypt(hKey, Encrypted, Size, NULL, NULL, 0, Decrypted, Size, &result, 0);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    DebugLog("Decryption status: 0x%08X\n", status);
    return status;
}
