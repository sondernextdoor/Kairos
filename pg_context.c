#include "pg_context.h"
#include "../common/utilities.h"
#include <bcrypt.h>

PVOID ValidatePgContext(PVOID Address) {
    if (MmIsAddressValid(Address)) {
        return Address;
    }
    return NULL;
}

NTSTATUS FindPatchGuardContext(PVOID* OutContext) {
    if (!OutContext) return STATUS_INVALID_PARAMETER;

    PVOID base = GetKernelBase();
    ULONG size = GetKernelSize();

    if (!base || !size) return STATUS_UNSUCCESSFUL;

    const CHAR signature[] = "Monitor";
    const SIZE_T sigLen = sizeof(signature) - 1;

    for (ULONG offset = 0; offset < size - sigLen; offset++) {
        PUCHAR ptr = (PUCHAR)base + offset;

        // Match the "Monitor" string, which has been used by PG contexts
        if (RtlCompareMemory(ptr, signature, sigLen) == sigLen) {
            DebugLog("Potential PG context found at: %p\n", ptr);

            if (MmIsAddressValid(ptr)) {
                *OutContext = (PVOID)ptr;
                return STATUS_SUCCESS;
            }
        }
    }

    return STATUS_NOT_FOUND;
}

VOID ExtractPgEncryptionKey(PVOID Context, PUCHAR KeyBuffer) {
    if (!Context || !KeyBuffer)
        return;

    // Try to extract from a fixed offset within the PG context (observed in Win10 PG)
    PUCHAR keyCandidate = (PUCHAR)Context + PG_KEY_DERIVATION_OFFSET;

    // Naive validation – check if it looks like a real key
    if (MmIsAddressValid(keyCandidate)) {
        RtlCopyMemory(KeyBuffer, keyCandidate, 32);
        DebugLog("Extracted PG key from context: %p\n", keyCandidate);
    } else {
        RtlFillMemory(KeyBuffer, 32, 0x42);  // fallback marker
        DebugLog("Fallback PG key used.\n");
    }
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
