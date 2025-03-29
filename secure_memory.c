#include "secure_memory.h"
#include "../common/utilities.h"

NTSTATUS ReadSecureMemory(PVOID Address, PVOID Buffer, ULONG Size) {
    UNREFERENCED_PARAMETER(Address);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(Size);
    DebugLog("Attempting to read secure memory via hypercall...\n");
    return STATUS_NOT_IMPLEMENTED;
}
