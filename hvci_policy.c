#include "hvci_policy.h"
#include "../common/utilities.h"

NTSTATUS HvciValidateImage(PVOID ImageBase) {
    UNREFERENCED_PARAMETER(ImageBase);
    DebugLog("Validating image via HVCI...\n");
    return STATUS_SUCCESS;
}

NTSTATUS SpoofCiPolicy(PCWSTR DriverPath) {
    UNREFERENCED_PARAMETER(DriverPath);
    DebugLog("Spoofing CI policy for driver: %ws\n", DriverPath);
    return STATUS_SUCCESS;
}
