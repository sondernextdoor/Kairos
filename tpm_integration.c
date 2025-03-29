#include "tpm_integration.h"
#include "../common/utilities.h"

NTSTATUS DumpTpmPcrs(void) {
    DebugLog("Dumping TPM PCRs (stub)...\n");
    return STATUS_SUCCESS;
}

NTSTATUS FakePlutonAttestation(PVOID FakeMeasurement) {
    UNREFERENCED_PARAMETER(FakeMeasurement);
    DebugLog("Simulating fake Pluton attestation...\n");
    return STATUS_SUCCESS;
}
