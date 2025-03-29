#pragma once

#include <ntddk.h>

NTSTATUS DumpTpmPcrs(void);
NTSTATUS FakePlutonAttestation(PVOID FakeMeasurement);
