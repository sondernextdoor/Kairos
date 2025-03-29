#pragma once

#include <ntddk.h>

NTSTATUS HvciValidateImage(PVOID ImageBase);
NTSTATUS SpoofCiPolicy(PCWSTR DriverPath);
