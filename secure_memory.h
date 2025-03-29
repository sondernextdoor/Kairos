#pragma once

#include <ntddk.h>

NTSTATUS ReadSecureMemory(PVOID Address, PVOID Buffer, ULONG Size);
