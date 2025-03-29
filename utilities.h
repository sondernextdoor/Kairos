#pragma once

#include <ntddk.h>

PVOID ResolveKernelSymbol(const CHAR* symbolName);
BOOLEAN IsWindows11OrLater(void);
VOID DebugLog(const CHAR* format, ...);
