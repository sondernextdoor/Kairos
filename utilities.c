#include "utilities.h"
#include <stdarg.h>
#include <wdm.h>

PVOID ResolveKernelSymbol(const CHAR* symbolName) {
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, symbolName);
    return MmGetSystemRoutineAddress(&name);
}

BOOLEAN IsWindows11OrLater(void) {
    RTL_OSVERSIONINFOW version = {0};
    version.dwOSVersionInfoSize = sizeof(version);
    if (NT_SUCCESS(RtlGetVersion(&version))) {
        return version.dwMajorVersion >= 10 && version.dwBuildNumber >= 22000;
    }
    return FALSE;
}

VOID DebugLog(const CHAR* format, ...) {
#if DBG
    va_list args;
    va_start(args, format);
    vDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, format, args);
    va_end(args);
#endif
}
