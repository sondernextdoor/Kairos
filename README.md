# Kairos
Windows 11 PatchGuard Bypass
windows-kernel-framework/
├── include/
│   └── windows_kernel_framework.h
├── src/
│   ├── common/
│   │   ├── utilities.h
│   │   └── utilities.c
│   ├── patchguard/
│   │   ├── pg_context.h
│   │   ├── pg_context.c
│   │   └── pg_exploit.c
│   ├── hvci/
│   │   ├── hvci_policy.h
│   │   └── hvci_policy.c
│   ├── vbs/
│   │   ├── secure_memory.h
│   │   └── secure_memory.c
│   ├── tpm_pluton/
│   │   ├── tpm_integration.h
│   │   └── tpm_integration.c
│   └── main.c
├── tools/
│   └── win_dbg_scripts/
│       ├── pg_scan.txt
│       └── secure_memory_dump.txt
├── README.md
├── LICENSE
└── Makefile / .vcxproj
