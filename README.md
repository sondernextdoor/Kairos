# Kairos
# Windows 11 PatchGuard Bypass

This framework is a research-oriented Windows kernel driver that demonstrates how to locate, decrypt, and potentially bypass PatchGuard (KPP) contexts, spoof hypervisor-protected code integrity (HVCI) policies, read secure memory regions guarded by virtualization-based security (VBS), and simulate TPM/Pluton attestation data. It includes code for hardware breakpoint handling (synchronized across all cores) to intercept PatchGuard or security checks and revert changes just-in-time, allowing deeper exploration of Windows 11 kernel defenses in a controlled, educational setting.

```
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

