# Kairos  
**Windows 11 PatchGuard, HVCI, and TPM Research Framework**

**Kairos** is an advanced research framework designed to explore, monitor, and (selectively) bypass Windows 11 kernel security mechanisms including **PatchGuard (KPP)**, **HVCI (Hypervisor-Protected Code Integrity)**, **VBS-protected memory**, and **TPM/Pluton attestation**.

> **DISCLAIMER:** This project is intended for **academic research, education, and security analysis** only.  
> It should not be used in production environments or for malicious purposes. Misuse may violate local laws and security policies.

---

## Features

- **PatchGuard Context Detection & Decryption**
  - Locates PG memory structures via signature scanning
  - Decrypts contexts using observed AES-XTS keys
  - Tracks `LastCheckTime` and evades PG runtime validation

- **Dynamic Patch Reversion**
  - Registers runtime kernel patches
  - Automatically reverts them just before PG checks
  - Reapplies patches after PG completes

- **HVCI Policy Spoofing (Stubbed)**
  - Interfaces for future bypasses of Windows Code Integrity enforcement

- **TPM/Pluton Attestation Spoofing (Stubbed)**
  - Designed to simulate PCR measurements and spoof secure boot attestation

- **VBS Secure Memory Reading (Planned)**
  - Framework support for hypercall-based secure memory extraction

- **System Stealth**
  - Driver cloaking from `PsLoadedModuleList`
  - PE header wiping and name obfuscation
  - Hooking of `KeInsertQueueDpc`, `KeBugCheckEx` to block PG and BSOD

---

## Architecture

```text
DriverEntry() → Detect PatchGuard → Spawn Monitor Thread
    ↳ Detects PatchGuard Contexts
    ↳ Registers Kernel Patches (Encrypted)
    ↳ On PG Activity:
        ↳ Revert Patches → Let PG Pass → Reapply
    ↳ Logs & Monitors Secure Structures

Kairos/
├── include/
│   └── windows_kernel_framework.h      # Central framework header
├── src/
│   ├── main.c                          # Driver entry, patch logic, monitor thread
│   ├── patchguard/
│   │   ├── pg_context.c/.h             # PG detection & decryption
│   │   └── pg_exploit.c                # PG activation timestamp discovery
│   ├── hvci/
│   │   ├── hvci_policy.c/.h            # HVCI spoofing (stubbed)
│   ├── vbs/
│   │   ├── secure_memory.c/.h          # Secure memory access (stubbed)
│   ├── tpm_pluton/
│   │   ├── tpm_integration.c/.h        # TPM spoofing (stubbed)
│   └── common/
│       ├── utilities.c/.h              # Symbol resolution, OS checks, logging
├── windows-kernel-framework.vcxproj   # Visual Studio KMDF project
└── README.md                          This file
