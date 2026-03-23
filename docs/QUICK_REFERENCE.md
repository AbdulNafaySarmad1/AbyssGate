# ABYSSGATE Quick Reference Guide

## File Structure

```
ABYSSGATE/
├── src/
│   ├── stage0_dropper/
│   │   └── stage0.asm          # Entry point (~1.2KB)
│   ├── stage1_loader/
│   │   └── stage1.asm          # Main loader (~7KB)
│   ├── stage2_beacon/
│   │   └── stage2.asm          # C2 beacon (~10KB)
│   └── common/
│       └── utils.asm           # Shared utilities
├── build/
│   ├── abyssgate_shellcode.bin # Final payload
│   ├── stage*.bin              # Individual stages
│   └── test_loader.c           # Test harness
├── variants/
│   └── abyssgate_v*.bin        # Polymorphic variants
├── docs/
│   ├── ARCHITECTURE.md         # Technical details
│   ├── PRESENTATION.md         # COAL lab slides
│   └── API_HASHES.md           # Hash reference
├── build.sh                    # Build script
└── README.md                   # Main documentation
```

## Quick Commands

### Build Everything
```bash
./build.sh
```

### Manual Assembly
```bash
# Stage 0
nasm -f bin src/stage0_dropper/stage0.asm -o build/stage0.bin

# Stage 1
nasm -f bin src/stage1_loader/stage1.asm -o build/stage1.bin

# Stage 2
nasm -f bin src/stage2_beacon/stage2.asm -o build/stage2.bin
```

### Test in VM
```bash
# Copy to VM
scp build/abyssgate_shellcode.bin user@vm:/tmp/

# Compile test harness
gcc -o test_loader build/test_loader.c

# Run
./test_loader /tmp/abyssgate_shellcode.bin
```

## API Hashes (ROR13)

| Module/Function | Hash Value |
|-----------------|------------|
| ntdll.dll | 0x22D3B5ED |
| kernel32.dll | 0x29A9D0C8 |
| kernelbase.dll | 0x4B1FFE8C |
| wininet.dll | 0x8F8F114D |
| LoadLibraryA | 0x8A8B4036 |
| GetProcAddress | 0xAAC5C2E1 |
| VirtualAlloc | 0x09CE0D4A |
| VirtualProtect | 0xC929E6B4 |
| Sleep | 0xE07EBCC9 |
| NtAllocateVirtualMemory | 0xE7C0585E |
| NtProtectVirtualMemory | 0x157B46C3 |
| NtCreateThreadEx | 0xD3C5D9B2 |

## Syscall Numbers (Win11 25H2)

| Function | SSN (hex) |
|----------|-----------|
| NtAllocateVirtualMemory | 0x18 |
| NtProtectVirtualMemory | 0x50 |
| NtCreateThreadEx | 0xC7 |
| NtQueueApcThread | 0x45 |
| NtDelayExecution | 0x34 |
| NtQueryInformationProcess | 0x19 |

## Memory Layout

```
Stage 0: 0x00xxxxxx (1.2KB, RWX)
    ↓ decrypts
Stage 1: 0x00yyyyyy (7KB, RWX)
    ↓ decrypts
Stage 2: 0x00zzzzzz (10KB, RWX)
    ↓ executes
C2 Loop: HTTPS beacon
```

## C2 Protocol

**Request Format:**
```
[SESSION_ID:8][CMD:1][LEN:4][DATA:LEN]
```

**Commands:**
- 0x01: PING
- 0x02: EXEC
- 0x03: DOWNLOAD
- 0x04: UPLOAD
- 0x05: SHELL
- 0x06: INJECT
- 0xFF: EXIT

**Encryption:** Rolling XOR with session key

## Anti-Analysis Checklist

| Check | Offset/Method | Response |
|-------|--------------|----------|
| PEB.BeingDebugged | gs:[0x60]+0x2 | Light |
| NtGlobalFlag | gs:[0x60]+0xBC | Light |
| Heap Flags | PEB+0x30 → +0x40 | Medium |
| Remote Debug | NtQueryInfoProc | Medium |
| Hardware BP | DR0-DR7 | Heavy |
| RDTSC | rdtsc delta | Heavy |
| CET | PEB+0xEC | Heavy |
| Tools | Module hash | Exit |

## Debugging Tips

### Enable Logging
```nasm
; Add to stage0/stage1 for debugging
; Only for development, remove in production

call debug_log
debug_log:
    ; Save registers
    push rax
    push rcx
    push rdx

    ; MessageBoxA with status
    ; (requires resolving MessageBoxA)

    ; Restore registers
    pop rdx
    pop rcx
    pop rax
    ret
```

### Common Issues

| Issue | Solution |
|-------|----------|
| Crash on PEB access | Check GS segment (x64) |
| API not found | Verify hash calculation |
| Decryption fails | Check key/nonce alignment |
| Syscall fails | Verify SSN for build |
| AMSI patch fails | Check if AMSI loaded |

### VM Setup

**Hyper-V Gen2:**
```powershell
# Enable VBS
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -Value 1

# Enable HVCI
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 1
```

**VMware:**
- Virtualization engine: Intel VT-x/EPT
- Virtualization-based security: ON
- Nested virtualization: ON

## Size Optimization Tips

1. **Use smaller registers** (eax vs rax) when possible
2. **RIP-relative addressing** instead of absolute
3. **Shared code** in common/utils.asm
4. **Loop unrolling** for small fixed iterations
5. **Avoid redundant pushes/pops**

Current sizes:
- Stage 0: 1,200 bytes (target: <1,500)
- Stage 1: 7,000 bytes (target: <8,000)
- Stage 2: 10,000 bytes (target: <12,000)

## Security Checklist

Before deployment:
- [ ] All debug code removed
- [ ] Unique encryption keys generated
- [ ] C2 domain configured
- [ ] Tested on target build (26200.8039)
- [ ] Polymorphic variants generated
- [ ] Documentation complete
- [ ] Legal authorization obtained

## Troubleshooting

### Build Errors
```bash
# NASM not found
sudo apt-get install nasm    # Linux
brew install nasm            # macOS
choco install nasm           # Windows

# Python errors
pip install pycryptodome     # For crypto operations
```

### Runtime Errors
```
0xC0000005 (Access Violation):
- Check memory permissions (should be RWX)
- Verify PIC addressing
- Check stack alignment

0xC0000409 (Stack Buffer Overflow):
- Increase stack reserve
- Check buffer sizes

Infinite loop:
- Check anti-analysis triggers
- Verify API resolution
```

## Contact & Support

**Project:** ABYSSGATE  
**Version:** 1.0  
**Date:** March 2026  
**Platform:** Windows 11 25H2 (Build 26200.8039)

For educational use only.
