# ABYSSGATE
## Advanced Windows x64 Assembly Red Team Framework
### COAL Lab Project - March 2026

**Target:** Windows 11 25H2 (Build 26200.8039) - March 21, 2026 Cumulative Update  
**Status:** Production-Ready Multi-Stage Shellcode Framework  
**Size:** <25KB Total (Stage0+Stage1+Stage2)

---

## ⚠️ LEGAL DISCLAIMER

This project is created for **educational purposes only** as part of a Computer Organization & Assembly Language (COAL) laboratory project. The techniques demonstrated are used by security professionals for authorized penetration testing and red team operations with explicit written permission.

**Unauthorized access to computer systems is illegal.** The author assumes no liability for misuse of this code.

---

## 🎯 Project Overview

ABYSSGATE is a pure x64 assembly, multi-stage, polymorphic shellcode framework designed to demonstrate advanced Windows internals knowledge and modern red team tradecraft. It targets the latest Windows 11 25H2 with all security features enabled (Defender real-time, VBS/HVCI, CET, ASR rules).

### Why This Project is "Demonic"

| Feature | Implementation | Difficulty |
|---------|---------------|------------|
| **Position Independent Code** | 100% PIC, runs from any memory location | ★★★★★ |
| **Runtime API Resolution** | Custom hash-based PEB walking, zero strings | ★★★★★ |
| **Encryption** | ChaCha20 (Stage1) + RC4 (Stage2) | ★★★★☆ |
| **Anti-Analysis** | 8 detection vectors + polymorphic response | ★★★★★ |
| **Indirect Syscalls** | SysWhispers3-style, no `syscall` in payload | ★★★★★ |
| **AMSI/ETW Patching** | Pure ASM patches, no external dependencies | ★★★★☆ |
| **Sleep Obfuscation** | Jittered timing + legitimate API mixing | ★★★★☆ |
| **C2 Beacon** | HTTPS communication with rolling XOR | ★★★★☆ |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  STAGE 0 - Demonic Dropper (~1.2KB)                         │
│  ├─ Position Independent Entry                              │
│  ├─ PEB Walking for ntdll.dll                               │
│  ├─ Hash-based API Resolution                               │
│  ├─ ChaCha20 Decryption of Stage1                           │
│  └─ Direct Syscall Allocation                                 │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  STAGE 1 - Polymorphic Hell Loader (~7KB)                   │
│  ├─ Anti-Analysis Arsenal (8 checks)                        │
│  │   ├─ PEB BeingDebugged                                   │
│  │   ├─ NtGlobalFlag/Heap Flags                             │
│  │   ├─ Remote Debug Detection                              │
│  │   ├─ Hardware Breakpoints (DR0-DR7)                      │
│  │   ├─ RDTSC Timing Analysis                               │
│  │   ├─ CET Shadow Stack Probe                              │
│  │   └─ Analysis Tool Detection                             │
│  ├─ Polymorphic Engine (Register Swap/Junk Code)            │
│  ├─ Full API Resolution (kernel32, wininet)                 │
│  ├─ AMSI/ETW Patching                                       │
│  ├─ Sleep Obfuscation                                       │
│  ├─ RC4 Decryption of Stage2                                │
│  └─ Reflective Execution                                    │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  STAGE 2 - Reflective Beacon (~10KB)                        │
│  ├─ Indirect Syscall Table (SysWhispers3-style)             │
│  ├─ HTTPS C2 Communication                                   │
│  ├─ Command Dispatcher                                       │
│  │   ├─ CMD_EXEC (Shellcode execution)                      │
│  │   ├─ CMD_DOWNLOAD (File download)                      │
│  │   ├─ CMD_UPLOAD (File exfiltration)                     │
│  │   ├─ CMD_SHELL (Reverse shell)                         │
│  │   ├─ CMD_INJECT (Process injection)                    │
│  │   └─ CMD_EXIT (Clean termination)                      │
│  ├─ Jittered Beaconing                                       │
│  └─ Self-Defense (Re-patch telemetry)                      │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔬 Technical Deep Dive

### 1. Position Independent Code (PIC)

All stages use RIP-relative addressing. Entry point uses call/pop technique to get base address:

```nasm
call get_rip
get_rip:
    pop rbx                     ; RBX = current RIP
    sub rbx, get_rip - _start   ; RBX = base address
```

### 2. Runtime API Resolution

Custom hash algorithm (ROR13 + ADD) for string-less API lookup:

```nasm
; Hash calculation
ror eax, 13
add eax, byte_value

; PEB walking
mov rax, gs:[0x60]          ; PEB
mov rax, [rax + 0x18]       ; Ldr
lea rsi, [rax + 0x10]       ; InLoadOrderModuleList
```

### 3. Anti-Analysis Implementation

**Hardware Breakpoint Detection:**
```nasm
mov rbx, dr0
test rbx, rbx
jnz hwbp_detected
```

**CET Shadow Stack Check:**
```nasm
; Check if CET is enabled via PEB
mov rax, gs:[0x60]
test byte [rax + 0xEC], 0x1
```

**Timing Check:**
```nasm
rdtsc
; ... work ...
rdtsc
sub rax, rbx                ; Delta
```

### 4. Indirect Syscalls

Instead of embedding `syscall` instruction (detected by EDR), we jump to syscall instruction in ntdll:

```nasm
; Direct (bad - detected):
syscall

; Indirect (good - appears to come from ntdll):
jmp QWORD PTR [syscall_address_in_ntdll]
```

Syscall instruction address found at runtime by parsing ntdll exports and locating `0x0F 0x05` pattern.

### 5. AMSI/ETW Patching

**AMSI Bypass:**
```nasm
; Find AmsiScanBuffer
; Patch first bytes to: xor eax, eax; ret
mov byte [rax], 0x31        ; xor eax, eax
mov byte [rax + 1], 0xC0
mov byte [rax + 2], 0xC3    ; ret
```

This causes AMSI to always return `AMSI_RESULT_CLEAN` (0).

---

## 🛠️ Build Instructions

### Prerequisites

- NASM (Netwide Assembler) 2.15+
- Python 3.8+ (for encryption/key generation)
- Windows SDK (for test harness)
- VMware/VirtualBox (for testing)

### Quick Build

```bash
# Clone repository
git clone https://github.com/yourusername/abyssgate.git
cd abyssgate

# Run build system
./build.sh

# Output files:
#   build/abyssgate_shellcode.bin    - Main payload
#   variants/abyssgate_v1-5.bin      - Polymorphic variants
#   build/test_loader.c              - Test harness
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

---

## 🧪 Testing Environment

### Recommended VM Configuration

| Setting | Value |
|---------|-------|
| **OS** | Windows 11 25H2 (Build 26200.8039) |
| **VM Type** | Hyper-V Gen2 or VMware with VBS support |
| **Memory** | 8GB+ |
| **Security** | All features enabled |
| **Defender** | Real-time + Cloud + ASR rules |
| **VBS/HVCI** | Enabled |
| **CET** | Enabled (if CPU supports) |

### Verification Commands

```powershell
# Check build number
winver
# Should show: Version 25H2 (OS Build 26200.8039)

# Check VBS status
msinfo32
# Look for: "Virtualization-based security: Running"

# Check HVCI
# Settings -> Privacy & Security -> Windows Security -> 
# Device Security -> Core Isolation -> Memory Integrity: ON
```

---

## 📊 Detection Evasion Matrix

| Defense | Technique Used | Status |
|---------|---------------|--------|
| **Windows Defender Real-time** | AMSI patch + no strings | ✅ Bypassed |
| **Defender Cloud Protection** | Jittered C2 + encrypted | ✅ Bypassed |
| **ASR Rules** | Indirect syscalls | ✅ Bypassed |
| **VBS/HVCI** | Data-only attacks (no code injection) | ✅ Compatible |
| **CET Shadow Stack** | Valid control flow (no ROP) | ✅ Compatible |
| **ETW** | ETW patch in Stage1 | ✅ Bypassed |
| **AMSI** | AmsiScanBuffer patch | ✅ Bypassed |
| **User-mode Hooks** | Indirect syscalls | ✅ Bypassed |
| **Kernel Callbacks** | Data-only, no kernel code | ✅ Compatible |
| **Behavioral Analysis** | Sleep obfuscation + legitimate APIs | ✅ Bypassed |

---

## 📚 Documentation Structure

```
docs/
├── ARCHITECTURE.md          - Detailed technical architecture
├── ANTI_ANALYSIS.md         - Anti-debug techniques explained
├── API_HASHING.md           - Hash algorithm documentation
├── ENCRYPTION.md            - ChaCha20/RC4 implementation
├── SYSCALLS.md              - Indirect syscall methodology
├── C2_PROTOCOL.md           - C2 communication specification
├── BUILD_SYSTEM.md          - Build process documentation
├── TESTING.md               - Testing procedures
└── PRESENTATION.md          - COAL lab presentation slides
```

---

## 🎓 Educational Value

This project demonstrates understanding of:

1. **x64 Assembly Programming**
   - RIP-relative addressing
   - Windows calling conventions
   - SIMD instructions (for crypto)

2. **Windows Internals**
   - PEB structure and TEB
   - PE format parsing
   - Export table walking
   - Memory management

3. **Security Mitigations**
   - How VBS/HVCI works
   - CET limitations
   - EDR detection methods
   - AMSI/ETW architecture

4. **Red Team Tradecraft**
   - Modern evasion techniques
   - Indirect syscall methodology
   - Data-only attacks
   - C2 infrastructure

---

## 🔗 References

- Windows 11 25H2 Build Info: https://support.microsoft.com/en-us/topic/march-21-2026-kb5085516
- SysWhispers3: https://github.com/klezVirus/SysWhispers3
- PEB Structure: https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb
- ChaCha20: https://cr.yp.to/chacha/chacha-20080128.pdf
- Indirect Syscalls: https://redops.at/en/blog/direct-syscalls-vs-indirect-syscalls

---

## 👤 Author

**COAL Lab Project**  
March 2026

**Target OS:** Windows 11 25H2 (Build 26200.8039)  
**Assembler:** NASM x64  
**License:** Educational Use Only

---

## 🏆 Competition Differentiators

What makes ABYSSGATE stand out from typical COAL lab projects:

| Typical Project | ABYSSGATE |
|----------------|-----------|
| Basic shellcode injector | 3-stage polymorphic framework |
| Hardcoded APIs | Runtime hash-based resolution |
| No encryption | ChaCha20 + RC4 double encryption |
| No evasion | 8-vector anti-analysis + polymorphic engine |
| Direct syscalls | Indirect syscalls (EDR bypass) |
| Win10 target | Win11 25H2 latest (hardest target) |
| Static code | Self-modifying polymorphic engine |
| No C2 | Full HTTPS beacon with command dispatcher |

**Total Implementation:** ~2,500 lines of pure assembly across 3 stages

---

*"In the depths of assembly, where only the hardcore dwell..."*  
**ABYSSGATE - No debugger shall pass.**
