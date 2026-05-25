#!/usr/bin/env python3
"""
crypto_scratch.py
Custom Cryptographic Library Implemented From Scratch.
No external cryptographic APIs are used.
"""

import time
import random

# =====================================================================
# 1. SHA-256 IMPLEMENTATION
# =====================================================================

SHA256_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

def rotr(x, n, size=32):
    return ((x >> n) | (x << (size - n))) & ((1 << size) - 1)

def sha256_compress(h, chunk):
    w = [0] * 64
    for i in range(16):
        w[i] = int.from_bytes(chunk[i*4 : i*4+4], 'big')
    
    for i in range(16, 64):
        s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3)
        s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10)
        w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xffffffff
        
    a, b, c, d, e, f, g, h_val = h
    
    for i in range(64):
        S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        ch = (e & f) ^ (~e & g)
        temp1 = (h_val + S1 + ch + SHA256_K[i] + w[i]) & 0xffffffff
        S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & 0xffffffff
        
        h_val = g
        g = f
        f = e
        e = (d + temp1) & 0xffffffff
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xffffffff
        
    return [
        (h[0] + a) & 0xffffffff,
        (h[1] + b) & 0xffffffff,
        (h[2] + c) & 0xffffffff,
        (h[3] + d) & 0xffffffff,
        (h[4] + e) & 0xffffffff,
        (h[5] + f) & 0xffffffff,
        (h[6] + g) & 0xffffffff,
        (h[7] + h_val) & 0xffffffff
    ]

def sha256(message: bytes) -> bytes:
    h = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]
    bit_len = len(message) * 8
    padded = bytearray(message)
    padded.append(0x80)
    
    # Pad with zeros until we are 8 bytes short of a multiple of 64 bytes
    while (len(padded) + 8) % 64 != 0:
        padded.append(0x00)
        
    # Append length in bits as 8-byte big-endian
    padded.extend(bit_len.to_bytes(8, 'big'))
    
    for i in range(0, len(padded), 64):
        chunk = padded[i : i+64]
        h = sha256_compress(h, chunk)
        
    return b''.join(val.to_bytes(4, 'big') for val in h)

def sha256_hex(message: bytes) -> str:
    return sha256(message).hex()


# =====================================================================
# 2. HMAC-SHA256 IMPLEMENTATION
# =====================================================================

def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    block_size = 64
    if len(key) > block_size:
        key = sha256(key)
    if len(key) < block_size:
        key = key + b'\x00' * (block_size - len(key))
        
    o_key_pad = bytes(x ^ 0x5C for x in key)
    i_key_pad = bytes(x ^ 0x36 for x in key)
    
    inner_hash = sha256(i_key_pad + msg)
    return sha256(o_key_pad + inner_hash)

def hmac_sha256_hex(key: bytes, msg: bytes) -> str:
    return hmac_sha256(key, msg).hex()


# =====================================================================
# 3. AES-256 (CBC MODE) IMPLEMENTATION
# =====================================================================

# S-Box & Inverse S-Box
AES_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

AES_INV_SBOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

AES_RCON = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
]

def sub_word(word):
    return [(AES_SBOX[b]) for b in word]

def rot_word(word):
    return word[1:] + word[:1]

def aes_key_expansion(key_bytes):
    # AES-256 takes 32-byte keys, resulting in 15 round keys of 16 bytes (total 60 4-byte words)
    words = []
    # Load original 8 words (32 bytes)
    for i in range(8):
        words.append(list(key_bytes[i*4 : i*4+4]))
        
    for i in range(8, 60):
        temp = list(words[i-1])
        if i % 8 == 0:
            temp = rot_word(temp)
            temp = sub_word(temp)
            temp[0] ^= AES_RCON[i // 8]
        elif i % 8 == 4:
            temp = sub_word(temp)
            
        new_word = [words[i-8][j] ^ temp[j] for j in range(4)]
        words.append(new_word)
        
    # Convert word list to 15 flat round keys (each 16 bytes)
    round_keys = []
    for r in range(15):
        flat = []
        for w_idx in range(4):
            flat.extend(words[r*4 + w_idx])
        round_keys.append(flat)
    return round_keys

def add_round_key(state, round_key):
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i + j*4]

def sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = AES_SBOX[state[i][j]]

def inv_sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = AES_INV_SBOX[state[i][j]]

def shift_rows(state):
    # Row 0: shift 0
    # Row 1: shift 1 left
    state[1] = state[1][1:] + state[1][:1]
    # Row 2: shift 2 left
    state[2] = state[2][2:] + state[2][:2]
    # Row 3: shift 3 left
    state[3] = state[3][3:] + state[3][:3]

def inv_shift_rows(state):
    # Row 0: shift 0
    # Row 1: shift 1 right
    state[1] = state[1][-1:] + state[1][:-1]
    # Row 2: shift 2 right
    state[2] = state[2][-2:] + state[2][:-2]
    # Row 3: shift 3 right
    state[3] = state[3][-3:] + state[3][:-3]

# Galois Field (2^8) multiplication by x (which is 0x02)
def xtime(a):
    return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

def gf_mul(a, b):
    # Russian Peasant multiplication in GF(2^8)
    p = 0
    for i in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a = (a << 1) & 0xff
        if hi_bit_set:
            a ^= 0x1b
        b >>= 1
    return p

def mix_columns(state):
    for c in range(4):
        s0 = state[0][c]
        s1 = state[1][c]
        s2 = state[2][c]
        s3 = state[3][c]
        
        state[0][c] = xtime(s0) ^ (xtime(s1) ^ s1) ^ s2 ^ s3
        state[1][c] = s0 ^ xtime(s1) ^ (xtime(s2) ^ s2) ^ s3
        state[2][c] = s0 ^ s1 ^ xtime(s2) ^ (xtime(s3) ^ s3)
        state[3][c] = (xtime(s0) ^ s0) ^ s1 ^ s2 ^ xtime(s3)

def inv_mix_columns(state):
    for c in range(4):
        s0 = state[0][c]
        s1 = state[1][c]
        s2 = state[2][c]
        s3 = state[3][c]
        
        state[0][c] = gf_mul(0x0e, s0) ^ gf_mul(0x0b, s1) ^ gf_mul(0x0d, s2) ^ gf_mul(0x09, s3)
        state[1][c] = gf_mul(0x09, s0) ^ gf_mul(0x0e, s1) ^ gf_mul(0x0b, s2) ^ gf_mul(0x0d, s3)
        state[2][c] = gf_mul(0x0d, s0) ^ gf_mul(0x09, s1) ^ gf_mul(0x0e, s2) ^ gf_mul(0x0b, s3)
        state[3][c] = gf_mul(0x0b, s0) ^ gf_mul(0x0d, s1) ^ gf_mul(0x09, s2) ^ gf_mul(0x0e, s3)

def aes_encrypt_block(block, round_keys):
    # Initialize state (4x4 matrix, column-major)
    state = [[0]*4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            state[r][c] = block[r + c*4]
            
    # Round 0
    add_round_key(state, round_keys[0])
    
    # Rounds 1-13
    for r in range(1, 14):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[r])
        
    # Round 14
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[14])
    
    # Flatten state back to block
    out = [0]*16
    for r in range(4):
        for c in range(4):
            out[r + c*4] = state[r][c]
    return bytes(out)

def aes_decrypt_block(block, round_keys):
    # Initialize state
    state = [[0]*4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            state[r][c] = block[r + c*4]
            
    # Round 14 (reverse round key 14)
    add_round_key(state, round_keys[14])
    inv_shift_rows(state)
    inv_sub_bytes(state)
    
    # Rounds 13 to 1
    for r in range(13, 0, -1):
        add_round_key(state, round_keys[r])
        inv_mix_columns(state)
        inv_shift_rows(state)
        inv_sub_bytes(state)
        
    # Round 0
    add_round_key(state, round_keys[0])
    
    # Flatten
    out = [0]*16
    for r in range(4):
        for c in range(4):
            out[r + c*4] = state[r][c]
    return bytes(out)

# PKCS#7 Padding
def pkcs7_pad(data, block_size=16):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data, block_size=16):
    if len(data) == 0:
        raise ValueError("Data empty")
    if len(data) % block_size != 0:
        raise ValueError("Data length is not multiple of block size")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding value")
    for i in range(len(data) - pad_len, len(data)):
        if data[i] != pad_len:
            raise ValueError("Invalid padding bytes")
    return data[:-pad_len]

# AES-256 CBC Mode
def aes_256_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes (256 bits) for AES-256")
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes (128 bits)")
    
    round_keys = aes_key_expansion(key)
    padded = pkcs7_pad(plaintext)
    ciphertext = bytearray()
    
    prev_cipher_block = iv
    for i in range(0, len(padded), 16):
        block = padded[i : i+16]
        # XOR block with previous cipher block
        xor_block = bytes(block[j] ^ prev_cipher_block[j] for j in range(16))
        encrypted_block = aes_encrypt_block(xor_block, round_keys)
        ciphertext.extend(encrypted_block)
        prev_cipher_block = encrypted_block
        
    return bytes(ciphertext)

def aes_256_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes (256 bits) for AES-256")
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes (128 bits)")
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be a multiple of 16")
        
    round_keys = aes_key_expansion(key)
    plaintext = bytearray()
    
    prev_cipher_block = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i : i+16]
        decrypted_block = aes_decrypt_block(block, round_keys)
        # XOR decrypted block with previous cipher block
        plain_block = bytes(decrypted_block[j] ^ prev_cipher_block[j] for j in range(16))
        plaintext.extend(plain_block)
        prev_cipher_block = block
        
    return pkcs7_unpad(bytes(plaintext))


# =====================================================================
# 4. RSA-1024 IMPLEMENTATION
# =====================================================================

def modular_exponentiation(base, exp, mod):
    """
    Binary Exponentiation / Right-to-Left Exponentiation
    Computes (base^exp) % mod in O(log exp) time.
    """
    res = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            res = (res * base) % mod
        base = (base * base) % mod
        exp //= 2
    return res

def miller_rabin(n, k=40):
    """
    Miller-Rabin Primality Test
    Returns True if n is probably prime, False if n is composite.
    """
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False
        
    # Write n - 1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
        
    # Witness loop
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = modular_exponentiation(a, d, n)
        if x == 1 or x == n - 1:
            continue
        composite_found = True
        for _ in range(r - 1):
            x = modular_exponentiation(x, 2, n)
            if x == n - 1:
                composite_found = False
                break
        if composite_found:
            return False
    return True

def generate_prime(bits=512):
    """
    Generates a prime number of target bits.
    """
    while True:
        # Generate random odd integer of size bits
        candidate = random.getrandbits(bits)
        candidate |= (1 << (bits - 1)) | 1 # Ensure it has the correct bit length and is odd
        
        # Fast divisibility check for first small primes to speed up generation
        small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]
        divisible = False
        for p in small_primes:
            if candidate != p and candidate % p == 0:
                divisible = True
                break
        if divisible:
            continue
            
        if miller_rabin(candidate, k=30):
            return candidate

def extended_gcd(a, b):
    """
    Extended Euclidean Algorithm
    Returns (gcd, x, y) such that a*x + b*y = gcd
    """
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def modular_inverse(e, phi):
    """
    Computes d = e^(-1) mod phi
    """
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    else:
        return x % phi

def generate_rsa_keys(bits=1024):
    """
    Generates public (e, n) and private (d, n) keypairs of 'bits' size.
    For bits=1024, generates two primes p and q of bits=512.
    """
    p = generate_prime(bits // 2)
    while True:
        q = generate_prime(bits // 2)
        if q != p:
            break
            
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Standard RSA public exponent
    e = 65537
    d = modular_inverse(e, phi)
    
    return (e, n), (d, n)

def rsa_encrypt(plaintext: bytes, pubkey) -> bytes:
    e, n = pubkey
    # Convert bytes to an integer
    m = int.from_bytes(plaintext, 'big')
    if m >= n:
        raise ValueError("Plaintext too large for RSA key modulus")
    c = modular_exponentiation(m, e, n)
    # Output length: size of n in bytes
    n_bytes = (n.bit_length() + 7) // 8
    return c.to_bytes(n_bytes, 'big')

def rsa_decrypt(ciphertext: bytes, privkey) -> bytes:
    d, n = privkey
    c = int.from_bytes(ciphertext, 'big')
    if c >= n:
        raise ValueError("Ciphertext too large for RSA key modulus")
    m = modular_exponentiation(c, d, n)
    # Estimate message length and convert to bytes
    n_bytes = (n.bit_length() + 7) // 8
    msg_bytes = m.to_bytes(n_bytes, 'big')
    # Strip leading zero padding if any
    return msg_bytes.lstrip(b'\x00')
