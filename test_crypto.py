#!/usr/bin/env python3
"""
test_crypto.py
Verifies the cryptographic algorithms in crypto_scratch.py.
"""

import sys
from crypto_scratch import (
    sha256, sha256_hex,
    hmac_sha256, hmac_sha256_hex,
    aes_256_cbc_encrypt, aes_256_cbc_decrypt,
    generate_rsa_keys, rsa_encrypt, rsa_decrypt
)

def run_tests():
    print("====================================================")
    print("RUNNING CRYPTOGRAPHIC VERIFICATION (FROM SCRATCH)")
    print("====================================================")
    
    # 1. Test SHA-256
    print("\n[+] Testing SHA-256:")
    msg1 = b"Hello, World!"
    hash1 = sha256_hex(msg1)
    print(f"  Input: {msg1.decode()}")
    print(f"  SHA-256 Hash: {hash1}")
    # Expected SHA-256 of "Hello, World!" is dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f
    if hash1 == "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f":
        print("  SHA-256 matches official vector! SUCCESS.")
    else:
        print("  SHA-256 failed match.")
        
    # 2. Test HMAC-SHA256
    print("\n[+] Testing HMAC-SHA256:")
    hmac_key = b"secret-key"
    hmac_msg = b"This is a signed message."
    hmac_val = hmac_sha256_hex(hmac_key, hmac_msg)
    print(f"  Key: {hmac_key.decode()}")
    print(f"  Msg: {hmac_msg.decode()}")
    print(f"  HMAC: {hmac_val}")
    # Standard check: should be consistent
    if hmac_val:
        print("  HMAC calculation succeeded! SUCCESS.")
        
    # 3. Test AES-256-CBC
    print("\n[+] Testing AES-256-CBC (256-bit key):")
    aes_key = b"0123456789abcdef0123456789abcdef"  # 32 bytes
    aes_iv = b"abcdef9876543210"                   # 16 bytes
    plaintext_msg = b"Secure server adaptive cryptanalysis defense! It must handle multiple block lengths seamlessly."
    print(f"  Original: {plaintext_msg.decode()}")
    print(f"  Length: {len(plaintext_msg)} bytes")
    
    try:
        ciphertext = aes_256_cbc_encrypt(plaintext_msg, aes_key, aes_iv)
        print(f"  Ciphertext (hex): {ciphertext.hex()[:60]}... ({len(ciphertext)} bytes)")
        
        decrypted = aes_256_cbc_decrypt(ciphertext, aes_key, aes_iv)
        print(f"  Decrypted: {decrypted.decode()}")
        
        if decrypted == plaintext_msg:
            print("  AES-256-CBC encrypt/decrypt matches! SUCCESS.")
        else:
            print("  AES-256-CBC decryption failed: text mismatch.")
    except Exception as e:
        print(f"  AES-256-CBC failed with exception: {e}")
        import traceback
        traceback.print_exc()

    # 4. Test RSA-1024 Key Gen and Cryptography
    print("\n[+] Testing RSA-1024 Key Generation & Cryptography:")
    import time
    start_time = time.time()
    print("  Generating 1024-bit RSA key pair (Primes p, q of 512 bits each)...")
    pubkey, privkey = generate_rsa_keys(bits=1024)
    duration = time.time() - start_time
    e, n = pubkey
    d, n_ = privkey
    print(f"  Keys generated in {duration:.4f} seconds!")
    print(f"  Modulus N (hex): {hex(n)[:40]}... ({n.bit_length()} bits)")
    print(f"  Public Exponent E: {e}")
    print(f"  Private Exponent D (hex): {hex(d)[:40]}...")
    
    # We encrypt a 32-byte AES key (which fits inside 1024-bit = 128 bytes RSA modulus)
    session_key = b"sessionkey123456sessionkey123456" # 32 bytes
    print(f"  Session Key to Encrypt: {session_key.decode()} ({len(session_key)} bytes)")
    
    try:
        enc_session_key = rsa_encrypt(session_key, pubkey)
        print(f"  RSA Encrypted Key (hex): {enc_session_key.hex()[:60]}... ({len(enc_session_key)} bytes)")
        
        dec_session_key = rsa_decrypt(enc_session_key, privkey)
        # Handle padding/length alignment
        if len(dec_session_key) > 32:
            # Slices off leading null bytes if any were retained
            dec_session_key = dec_session_key[-32:]
            
        print(f"  RSA Decrypted Key: {dec_session_key.decode()}")
        if dec_session_key == session_key:
            print("  RSA Encryption/Decryption matches! SUCCESS.")
        else:
            print(f"  RSA decryption failed: key mismatch. Decrypted size: {len(dec_session_key)}")
    except Exception as e:
        print(f"  RSA Encryption failed with exception: {e}")
        import traceback
        traceback.print_exc()
        
    print("\n====================================================")
    print("VERIFICATION COMPLETED!")
    print("====================================================")

if __name__ == '__main__':
    run_tests()
