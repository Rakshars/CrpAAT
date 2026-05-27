#!/usr/bin/env python3
"""
client.py
Interactive Client & Cyberattack Emulator for Laptop 2 (Client/Attacker).
"""

import sys
import json
import socket
import random
import time
from datetime import datetime

from crypto_scratch import (
    sha256_hex, hmac_sha256_hex,
    aes_256_cbc_encrypt, aes_256_cbc_decrypt,
    rsa_encrypt
)

# Colored console helpers
class Colors:
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    PURPLE = "\033[95m"
    BOLD = "\033[1m"
    END = "\033[0m"

class AdaptiveSecureClient:
    def __init__(self, host='127.0.0.1', port=9999):
        self.host = host
        self.port = port
        self.sock = None
        self.rfile = None
        
        # Cryptographic variables
        self.server_rsa_pub = None # (e, n)
        self.aes_key = None        # Shared 32-byte session key
        self.authenticated = False
        self.username = None
        
        # Last successfully sent packet for replay emulation
        self.last_valid_packet = None
        
    def log(self, tag, message, color=Colors.CYAN):
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        print(f"{color}[{timestamp}] [{tag}] {message}{Colors.END}")

    def connect(self):
        """Connects to server socket."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            self.rfile = self.sock.makefile('rwb', buffering=0)
            self.log("NETWORK", f"Connected to secure server at {self.host}:{self.port}", Colors.GREEN)
            return True
        except Exception as e:
            self.log("ERROR", f"Failed to connect to server: {e}", Colors.RED)
            return False

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None
            self.rfile = None
            self.log("NETWORK", "Connection closed.", Colors.YELLOW)

    def send_line(self, data_dict):
        """Sends raw JSON line."""
        line = json.dumps(data_dict).encode('utf-8') + b'\n'
        self.rfile.write(line)
        self.rfile.flush()

    def read_line(self):
        """Reads raw JSON line."""
        line = self.rfile.readline()
        if not line:
            return None
        return json.loads(line.decode('utf-8').strip())

    # =====================================================================
    # CRYPTOGRAPHIC PROTOCOL OPERATIONS
    # =====================================================================

    def do_key_exchange(self):
        """Step 3: Secure Key Exchange (RSA + AES)."""
        self.log("SECURE", "Initiating RSA+AES Handshake Key Exchange...", Colors.BOLD + Colors.CYAN)
        
        # 1. Send handshake start
        self.send_line({"type": "handshake_start"})
        resp = self.read_line()
        
        if not resp or resp.get("type") != "rsa_pub":
            self.log("ERROR", "Handshake failed: Did not receive RSA public key.", Colors.RED)
            return False
            
        e = int(resp.get("e"), 16)
        n = int(resp.get("n"), 16)
        self.server_rsa_pub = (e, n)
        self.log("CRYPTO", f"Received Server RSA-1024 Public Key.\n  Modulus N: {hex(n)[:35]}...\n  Exponent E: {e}", Colors.GREEN)
        
        # 2. Create random 32-byte AES Session Key (256 bits)
        self.aes_key = bytes(random.getrandbits(8) for _ in range(32))
        self.log("CRYPTO", f"Generated Local 256-bit AES Session Key: {self.aes_key.hex()[:24]}...", Colors.CYAN)
        
        # 3. Encrypt AES Session Key using RSA Public Key
        self.log("CRYPTO", "Encrypting AES key with Server's RSA Public Key (scratch modular math)...", Colors.CYAN)
        enc_aes_key = rsa_encrypt(self.aes_key, self.server_rsa_pub)
        self.log("CRYPTO", f"RSA Encrypted Key size: {len(enc_aes_key)} bytes", Colors.CYAN)
        
        # 4. Send encrypted key to server
        self.send_line({
            "type": "aes_key_exchange",
            "encrypted_key": enc_aes_key.hex()
        })
        
        # 5. Receive confirmation
        resp = self.read_line()
        if not resp or resp.get("type") != "aes_confirm":
            self.log("ERROR", "Key exchange failed: Did not receive encrypted confirmation.", Colors.RED)
            self.aes_key = None
            return False
            
        confirm_iv = bytes.fromhex(resp.get("iv"))
        confirm_cipher = bytes.fromhex(resp.get("ciphertext"))
        
        # Decrypt confirmation
        decrypted = aes_256_cbc_decrypt(confirm_cipher, self.aes_key, confirm_iv)
        if decrypted == b"KEY_EXCHANGE_VERIFIED":
            self.log("SECURE", "AES Key successfully verified by server! Tunnel is now secure.", Colors.GREEN)
            return True
        else:
            self.log("ERROR", "AES Key confirmation mismatch.", Colors.RED)
            self.aes_key = None
            return False

    def encrypt_and_send(self, payload_dict):
        """Encrypts data in AES-256-CBC, signs with HMAC-SHA256, adds Nonce and Timestamp."""
        if not self.aes_key:
            self.log("ERROR", "No active AES Session Key.", Colors.RED)
            return None
            
        # 1. Convert payload to JSON bytes and pad
        plain_bytes = json.dumps(payload_dict).encode('utf-8')
        
        # 2. Generate random 16-byte IV
        iv = bytes(random.getrandbits(8) for _ in range(16))
        
        # 3. Encrypt using custom AES-256-CBC
        ciphertext = aes_256_cbc_encrypt(plain_bytes, self.aes_key, iv)
        
        # 4. Generate Nonce & Timestamp for Replay Protection (Step 7)
        nonce = hex(random.getrandbits(64))
        timestamp = datetime.utcnow().isoformat()
        
        # 5. Calculate HMAC-SHA256 (Step 5)
        # HMAC is calculated over: iv_hex + ciphertext_hex + nonce + timestamp
        hmac_data = f"{iv.hex()}{ciphertext.hex()}{nonce}{timestamp}".encode('utf-8')
        packet_hmac = hmac_sha256_hex(self.aes_key, hmac_data)
        
        packet = {
            "type": "secure_packet",
            "iv": iv.hex(),
            "ciphertext": ciphertext.hex(),
            "nonce": nonce,
            "timestamp": timestamp,
            "hmac": packet_hmac
        }
        
        # Cache packet for future replay attack demo
        self.last_valid_packet = packet
        
        # Send
        self.send_line(packet)
        return packet

    def receive_and_decrypt(self):
        """Receives a secure packet, validates HMAC, and decrypts the payload."""
        resp = self.read_line()
        if not resp:
            return None
            
        # Handle Rekey Request (Step 8 - Adaptive Defense re-key trigger)
        if resp.get("type") == "rekey_request":
            self.log("DEFENSE", "SERVER TRIGGERED ADAPTIVE KEY ROTATION! Performing immediate Rekeying...", Colors.YELLOW + Colors.BOLD)
            # Re-run key exchange
            if self.do_key_exchange():
                # Server invalidated previous session key. Let's re-authenticate implicitly if we had logged in!
                if self.username:
                    self.log("SECURE", f"Re-authenticating user '{self.username}' automatically with new rotated AES session key...", Colors.CYAN)
                    # Pre-hash password for demonstration logic:
                    # Let's send a silent auth request. Note: in this menu model we will let the next user command execute,
                    # but we can re-send the login. Let's do a quick login.
                    pass_hashes = {
                        "alice": "4e40e8ffe0ee32fa53e139147ed559229a5930f89c2204706fc174beb36210b3",
                        "bob": "bc786c379d8b4334faa1f5ed4428d53ed5fbf6247a5974a72eac7fd5c13410d8"
                    }
                    if self.username in pass_hashes:
                        self.encrypt_and_send({
                            "action": "login",
                            "username": self.username,
                            "password_hash": pass_hashes[self.username]
                        })
                        # Read response of this silent login
                        self.read_line() 
                return {"status": "rekeyed", "msg": "Session re-keyed successfully."}
            else:
                self.log("ERROR", "Adaptive re-keying failed.", Colors.RED)
                return None
                
        if resp.get("type") != "secure_packet":
            # Simple unencrypted responses (like errors or block notices)
            return resp
            
        # Standard Secure Packet
        iv_hex = resp.get("iv")
        cipher_hex = resp.get("ciphertext")
        nonce = resp.get("nonce")
        timestamp_str = resp.get("timestamp")
        packet_hmac = resp.get("hmac")
        
        # 1. Verify HMAC
        hmac_data = f"{iv_hex}{cipher_hex}{nonce}{timestamp_str}".encode('utf-8')
        computed_hmac = hmac_sha256_hex(self.aes_key, hmac_data)
        
        if computed_hmac != packet_hmac:
            self.log("ATTACK", "Warning: Received response packet from server has invalid HMAC signature! Possible MITM/Tampering.", Colors.RED)
            return {"status": "tampered", "msg": "Response HMAC integrity check failed."}
            
        # 2. Decrypt
        iv = bytes.fromhex(iv_hex)
        ciphertext = bytes.fromhex(cipher_hex)
        decrypted_bytes = aes_256_cbc_decrypt(ciphertext, self.aes_key, iv)
        return json.loads(decrypted_bytes.decode('utf-8'))

    # =====================================================================
    # DEMO ACTIONS / STEPS
    # =====================================================================

    def do_login(self, username, password):
        """Step 2: Client Login (SHA-256)."""
        if not self.aes_key:
            self.log("ERROR", "No active secure tunnel. Run key exchange first.", Colors.RED)
            return
            
        self.log("SECURE", f"Hashing password for user '{username}' using custom SHA-256 (no APIs)...", Colors.CYAN)
        pass_hash = sha256_hex(password.encode('utf-8'))
        self.log("CRYPTO", f"SHA-256 Digest: {pass_hash}", Colors.GREEN)
        
        payload = {
            "action": "login",
            "username": username,
            "password_hash": pass_hash
        }
        
        self.log("SECURE", f"Sending encrypted credentials to server via AES-256...", Colors.CYAN)
        self.encrypt_and_send(payload)
        
        resp = self.receive_and_decrypt()
        if not resp:
            self.log("ERROR", "No response from server.", Colors.RED)
            return
            
        if resp.get("status") == "success":
            self.authenticated = True
            self.username = username
            self.log("SECURE", f"Success! Server accepted credentials: {resp.get('msg')}", Colors.GREEN)
        else:
            self.log("DEFENSE", f"Failed! Server rejected credentials: {resp.get('msg')}", Colors.RED)

    def do_send_message(self, message):
        """Step 4: Secure Communication (AES-256-CBC)."""
        if not self.aes_key:
            self.log("ERROR", "Session key required.", Colors.RED)
            return
            
        payload = {
            "action": "chat",
            "message": message
        }
        
        self.log("CRYPTO", f"Encrypting message '{message}' with AES-256-CBC...", Colors.CYAN)
        self.encrypt_and_send(payload)
        
        resp = self.receive_and_decrypt()
        if resp:
            if resp.get("status") == "rekeyed":
                # Rekeyed occurred, retry sending message
                self.log("NETWORK", "Retrying message send with newly established AES key...", Colors.YELLOW)
                self.encrypt_and_send(payload)
                resp = self.receive_and_decrypt()
                
            if resp.get("status") == "success":
                self.log("SECURE", f"Server response decrypted successfully: {resp.get('msg')}", Colors.GREEN)
            else:
                self.log("ERROR", f"Server error: {resp.get('msg')}", Colors.RED)

    def do_get_classified_financials(self):
        """Simulates accessing confidential database files."""
        if not self.aes_key:
            self.log("ERROR", "Session key required.", Colors.RED)
            return None
            
        payload = {"action": "get_classified_financials"}
        self.log("SECURE", "Requesting classified financials from confidential database...", Colors.CYAN)
        self.encrypt_and_send(payload)
        
        resp = self.receive_and_decrypt()
        if not resp:
            return None
            
        if resp.get("status") == "success":
            filename = resp.get("filename", "classified_financials.pdf")
            pdf_b64 = resp.get("pdf_data", "")
            
            self.log("SECURE", f"SUCCESS! Received encrypted file: {filename}", Colors.GREEN)
            
            if pdf_b64:
                import base64
                try:
                    pdf_bytes = base64.b64decode(pdf_b64)
                    with open(filename, "wb") as f:
                        f.write(pdf_bytes)
                    self.log("SECURE", f"PDF file successfully saved locally to: {filename}", Colors.GREEN)
                except Exception as e:
                    self.log("ERROR", f"Failed to save PDF locally: {e}", Colors.RED)
            
            print(f"{Colors.BOLD}{Colors.PURPLE}=== FILE PREVIEW ===\n{resp.get('content')}\n===================={Colors.END}")
            
            if "honey_flag" in resp:
                print(f"{Colors.RED}{Colors.BOLD}⚠️ WARNING: Trap flag detected: {resp.get('honey_flag')} (Decoy Feeder Active!){Colors.END}")
            
            return resp
        else:
            self.log("DEFENSE", f"Access Denied: {resp.get('msg')}", Colors.RED)
            return resp

    def do_tamper_demo(self):
        """Simulates MITM packet modification (HMAC failure)."""
        if not self.aes_key:
            self.log("ERROR", "Key exchange required.", Colors.RED)
            return
            
        self.log("ATTACK", "Creating valid packet but intentionally tampering with its content...", Colors.YELLOW + Colors.BOLD)
        payload = {"action": "chat", "message": "Legitimate request."}
        
        # Generate the encrypted packet
        plain_bytes = json.dumps(payload).encode('utf-8')
        iv = bytes(random.getrandbits(8) for _ in range(16))
        ciphertext = aes_256_cbc_encrypt(plain_bytes, self.aes_key, iv)
        nonce = hex(random.getrandbits(64))
        timestamp = datetime.utcnow().isoformat()
        
        # Tampering ciphertext! Flip a byte!
        cipher_list = list(ciphertext)
        cipher_list[0] ^= 0xFF # Corrupt the first byte
        corrupted_ciphertext = bytes(cipher_list)
        
        # Calculate HMAC over correct variables but sending corrupted cipher!
        hmac_data = f"{iv.hex()}{corrupted_ciphertext.hex()}{nonce}{timestamp}".encode('utf-8')
        packet_hmac = hmac_sha256_hex(self.aes_key, hmac_data)
        
        # To simulate a signature mismatch, we can also just mess up the HMAC itself
        packet = {
            "type": "secure_packet",
            "iv": iv.hex(),
            "ciphertext": corrupted_ciphertext.hex(),
            "nonce": nonce,
            "timestamp": timestamp,
            "hmac": packet_hmac + "bad" # Modifies the HMAC string
        }
        
        self.log("ATTACK", "Sending tampered packet to server...", Colors.RED)
        self.send_line(packet)
        
        resp = self.read_line()
        if resp:
            self.log("DEFENSE", f"Server response: {resp.get('msg')} (Integrity breach protected!)", Colors.GREEN)

    # =====================================================================
    # PHASE 2: CYBERATTACKS EMULATOR
    # =====================================================================

    def run_brute_force(self):
        """Step 6: Brute Force Attack."""
        self.log("ATTACK", "Starting Automated Brute Force Password Cracking...", Colors.RED + Colors.BOLD)
        
        passwords = ["admin123", "password", "123456", "superman", "cyberdefense"]
        for p in passwords:
            self.log("ATTACK", f"Attempting login with password candidate: '{p}'", Colors.YELLOW)
            pass_hash = sha256_hex(p.encode('utf-8'))
            
            payload = {
                "action": "login",
                "username": "alice",
                "password_hash": pass_hash
            }
            
            self.encrypt_and_send(payload)
            resp = self.receive_and_decrypt()
            
            if resp:
                status = resp.get("status")
                msg = resp.get("msg")
                if status == "blocked":
                    self.log("DEFENSE", f"ALERT! Server blocked brute-force: {msg}", Colors.RED + Colors.BOLD)
                    break
                else:
                    self.log("DEFENSE", f"Rejected: {msg}", Colors.RED)
            time.sleep(1.0)

    def run_replay_attack(self):
        """Step 7: Replay Attack."""
        if not self.last_valid_packet:
            self.log("ERROR", "No saved packet to replay! Send a legitimate encrypted message first.", Colors.RED)
            return
            
        self.log("ATTACK", "Automating Replay Attack...", Colors.RED + Colors.BOLD)
        self.log("ATTACK", f"Replaying saved message packet (Nonce: {self.last_valid_packet.get('nonce')})...", Colors.YELLOW)
        
        # Send the exact same cached packet
        self.send_line(self.last_valid_packet)
        
        # Server response will be unencrypted block message or rejected block
        resp = self.read_line()
        if resp:
            self.log("DEFENSE", f"Server response: {resp.get('msg')} (Replay prevented successfully!)", Colors.GREEN + Colors.BOLD)

    def check_honeypot_trap(self):
        """Step 9: Honeypot / Fake Response Check."""
        self.log("ATTACK", "Probing Server environment for Honey Traps...", Colors.PURPLE + Colors.BOLD)
        
        # Attempting brute force login again to trigger honeypot level if already blocked
        self.log("ATTACK", "Sending probe login attempt to force intrusion state...", Colors.YELLOW)
        pass_hash = sha256_hex(b"any_bad_password")
        payload = {
            "action": "login",
            "username": "admin",
            "password_hash": pass_hash
        }
        self.encrypt_and_send(payload)
        
        resp = self.receive_and_decrypt()
        if resp and resp.get("status") == "success" and "session_token" in resp:
            # Server responded success despite incorrect credentials! Honeypot activated!
            self.log("HONEYPOT", "🔥 DANGER DETECTED: The server successfully logged us in with FAKE credentials!", Colors.RED + Colors.BOLD)
            self.log("HONEYPOT", f"Decoy Root Token Fed: {resp.get('session_token')}", Colors.PURPLE)
            
            # Request sensitive files
            self.log("HONEYPOT", "Probing file download to check decoy data...", Colors.YELLOW)
            self.do_get_classified_financials()
        else:
            self.log("INFO", "Server responded normally (Honeypot mode is currently inactive. Ensure Threat Level is raised to CRITICAL first).", Colors.GREEN)

# =====================================================================
# INTERACTIVE CLI SHELL
# =====================================================================

def print_banner():
    print(f"""
{Colors.CYAN}==================================================================
        ADAPTIVE CRYPTOSHIELD CLIENT & ATTACK EMULATOR
                  (Runtimes built from scratch)
=================================================================={Colors.END}""")

def show_menu():
    print(f"""
{Colors.GREEN}--- PHASE 1: FRIENDLY USER MODE ---{Colors.END}
  [1] Secure Key Exchange (RSA + AES)
  [2] User Login (SHA-256 Password Hash)
  [3] Send Encrypted Chat Message (AES-256-CBC + HMAC)
  [4] Download Confidential Data (Classified Financials)
  [5] Tamper Packet in Transit (MITM / HMAC Integrity Test)

{Colors.RED}--- PHASE 2: CYBERATTACK MODE ---{Colors.END}
  [6] Execute Brute-Force Password Attack (Step 6)
  [7] Execute Replay Attack (Step 7 - Resend Captured Packet)
  [8] Probe Decoy Environment (Step 9 - Honeypot Trapping Check)

{Colors.YELLOW}--- SYSTEM OPTIONS ---{Colors.END}
  [9] Disconnect & Exit CLI
""")

def main():
    print_banner()
    
    print(f"\n{Colors.GREEN}[*] Redirecting Interactive Client Control to browser-based Dashboard...{Colors.END}")
    print(f"{Colors.GREEN}[+] Real-time log streams & cryptographic telemetries are fully armed!{Colors.END}")
    
    print(f"\n{Colors.BOLD}{Colors.CYAN}👉 Click this link to open the Client Operations Dashboard:{Colors.END}")
    print(f"   {Colors.BOLD}{Colors.GREEN}http://localhost:8080/client{Colors.END}")
    
    print(f"\n{Colors.YELLOW}(Please ensure 'python server.py' is running in the background.){Colors.END}")
    
    try:
        input(f"\n{Colors.BOLD}Press Enter to exit...{Colors.END}")
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main()
