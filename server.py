#!/usr/bin/env python3
"""
server.py
Secure Server Engine with Adaptive Cryptanalysis Defense & HTTP Live Dashboard.
"""

import sys
if sys.platform.startswith('win'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        pass
import json
import socket
import threading
import time
import queue
import urllib.parse
import random
from datetime import datetime

from crypto_scratch import (
    sha256_hex, hmac_sha256, hmac_sha256_hex,
    aes_256_cbc_encrypt, aes_256_cbc_decrypt,
    generate_rsa_keys, rsa_decrypt
)

# Import client for in-process management (dashboard control)
from client import AdaptiveSecureClient

# User Database (Pre-hashed passwords using custom SHA-256)
# Password for "alice" is "alice123" -> SHA-256: 4e40e8ffe0ee32fa53e139147ed559229a5930f89c2204706fc174beb36210b3
# Password for "bob" is "bobpassword" -> SHA-256: bc786c379d8b4334faa1f5ed4428d53ed5fbf6247a5974a72eac7fd5c13410d8
USERS = {
    "alice": "4e40e8ffe0ee32fa53e139147ed559229a5930f89c2204706fc174beb36210b3",
    "bob": "bc786c379d8b4334faa1f5ed4428d53ed5fbf6247a5974a72eac7fd5c13410d8"
}

class AdaptiveSecureServer:
    def __init__(self, tcp_port=9999, http_port=8080):
        self.tcp_port = tcp_port
        self.http_port = http_port
        
        # Threat & Monitoring State
        self.threat_level = 0  # 0: SAFE, 1: ELEVATED, 2: HIGH, 3: CRITICAL (Honeypot)
        self.failed_logins = {}  # IP -> count
        self.blocked_ips = {}    # IP -> block_expiry_timestamp
        self.used_nonces = set()
        
        # Crypto keys
        print("[*] Generating Server RSA-1024 Keypair (scratch math)...")
        self.rsa_pub, self.rsa_priv = generate_rsa_keys(bits=1024)
        print("[+] RSA-1024 Keypair Generated Successfully.")
        
        # Active sessions: IP -> { "aes_key": bytes, "username": str, "rekey_count": int }
        self.sessions = {}
        
        # SSE Broadcasting (server dashboard)
        self.sse_listeners = []
        self.lock = threading.Lock()
        self.logs = []

        # ── Client Dashboard: SSE listeners + managed client state ────
        self.client_sse_listeners = []
        self.managed_client = None          # live AdaptiveSecureClient
        self.client_lock = threading.Lock()
        self.client_busy = False

        # Add initial logs
        self.log_event("SYSTEM", "Secure Server Engine initialized.", "info")
        self.log_event("CRYPTO", f"RSA-1024 Key Modulus N generated: {hex(self.rsa_pub[1])[:30]}...", "secure")
        self.log_event("CRYPTO", "RSA Public Exponent E: 65537", "secure")
        
    def log_event(self, category, message, level="info"):
        """Logs an event and broadcasts it to all SSE dashboard listeners."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        log_entry = {
            "timestamp": timestamp,
            "category": category,
            "message": message,
            "level": level,  # info, secure, warning, alarm, honeypot
            "threat_level": self.threat_level
        }
        with self.lock:
            self.logs.append(log_entry)
            # Keep logs limit to 100
            if len(self.logs) > 100:
                self.logs.pop(0)
                
        # Broadcast to dashboard
        self.broadcast_sse("log", log_entry)
        
    def broadcast_sse(self, event_type, data):
        """Sends real-time telemetry to the web dashboard."""
        payload = json.dumps({
            "event": event_type,
            "data": data,
            "threat_level": self.threat_level,
            "blocked_ips": {ip: float(exp - time.time()) for ip, exp in self.blocked_ips.items() if exp > time.time()}
        })
        with self.lock:
            active_listeners = []
            for q in self.sse_listeners:
                try:
                    q.put_nowait(payload)
                    active_listeners.append(q)
                except Exception:
                    pass
            self.sse_listeners = active_listeners

    def register_sse_listener(self, q):
        with self.lock:
            self.sse_listeners.append(q)
            
    def unregister_sse_listener(self, q):
        with self.lock:
            if q in self.sse_listeners:
                self.sse_listeners.remove(q)

    # ── Client Dashboard SSE helpers ──────────────────────────────────
    def register_client_sse(self, q):
        with self.client_lock:
            self.client_sse_listeners.append(q)

    def unregister_client_sse(self, q):
        with self.client_lock:
            if q in self.client_sse_listeners:
                self.client_sse_listeners.remove(q)

    def broadcast_client_msg(self, payload_dict):
        """Push a JSON message to all client-dashboard SSE listeners."""
        data = json.dumps(payload_dict)
        with self.client_lock:
            alive = []
            for q in self.client_sse_listeners:
                try:
                    q.put_nowait(data)
                    alive.append(q)
                except Exception:
                    pass
            self.client_sse_listeners = alive

    def client_log(self, tag, message, color_class='msg-info'):
        """Send a log line to the client dashboard SSE stream."""
        self.broadcast_client_msg({
            'type': 'log',
            'tag': tag,
            'message': message,
            'color_class': color_class
        })

    def client_status(self, **kwargs):
        """Push a status update to the client dashboard."""
        kwargs['type'] = 'status'
        self.broadcast_client_msg(kwargs)

    def client_result(self, status, label, content):
        """Push an operation result to the client dashboard result panel."""
        self.broadcast_client_msg({
            'type': 'result',
            'status': status,
            'label': label,
            'content': content
        })

    def _patch_client_logger(self, client):
        """Monkey-patch client.log() so output also streams to the dashboard."""
        server = self
        COLOR_MAP = {
            '\033[96m':  ('INFO',    'msg-info'),
            '\033[92m':  ('SECURE',  'msg-secure'),
            '\033[93m':  ('DEFENSE', 'msg-warning'),
            '\033[91m':  ('ATTACK',  'msg-alarm'),
            '\033[95m':  ('HONEYPOT','msg-honeypot'),
            '\033[1m':   ('INFO',    'msg-info'),
        }
        def patched_log(tag, message, color='\033[96m'):
            # Original stdout print (keep CLI working)
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            print(f"{color}[{timestamp}] [{tag}] {message}\033[0m")
            # Map color to CSS class
            _, css = COLOR_MAP.get(color, ('INFO', 'msg-info'))
            server.client_log(tag, message, css)
        client.log = patched_log

    def get_or_create_client(self):
        """Return the managed client, creating+connecting if needed."""
        if self.managed_client and self.managed_client.sock:
            return self.managed_client
        c = AdaptiveSecureClient(host='127.0.0.1', port=9999)
        self._patch_client_logger(c)
        if c.connect():
            self.managed_client = c
            self.client_status(
                connected=True,
                aes_key=None,
                username=None,
                last_op='connect',
                last_status='success'
            )
            return c
        else:
            self.client_log('ERROR', 'Could not connect to TCP server on port 9999.', 'msg-alarm')
            return None

    def run_client_action(self, body):
        """Execute a client operation in a background thread and stream output via SSE."""
        action = body.get('action', '')
        self.client_busy = True
        self.broadcast_client_msg({'type': 'busy', 'running': True})

        try:
            c = self.get_or_create_client()
            if c is None:
                self.client_log('ERROR', 'No active connection. Cannot execute action.', 'msg-alarm')
                return

            if action == 'key_exchange':
                ok = c.do_key_exchange()
                self.client_status(
                    aes_key=(c.aes_key.hex()[:16] + '...' if c.aes_key else None),
                    last_op='Key Exchange',
                    last_status='success' if ok else 'failed'
                )
                self.client_result(
                    'success' if ok else 'error',
                    'Key Exchange ' + ('✓ Complete' if ok else '✗ Failed'),
                    ('AES-256 Session Key established.\nKey (first 16 bytes): ' + c.aes_key.hex()[:32] + '...') if ok
                    else 'Key exchange failed. Check server connection.'
                )

            elif action == 'login':
                username = body.get('username', '')
                password = body.get('password', '')
                if not c.aes_key:
                    self.client_log('ERROR', 'Key exchange required before login!', 'msg-alarm')
                    self.client_result('error', 'Prerequisites Missing', 'Run [1] Key Exchange first.')
                    return
                c.do_login(username, password)
                self.client_status(
                    username=(c.username if c.authenticated else None),
                    last_op=f'Login ({username})',
                    last_status='success' if c.authenticated else 'failed'
                )
                self.client_result(
                    'success' if c.authenticated else 'error',
                    f'Login: {"Authenticated" if c.authenticated else "Rejected"}',
                    f'User: {username}\nStatus: {"Access granted" if c.authenticated else "Invalid credentials"}'
                )

            elif action == 'chat':
                message = body.get('message', 'Hello!')
                if not c.aes_key:
                    self.client_log('ERROR', 'Key exchange required before sending chat!', 'msg-alarm')
                    self.client_result('error', 'Prerequisites Missing', 'Run [1] Key Exchange first.')
                    return
                c.do_send_message(message)
                self.client_status(last_op='Send Chat', last_status='success')
                self.client_result(
                    'success', 'Chat Sent ✓',
                    f'Message: "{message}"\nEncrypted with AES-256-CBC + HMAC-SHA256'
                )

            elif action == 'financials':
                if not c.aes_key:
                    self.client_log('ERROR', 'Key exchange required first!', 'msg-alarm')
                    self.client_result('error', 'Prerequisites Missing', 'Run [1] Key Exchange first.')
                    return
                resp = c.do_get_classified_financials()
                if resp and resp.get("status") == "success":
                    pdf_data = resp.get("pdf_data", "")
                    filename = resp.get("filename", "classified_financials.pdf")
                    honey_flag = resp.get("honey_flag")
                    
                    self.client_status(last_op='Download Financials', last_status='success')
                    self.client_result(
                        'warn' if honey_flag else 'success',
                        f'Classified File Received: {filename} ✓',
                        f"__PDF_PAYLOAD__:{filename}:{pdf_data}"
                    )
                else:
                    self.client_status(last_op='Download Financials', last_status='failed')
                    self.client_result(
                        'error', 'Access Denied ✗',
                        resp.get("msg") if resp else 'No response from server.'
                    )

            elif action == 'tamper':
                if not c.aes_key:
                    self.client_log('ERROR', 'Key exchange required first!', 'msg-alarm')
                    self.client_result('error', 'Prerequisites Missing', 'Run [1] Key Exchange first.')
                    return
                c.do_tamper_demo()
                self.client_status(last_op='Tamper Demo', last_status='success')
                self.client_result(
                    'warn', 'Tamper Packet Sent ⚠',
                    'Packet intentionally corrupted (HMAC modified).\nServer should reject with integrity error.'
                )

            elif action == 'brute_force':
                if not c.aes_key:
                    self.client_log('ERROR', 'Key exchange required first!', 'msg-alarm')
                    self.client_result('error', 'Prerequisites Missing', 'Run [1] Key Exchange first.')
                    return
                c.run_brute_force()
                self.client_status(last_op='Brute-Force Attack', last_status='success')
                self.client_result(
                    'warn', 'Brute-Force Sequence Complete',
                    'Attempted: admin123, password, 123456, superman, cyberdefense\nServer should have blocked the IP after 3 attempts.'
                )

            elif action == 'replay':
                if not c.last_valid_packet:
                    self.client_log('ERROR', 'No saved packet to replay! Send a chat message first (Option 3).', 'msg-alarm')
                    self.client_result('error', 'No Packet Cached', 'Send a chat message first to capture a valid packet.')
                    return
                c.run_replay_attack()
                self.client_status(last_op='Replay Attack', last_status='success')
                self.client_result(
                    'warn', 'Replay Attack Fired ⚠',
                    f'Replayed nonce: {c.last_valid_packet.get("nonce", "n/a")}\nServer should have rejected with replay protection.'
                )

            elif action == 'honeypot':
                if not c.aes_key:
                    self.client_log('ERROR', 'Key exchange required first!', 'msg-alarm')
                    self.client_result('error', 'Prerequisites Missing', 'Run [1] Key Exchange first.')
                    return
                c.check_honeypot_trap()
                self.client_status(last_op='Honeypot Probe', last_status='success')
                self.client_result(
                    'warn', 'Honeypot Probe Complete 🕵️',
                    'Sent probe login with bad credentials.\nIf threat level is CRITICAL, server feeds decoy data.'
                )

            elif action == 'disconnect':
                if self.managed_client:
                    self.managed_client.close()
                    self.managed_client = None
                
                # Reset threat level to SAFE (0) and clear all active blocked IPs!
                self.blocked_ips.clear()
                self.failed_logins.clear()
                self.threat_level = 0
                self.log_event("SYSTEM", "Client session reset requested. Clearing active IP blocks and resetting threat level to SAFE (0).", "info")
                self.broadcast_sse("threat_change", {"threat_level": 0})
                
                self.client_status(
                    connected=False, aes_key=None,
                    username=None, last_op='Disconnect', last_status='success'
                )
                self.client_result('warn', 'Disconnected & Reset', 'Session closed. Threat level reset to SAFE (0) and active IP blocks cleared!')

            else:
                self.client_log('ERROR', f'Unknown action: {action}', 'msg-alarm')

        except Exception as ex:
            import traceback
            tb = traceback.format_exc()
            self.client_log('ERROR', f'Action error: {ex}', 'msg-alarm')
            self.client_result('error', 'Unhandled Error', str(ex))
            print(tb)
        finally:
            self.client_busy = False
            self.broadcast_client_msg({'type': 'busy', 'running': False})

    def check_ip_blocked(self, ip):
        """Checks if an IP is currently blocked, handles expiry."""
        if ip in self.blocked_ips:
            expiry = self.blocked_ips[ip]
            if time.time() < expiry:
                return True
            else:
                # Block expired, unblock IP and drop threat level
                del self.blocked_ips[ip]
                self.failed_logins[ip] = 0
                self.log_event("DEFENSE", f"Block expired for IP {ip}. IP unblocked.", "info")
                self.adjust_threat_level(-1)
        return False
        
    def adjust_threat_level(self, delta):
        """Updates threat level and broadcasts update to dashboard."""
        old = self.threat_level
        self.threat_level = max(0, min(3, self.threat_level + delta))
        if self.threat_level != old:
            level_names = ["SAFE (Green)", "ELEVATED (Yellow)", "HIGH (Orange)", "CRITICAL/HONEYPOT (Red)"]
            self.log_event(
                "DEFENSE", 
                f"Threat level transitioned from {level_names[old]} to {level_names[self.threat_level]}.",
                "warning" if self.threat_level > old else "info"
            )
            self.broadcast_sse("threat_change", {"threat_level": self.threat_level})

    def handle_client_tcp(self, conn, addr):
        ip = addr[0]
        self.log_event("NETWORK", f"New TCP connection established from client at {ip}.", "info")
        
        session_aes_key = None
        username = None
        rekey_count = 0
        
        try:
            while True:
                # Read line-delimited JSON
                data = conn.readline()
                if not data:
                    break
                
                # Check block status before parsing
                if self.check_ip_blocked(ip):
                    # Attacker is hammering a blocked IP
                    self.adjust_threat_level(1)  # Escalates to CRITICAL
                    self.log_event("ATTACK", f"Blocked IP {ip} attempted transmission. Escalating threat.", "alarm")
                    
                    if self.threat_level == 3:
                        # Try to decrypt and serve action-specific honeypot reply
                        try:
                            req = json.loads(data.decode('utf-8').strip())
                            if req.get("type") == "secure_packet" and session_aes_key:
                                iv = bytes.fromhex(req.get("iv"))
                                ciphertext = bytes.fromhex(req.get("ciphertext"))
                                decrypted_bytes = aes_256_cbc_decrypt(ciphertext, session_aes_key, iv)
                                decrypted_payload = json.loads(decrypted_bytes.decode('utf-8'))
                                action = decrypted_payload.get("action")
                                
                                # Feed encrypted custom decoy response
                                fake_reply = self.get_honeypot_fake_reply(action, decrypted_payload)
                                fake_reply_enc = self.encrypt_payload(fake_reply, session_aes_key)
                                conn.write(json.dumps(fake_reply_enc).encode('utf-8') + b'\n')
                                conn.flush()
                                continue
                        except Exception:
                            pass
                            
                        # Fallback to generic unencrypted decoy response
                        fake_reply = self.get_honeypot_fake_reply("ATTACK_HAMMER")
                        conn.write(json.dumps(fake_reply).encode('utf-8') + b'\n')
                        conn.flush()
                        continue
                    else:
                        conn.write(json.dumps({"status": "blocked", "msg": "Your IP is temporarily blocked."}).encode('utf-8') + b'\n')
                        conn.flush()
                        continue
                
                # Try loading the request JSON
                try:
                    req = json.loads(data.decode('utf-8').strip())
                except Exception:
                    self.log_event("NETWORK", f"Malformed payload from {ip}.", "warning")
                    conn.write(json.dumps({"status": "error", "msg": "Invalid JSON"}).encode('utf-8') + b'\n')
                    conn.flush()
                    continue
                
                req_type = req.get("type")
                
                # Step 1 & 3: RSA Key Handshake
                if req_type == "handshake_start":
                    self.log_event("SECURE", f"Client at {ip} initiated handshake. Sending RSA-1024 public key.", "secure")
                    # Send public key
                    resp = {
                        "type": "rsa_pub",
                        "e": hex(self.rsa_pub[0]),
                        "n": hex(self.rsa_pub[1])
                    }
                    self.broadcast_sse("packet", {
                        "direction": "Server ➔ Client",
                        "type": "RSA Key Handshake",
                        "summary": "Sending Server RSA-1024 Public Key",
                        "detail": f"E: {resp['e'][:10]}..., N: {resp['n'][:20]}...",
                        "status": "passed"
                    })
                    conn.write(json.dumps(resp).encode('utf-8') + b'\n')
                    conn.flush()
                    continue
                    
                elif req_type == "aes_key_exchange":
                    enc_key_hex = req.get("encrypted_key")
                    self.log_event("CRYPTO", "Received encrypted AES session key from client.", "secure")
                    
                    try:
                        enc_key_bytes = bytes.fromhex(enc_key_hex)
                        decrypted_key = rsa_decrypt(enc_key_bytes, self.rsa_priv)
                        # Ensure exactly 32 bytes
                        if len(decrypted_key) > 32:
                            decrypted_key = decrypted_key[-32:]
                        elif len(decrypted_key) < 32:
                            decrypted_key = decrypted_key.rjust(32, b'\x00')
                            
                        session_aes_key = decrypted_key
                        self.sessions[ip] = {
                            "aes_key": session_aes_key,
                            "username": None,
                            "rekey_count": rekey_count
                        }
                        
                        self.log_event("CRYPTO", f"AES-256 Session Key successfully decrypted and established: {session_aes_key.hex()[:16]}...", "secure")
                        
                        # Send confirmation message encrypted with AES
                        confirm_iv = bytes(random.getrandbits(8) for _ in range(16))
                        confirm_plain = b"KEY_EXCHANGE_VERIFIED"
                        confirm_cipher = aes_256_cbc_encrypt(confirm_plain, session_aes_key, confirm_iv)
                        
                        resp = {
                            "type": "aes_confirm",
                            "iv": confirm_iv.hex(),
                            "ciphertext": confirm_cipher.hex()
                        }
                        
                        self.broadcast_sse("packet", {
                            "direction": "Client ➔ Server",
                            "type": "AES Key Exchange",
                            "summary": "Received encrypted AES key",
                            "detail": f"Decrypted AES Key: {session_aes_key.hex()[:16]}...",
                            "status": "passed"
                        })
                        conn.write(json.dumps(resp).encode('utf-8') + b'\n')
                        conn.flush()
                        
                    except Exception as e:
                        self.log_event("CRYPTO", f"RSA Decryption of Session Key failed: {e}", "warning")
                        conn.write(json.dumps({"status": "error", "msg": "Key exchange decryption failed"}).encode('utf-8') + b'\n')
                        conn.flush()
                    continue
                
                # Check for AES Key setup before handling encrypted packets
                if session_aes_key is None:
                    self.log_event("SECURE", f"Client at {ip} attempted communication without exchanging AES keys.", "warning")
                    conn.write(json.dumps({"status": "error", "msg": "Key exchange required first."}).encode('utf-8') + b'\n')
                    conn.flush()
                    continue
                
                # Decrypted packet handling (Step 4 & 5)
                if req_type == "secure_packet":
                    iv_hex = req.get("iv")
                    cipher_hex = req.get("ciphertext")
                    nonce = req.get("nonce")
                    timestamp_str = req.get("timestamp")
                    packet_hmac = req.get("hmac")
                    
                    # 1. TAMPERING CHECK (HMAC Verification)
                    # HMAC computed over (iv + ciphertext + nonce + timestamp)
                    hmac_data = f"{iv_hex}{cipher_hex}{nonce}{timestamp_str}".encode('utf-8')
                    computed_hmac = hmac_sha256_hex(session_aes_key, hmac_data)
                    
                    if computed_hmac != packet_hmac:
                        # HMAC Mismatch -> Packet Tampering Detected!
                        self.adjust_threat_level(1)
                        self.log_event("ATTACK", f"HMAC validation failed from {ip}! Packet compromised/tampered in transit.", "alarm")
                        self.broadcast_sse("packet", {
                            "direction": "Client ➔ Server",
                            "type": "Secure Payload",
                            "summary": "TAMPERED PACKET REJECTED",
                            "detail": f"Given HMAC: {packet_hmac[:10]}... Computed: {computed_hmac[:10]}...",
                            "status": "tampered"
                        })
                        
                        conn.write(json.dumps({"status": "tampered", "msg": "Packet integrity check failed."}).encode('utf-8') + b'\n')
                        conn.flush()
                        continue
                        
                    # 2. REPLAY ATTACK CHECK (Nonce & Timestamp Verification)
                    # First check Timestamp expiry (older than 15s)
                    try:
                        packet_time = datetime.fromisoformat(timestamp_str)
                        time_diff = abs((datetime.utcnow() - packet_time).total_seconds())
                    except Exception:
                        time_diff = 999.0
                        
                    if time_diff > 15.0:
                        # Replay or Expired Packet
                        self.adjust_threat_level(1)
                        self.log_event("ATTACK", f"Replay/Timeout protection triggered from {ip}! Time drift: {time_diff:.1f}s", "alarm")
                        self.broadcast_sse("packet", {
                            "direction": "Client ➔ Server",
                            "type": "Secure Payload",
                            "summary": "EXPIRED PACKET BLOCKED",
                            "detail": f"Timestamp drift {time_diff:.1f}s exceeding 15s window.",
                            "status": "replay"
                        })
                        conn.write(json.dumps({"status": "expired", "msg": "Packet timestamp expired (Replay protection)."}).encode('utf-8') + b'\n')
                        conn.flush()
                        continue
                        
                    # Check Nonce reuse
                    if nonce in self.used_nonces:
                        # Replay Attack! Same nonce reused
                        self.adjust_threat_level(1)
                        # Elevate to High immediately and block IP
                        self.blocked_ips[ip] = time.time() + 30.0
                        self.adjust_threat_level(1)
                        self.log_event("ATTACK", f"REPLAY ATTACK DETECTED from {ip}! Nonce {nonce} reused. IP blocked.", "alarm")
                        
                        self.broadcast_sse("packet", {
                            "direction": "Client ➔ Server",
                            "type": "Secure Payload",
                            "summary": "REPLAY ATTACK DETECTED",
                            "detail": f"Reused Nonce: {nonce} - IP BLOCKED for 30s.",
                            "status": "replay"
                        })
                        
                        if self.threat_level == 3:
                            fake_reply = self.get_honeypot_fake_reply("REPLAY_ATTACK")
                            conn.write(json.dumps(fake_reply).encode('utf-8') + b'\n')
                        else:
                            conn.write(json.dumps({"status": "blocked", "msg": "Replay attack detected. IP Blocked."}).encode('utf-8') + b'\n')
                        conn.flush()
                        continue
                        
                    self.used_nonces.add(nonce)
                    
                    # Decrypt cipher
                    try:
                        iv = bytes.fromhex(iv_hex)
                        ciphertext = bytes.fromhex(cipher_hex)
                        decrypted_bytes = aes_256_cbc_decrypt(ciphertext, session_aes_key, iv)
                        decrypted_payload = json.loads(decrypted_bytes.decode('utf-8'))
                    except Exception as e:
                        self.log_event("CRYPTO", f"AES Decryption error: {e}", "warning")
                        conn.write(json.dumps({"status": "error", "msg": "Decryption error."}).encode('utf-8') + b'\n')
                        conn.flush()
                        continue
                        
                    # Successfully parsed decrypted message!
                    action = decrypted_payload.get("action")
                    
                    # Log packet telemetry to dashboard
                    self.broadcast_sse("packet", {
                        "direction": "Client ➔ Server",
                        "type": "Secure Payload",
                        "summary": f"Decrypted Action: '{action}'",
                        "detail": f"Decrypted: {json.dumps(decrypted_payload)[:60]}...",
                        "status": "passed"
                    })
                    
                    # Check Honeypot mode triggers
                    if self.threat_level == 3:
                        # Feed decoy honeypot response
                        self.log_event("HONEYPOT", f"Feeding fake results to attacker {ip} for action '{action}'.", "honeypot")
                        fake_reply = self.get_honeypot_fake_reply(action, decrypted_payload)
                        # Encrypt fake reply using current key to make attacker think it's authentic!
                        fake_reply_enc = self.encrypt_payload(fake_reply, session_aes_key)
                        conn.write(json.dumps(fake_reply_enc).encode('utf-8') + b'\n')
                        conn.flush()
                        continue
                    
                    # Handle Decrypted Actions
                    if action == "login":
                        attempt_user = decrypted_payload.get("username")
                        pass_hash = decrypted_payload.get("password_hash")
                        
                        if attempt_user in USERS and USERS[attempt_user] == pass_hash:
                            username = attempt_user
                            self.sessions[ip]["username"] = username
                            self.log_event("SECURE", f"Client '{username}' successfully authenticated from {ip}.", "secure")
                            
                            reply = {"status": "success", "msg": f"Welcome, {username}! Access authorized."}
                            conn.write(json.dumps(self.encrypt_payload(reply, session_aes_key)).encode('utf-8') + b'\n')
                            conn.flush()
                        else:
                            # Auth failed!
                            self.failed_logins[ip] = self.failed_logins.get(ip, 0) + 1
                            count = self.failed_logins[ip]
                            self.log_event("DEFENSE", f"Failed login attempt from {ip} for '{attempt_user}' ({count}/3).", "warning")
                            
                            if count >= 3:
                                # Block IP
                                self.blocked_ips[ip] = time.time() + 30.0
                                self.adjust_threat_level(1)  # Raises threat level
                                self.log_event("DEFENSE", f"BRUTE FORCE DETECTED from {ip}! Blocking IP for 30s.", "alarm")
                                reply = {"status": "blocked", "msg": "Too many failed logins. Your IP is blocked for 30s."}
                            else:
                                if self.threat_level == 0:
                                    self.adjust_threat_level(1) # Elevated
                                reply = {"status": "failed", "msg": "Invalid credentials."}
                                
                            conn.write(json.dumps(self.encrypt_payload(reply, session_aes_key)).encode('utf-8') + b'\n')
                            conn.flush()
                            
                    elif action == "chat":
                        chat_msg = decrypted_payload.get("message")
                        self.log_event("CHAT", f"[{username or 'ANONYMOUS'}] {chat_msg}", "info")
                        
                        # Increment message counter for adaptive rekeying
                        rekey_count += 1
                        self.sessions[ip]["rekey_count"] = rekey_count
                        
                        # Trigger Adaptive re-keying after every 5 messages
                        if rekey_count >= 5:
                            self.log_event("DEFENSE", f"Adaptive rekeying limit reached for {ip}. Invalidating session key & triggering rotating key exchange.", "secure")
                            rekey_count = 0
                            self.sessions[ip]["rekey_count"] = 0
                            
                            # Send rekey request (unencrypted trigger, client must establish a new key)
                            rekey_trigger = {"type": "rekey_request", "msg": "Session key rotation requested."}
                            conn.write(json.dumps(rekey_trigger).encode('utf-8') + b'\n')
                            conn.flush()
                            session_aes_key = None  # Key is now invalidated, client must reconnect handshake
                            continue
                            
                        reply = {"status": "success", "msg": f"Server received your message: '{chat_msg}'."}
                        conn.write(json.dumps(self.encrypt_payload(reply, session_aes_key)).encode('utf-8') + b'\n')
                        conn.flush()
                        
                    elif action == "get_classified_financials":
                        if username:
                            self.log_event("SECURE", f"User '{username}' accessed classified financials.", "secure")
                            
                            pdf_lines = [
                                b"CRYPTOSHIELD SECURE DATA TRANSMISSION",
                                b"=====================================",
                                b"CLASSIFIED FINANCIAL RECORDS - CONFIDENTIAL",
                                b"Authorized Access granted to: " + username.encode('utf-8'),
                                b"",
                                b"Date        Revenue     Expense    Net Profit",
                                b"---------------------------------------------",
                                b"2026-Q1    $155,000    $112,000      $43,000",
                                b"2026-Q2    $189,000    $130,000      $59,000",
                                b"2026-Q3    $204,000    $145,000      $59,000",
                                b"---------------------------------------------",
                                b"Total      $548,000    $387,000     $161,000",
                                b"",
                                b"Verification Signature (HMAC-SHA256): Verified",
                                b"Security Protocol: AES-256-CBC Encrypted",
                            ]
                            pdf_bytes = self.generate_pdf_from_scratch(pdf_lines)
                            import base64
                            pdf_base64 = base64.b64encode(pdf_bytes).decode('ascii')
                            
                            reply = {
                                "status": "success",
                                "filename": "classified_financials.pdf",
                                "pdf_data": pdf_base64,
                                "content": "Date,Revenue,Expense\n2026-Q1,$155,000,$112,000\n2026-Q2,$189,000,$130,000\n2026-Q3,$204,000,$145,000\nTotal,$548,000,$387,000\nNetProfit,$161,000"
                            }
                        else:
                            reply = {"status": "failed", "msg": "Authentication required for this operation."}
                            
                        conn.write(json.dumps(self.encrypt_payload(reply, session_aes_key)).encode('utf-8') + b'\n')
                        conn.flush()
                        
                    else:
                        reply = {"status": "error", "msg": f"Unknown action: {action}"}
                        conn.write(json.dumps(self.encrypt_payload(reply, session_aes_key)).encode('utf-8') + b'\n')
                        conn.flush()
                        
        except ConnectionResetError:
            self.log_event("NETWORK", f"Client {ip} disconnected abruptly.", "warning")
        except Exception as e:
            self.log_event("SYSTEM", f"Error handling TCP client {ip}: {e}", "warning")
            import traceback
            traceback.print_exc()
        finally:
            conn.close()
            if ip in self.sessions:
                del self.sessions[ip]
            self.log_event("NETWORK", f"TCP socket closed for {ip}.", "info")

    def generate_pdf_from_scratch(self, text_lines):
        """
        Generates a structurally valid PDF byte stream from scratch
        with standard Courier font and mathematically accurate cross-reference tables.
        """
        objects = []
        # 1. Catalog
        objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
        # 2. Pages list
        objects.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        
        # Build text stream
        stream_content = b"BT\n/F1 12 Tf\n16 TL\n50 720 Td\n"
        for line in text_lines:
            escaped = line.replace(b"(", b"\\(").replace(b")", b"\\)")
            stream_content += b"(" + escaped + b") Tj T*\n"
        stream_content += b"ET"
        
        # 3. Page definition
        objects.append(b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /MediaBox [0 0 612 792] /Contents 5 0 R >>")
        # 4. Font definition
        objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")
        # 5. Stream content definition
        objects.append(b"<< /Length " + str(len(stream_content)).encode('ascii') + b" >>\nstream\n" + stream_content + b"\nendstream")
        
        pdf = bytearray(b"%PDF-1.4\n")
        offsets = []
        
        for idx, obj in enumerate(objects, start=1):
            offsets.append(len(pdf))
            pdf.extend(f"{idx} 0 obj\n".encode('ascii'))
            pdf.extend(obj)
            pdf.extend(b"\nendobj\n")
            
        xref_pos = len(pdf)
        pdf.extend(b"xref\n")
        pdf.extend(f"0 {len(objects) + 1}\n".encode('ascii'))
        pdf.extend(b"0000000000 65535 f \n")
        for offset in offsets:
            pdf.extend(f"{offset:010d} 00000 n \n".encode('ascii'))
            
        pdf.extend(b"trailer\n")
        pdf.extend(f"<< /Size {len(objects) + 1} /Root 1 0 R >>\n".encode('ascii'))
        pdf.extend(b"startxref\n")
        pdf.extend(f"{xref_pos}\n".encode('ascii'))
        pdf.extend(b"%%EOF\n")
        
        return bytes(pdf)

    def encrypt_payload(self, data_dict, aes_key):
        """Helper to package and encrypt a payload into standard secure_packet JSON."""
        iv = bytes(random.getrandbits(8) for _ in range(16))
        plain_bytes = json.dumps(data_dict).encode('utf-8')
        cipher = aes_256_cbc_encrypt(plain_bytes, aes_key, iv)
        
        nonce = hex(random.getrandbits(64))
        timestamp = datetime.utcnow().isoformat()
        
        # Calculate HMAC
        hmac_data = f"{iv.hex()}{cipher.hex()}{nonce}{timestamp}".encode('utf-8')
        packet_hmac = hmac_sha256_hex(aes_key, hmac_data)
        
        return {
            "type": "secure_packet",
            "iv": iv.hex(),
            "ciphertext": cipher.hex(),
            "nonce": nonce,
            "timestamp": timestamp,
            "hmac": packet_hmac
        }

    def get_honeypot_fake_reply(self, action, decrypted_payload=None):
        """Generates decoy/fake successful results for Step 9 (Honeypot/Fake Response System)."""
        self.log_event("HONEYPOT", "Feeding decoy success telemetry to isolate attacker activity.", "honeypot")
        
        if action == "login":
            return {
                "status": "success",
                "msg": "Welcome, Administrator! Access granted to root environment.",
                "session_token": "DECOY_ROOT_AUTH_TOKEN_99812739182379A",
                "system_node": "CORE-SERVER-NODE-1",
                "classified_databases": ["customer_passwords", "financial_records"]
            }
        elif action == "get_classified_financials" or "classified" in str(decrypted_payload):
            decoy_lines = [
                b"WARNING: DECOY FEEDER ACTIVE - ACTIVE HONEYPOT ALERT",
                b"====================================================",
                b"UNAUTHORIZED INTRUSION DETECTED",
                b"SYSTEM LEVEL ALERT: HIGH/CRITICAL SEVERITY TRAP",
                b"",
                b"CLASSIFIED ROOT FINANCIAL TELEMETRY (DECOY):",
                b"---------------------------------------------",
                b"Node ID: CORE-SERVER-NODE-1",
                b"Session Token: DECOY_ROOT_AUTH_TOKEN_99812739182379A",
                b"Honeypot Flag: FLAG{YOU_HAVE_BEEN_TRAPPED_BY_CYBER_SHIELD_HONEYPOT}",
                b"",
                b"Intruder Telemetry Logged Successfully.",
                b"All actions are monitored and reported to Cyber Ops.",
            ]
            pdf_bytes = self.generate_pdf_from_scratch(decoy_lines)
            import base64
            pdf_base64 = base64.b64encode(pdf_bytes).decode('ascii')
            return {
                "status": "success",
                "filename": "decoy_financials.pdf",
                "pdf_data": pdf_base64,
                "content": "Date,Revenue,Expense\n2026-Q1,$15,482,900,$12,883,000\nTotal,$59,193,100,$44,914,200\n(DECOY FINANCIAL RECORDS - ACTIVE MONITORING TRAP)",
                "honey_flag": "FLAG{YOU_HAVE_BEEN_TRAPPED_BY_CYBER_SHIELD_HONEYPOT}"
            }
        else:
            # Default decoy chat response
            return {
                "status": "success",
                "msg": "Decoy secure server accepted execution payload.",
                "honeypot_active": True,
                "decoy_id": f"TRAP_{random.randint(1000, 9999)}"
            }

# =====================================================================
# HTTP AND SSE SERVER IMPLEMENTATION
# =====================================================================

import http.server
import socketserver

def make_http_handler_class(server_instance):
    class TelemetryHTTPHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            # Suppress normal HTTP access logs on terminal to keep it clean
            pass
            
        def do_GET(self):
            parsed_path = urllib.parse.urlparse(self.path)
            
            # SSE Endpoint
            if parsed_path.path == "/events":
                self.send_response(200)
                self.send_header('Content-Type', 'text/event-stream')
                self.send_header('Cache-Control', 'no-cache')
                self.send_header('Connection', 'keep-alive')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                
                q = queue.Queue()
                server_instance.register_sse_listener(q)
                
                # Send history logs first
                with server_instance.lock:
                    for log in server_instance.logs:
                        init_payload = json.dumps({
                            "event": "log",
                            "data": log,
                            "threat_level": server_instance.threat_level,
                            "blocked_ips": {ip: float(exp - time.time()) for ip, exp in server_instance.blocked_ips.items() if exp > time.time()}
                        })
                        try:
                            self.wfile.write(f"data: {init_payload}\n\n".encode('utf-8'))
                        except Exception:
                            pass
                    self.wfile.flush()
                
                try:
                    while True:
                        try:
                            # Check every 5 seconds to send keepalive or push events
                            event_data = q.get(timeout=5.0)
                            self.wfile.write(f"data: {event_data}\n\n".encode('utf-8'))
                            self.wfile.flush()
                        except queue.Empty:
                            # Keep alive ping to check if client disconnected
                            self.wfile.write(b": ping\n\n")
                            self.wfile.flush()
                except (ConnectionError, BrokenPipeError, socket.error):
                    pass
                finally:
                    server_instance.unregister_sse_listener(q)
                return
                
            # Serves Server Dashboard HTML
            if parsed_path.path in ["/", "/index.html", "/dashboard"]:
                try:
                    with open("dashboard.html", "r", encoding="utf-8") as f:
                        content = f.read()
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(content.encode('utf-8'))
                except FileNotFoundError:
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b"dashboard.html not found.")
                return

            # Serves Client Dashboard HTML
            if parsed_path.path in ["/client", "/client.html", "/client-dashboard"]:
                try:
                    with open("client_dashboard.html", "r", encoding="utf-8") as f:
                        content = f.read()
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(content.encode('utf-8'))
                except FileNotFoundError:
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b"client_dashboard.html not found.")
                return

            # Client SSE Event Stream
            if parsed_path.path == "/client-events":
                self.send_response(200)
                self.send_header('Content-Type', 'text/event-stream')
                self.send_header('Cache-Control', 'no-cache')
                self.send_header('Connection', 'keep-alive')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()

                q = queue.Queue()
                server_instance.register_client_sse(q)

                # Send current client state immediately on connect
                c = server_instance.managed_client
                init_status = json.dumps({
                    'type': 'status',
                    'connected': bool(c and c.sock),
                    'aes_key': (c.aes_key.hex()[:16] + '...' if c and c.aes_key else None),
                    'username': (c.username if c and c.authenticated else None),
                    'last_op': '—',
                    'last_status': '—'
                })
                try:
                    self.wfile.write(f"data: {init_status}\n\n".encode('utf-8'))
                    self.wfile.flush()
                except Exception:
                    server_instance.unregister_client_sse(q)
                    return

                try:
                    while True:
                        try:
                            event_data = q.get(timeout=5.0)
                            self.wfile.write(f"data: {event_data}\n\n".encode('utf-8'))
                            self.wfile.flush()
                        except queue.Empty:
                            self.wfile.write(b": ping\n\n")
                            self.wfile.flush()
                except (ConnectionError, BrokenPipeError, socket.error):
                    pass
                finally:
                    server_instance.unregister_client_sse(q)
                return

            # Default 404
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

        def do_OPTIONS(self):
            self.send_response(200)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type')
            self.end_headers()

        def do_POST(self):
            parsed_path = urllib.parse.urlparse(self.path)

            # Client Action Endpoint
            if parsed_path.path == "/client-action":
                # CORS preflight handled implicitly; read body
                content_length = int(self.headers.get('Content-Length', 0))
                body_bytes = self.rfile.read(content_length) if content_length else b'{}'
                try:
                    body = json.loads(body_bytes.decode('utf-8'))
                except Exception:
                    body = {}

                if server_instance.client_busy:
                    resp = json.dumps({'error': 'Client is busy. Please wait.'}).encode('utf-8')
                    self.send_response(429)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.send_header('Content-Length', str(len(resp)))
                    self.end_headers()
                    self.wfile.write(resp)
                    return

                # Run action in background thread to avoid blocking HTTP
                t = threading.Thread(
                    target=server_instance.run_client_action,
                    args=(body,),
                    daemon=True
                )
                t.start()

                resp = json.dumps({'status': 'accepted', 'action': body.get('action')}).encode('utf-8')
                self.send_response(202)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Content-Length', str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)
                return

            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")
            
    return TelemetryHTTPHandler

class ThreadedTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

def run_tcp_server(server_instance):
    # Setup raw TCP listening socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(('0.0.0.0', server_instance.tcp_port))
        s.listen(10)
        print(f"[+] TCP Secure Socket Server listening on 0.0.0.0:{server_instance.tcp_port}")
        server_instance.log_event("SYSTEM", f"TCP Socket Server successfully listening on port {server_instance.tcp_port}.", "info")
    except Exception as e:
        print(f"[-] TCP bind failed: {e}")
        sys.exit(1)
        
    while True:
        try:
            conn, addr = s.accept()
            # Wrap in line-oriented file object
            # socket.makefile permits readline() usage over socket stream
            rfile = conn.makefile('rwb', buffering=0)
            t = threading.Thread(target=server_instance.handle_client_tcp, args=(rfile, addr), daemon=True)
            t.start()
        except Exception as e:
            print(f"[-] TCP accept exception: {e}")

def run_http_server(server_instance):
    handler_class = make_http_handler_class(server_instance)
    try:
        httpd = ThreadedTCPServer(('0.0.0.0', server_instance.http_port), handler_class)
        print(f"[+] Web Dashboard Server running at http://localhost:{server_instance.http_port}/")
        server_instance.log_event("SYSTEM", f"Web Dashboard Server running at http://localhost:{server_instance.http_port}/", "info")
        httpd.serve_forever()
    except Exception as e:
        print(f"[-] HTTP bind failed: {e}")
        sys.exit(1)

def main():
    print("==========================================================")
    print("   ADAPTIVE SECURE SERVER WITH LIVE CRYPTANALYSIS DEFENSE ")
    print("==========================================================")
    
    server = AdaptiveSecureServer(tcp_port=9999, http_port=8080)
    
    # Run TCP Server thread
    tcp_thread = threading.Thread(target=run_tcp_server, args=(server,), daemon=True)
    tcp_thread.start()
    
    # Run HTTP Server (blocks, main thread)
    run_http_server(server)

if __name__ == "__main__":
    main()
