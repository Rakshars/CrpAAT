## 2.1 Implementation Steps

The system architecture is structured as a zero-dependency secure cryptosystem and active threat-mitigation platform. The core cryptographic primitives, asymmetric handshakes, symmetric encryption tunnels, integrity checks, and defense state machines are implemented from mathematical first principles (without standard libraries like `cryptography`, `PyCrypto`, or `OpenSSL`). 

The implementation is organized into ten sequential steps, grouped across two primary operational phases: **Phase 1: Secure Communication (Friendly Mode)** and **Phase 2: Cyberattack Emulation and Defense**.

---

### Phase 1: Secure Communication (Friendly Mode)

```
[Server Init] ---> [RSA Key Gen] ---> [Socket Listen]
                                            |
[Secure Client] <--- [Handshake Init] <-----+
      |
      +---> [AES Session Key Gen] ---> [RSA Encrypted Exchange] ---> [Tunnel Established]
```

#### Step 1 — Server Initialization and RSA Key Generation
The backend engine (`server.py`) initializes the security boundary by generating a custom 1024-bit RSA keypair.
* **Primality Generation (`generate_prime`):** The system generates two large 512-bit prime numbers, $p$ and $q$, using a custom prime generator. Candidate odd integers are subjected to the **Miller-Rabin Primality Test** configured with $30$ independent verification rounds to guarantee a negligible false-positive probability ($< 4^{-30}$).
* **Keypair Calculation:** 
  * The RSA modulus is computed as $n = p \times q$.
  * Euler's totient is computed as $\phi(n) = (p-1) \times (q-1)$.
  * The public exponent is fixed at $e = 65537$ (Fermat prime $F_4$) due to its efficiency and co-primality.
  * The private key $d$ is derived as the modular multiplicative inverse of $e$ modulo $\phi(n)$, calculated via the **Extended Euclidean Algorithm**:
    $$d \equiv e^{-1} \pmod{\phi(n)}$$
* **Network & Multi-threading Architecture:** 
  * The server binds a TCP socket on port `9999` to handle raw encrypted client communications.
  * Concurrently, a threaded HTTP socket server is bound to port `8080` to host the telemetry and client control dashboards.
  * Multi-threading is implemented via the `threading` library, spawning a persistent worker thread for incoming TCP socket connections and a dedicated main-loop thread for non-blocking HTTP dashboard requests.

#### Step 2 — Client Authentication (Password Hashing)
Authentication is verified securely without transmitting plaintext passwords over the wire or storing them in plain text.
* **Custom SHA-256 Hashing Engine:** The client hashes the password candidate using a pure Python implementation of the **SHA-256** compression algorithm. The engine processes inputs in 512-bit message blocks, applying the standard $64$-round compression function utilizing bitwise logical operations (Ch, Maj, $\Sigma_0, \Sigma_1, \sigma_0, \sigma_1$) and fractional part constant initializations.
* **Verification Pipeline:** The client sends the calculated hexadecimal digest over the secure tunnel. The server validates the login by executing a constant-time comparison against a local pre-hashed credential database (`USERS`), preventing timing-attack vectors:
  * `alice` $\rightarrow$ `4e40e8ffe0ee32fa53e139147ed559229a5930f89c2204706fc174beb36210b3` (password: `alice123`)
  * `bob` $\rightarrow$ `bc786c379d8b4334faa1f5ed4428d53ed5fbf6247a5974a72eac7fd5c13410d8` (password: `bobpassword`)

#### Step 3 — RSA + AES Hybrid Key Exchange
To avoid the high computational cost of asymmetric operations for bulk data transmission, the system uses a hybrid cryptosystem.
1. **Handshake Initiation:** The client connects and transmits a plain JSON initialization payload: `{"type": "handshake_start"}`.
2. **Public Key Delivery:** The server responds by transmitting its public exponents: `{"type": "rsa_pub", "e": "0x10001", "n": "0x..."}`.
3. **Session Key Generation:** The client generates a cryptographically secure 256-bit symmetric session key ($32$ random bytes) by reading entropy source bits.
4. **Asymmetric Key Encryption:** The client encrypts the 32-byte AES key using the server's public RSA key. The modular exponentiation is calculated from scratch using the square-and-multiply algorithm to prevent integer overflow:
   $$c \equiv m^e \pmod n$$
5. **Decryption & Validation:** The server receives the ciphertext, decrypts it using its private exponent $d$ ($m \equiv c^d \pmod n$), and recovers the symmetric session key. The server confirms tunnel establishment by returning a confirmation message:
   `"KEY_EXCHANGE_VERIFIED"`, encrypted with the new AES key. The client decrypts and verifies this packet, activating the secure tunnel.

#### Step 4 — Encrypted Communication (AES-256-CBC)
All post-handshake traffic is fully encrypted utilizing a custom **AES-256** implementation operating in **Cipher Block Chaining (CBC)** mode.
* **Padding (PKCS#7):** Before encryption, payloads are padded to match the 16-byte (128-bit) block boundary. The pad byte value represents the number of padding bytes added.
* **CBC Encryption Routine:** For each 16-byte block of plaintext ($P_i$), the block is XORed with the preceding block's ciphertext ($C_{i-1}$) before passing through the AES core cipher. The first block is XORed with a cryptographically secure, randomized 16-byte **Initialization Vector (IV)**:
  $$C_i = \text{AES\_Encrypt}(P_i \oplus C_{i-1}, K)$$
  $$C_0 = \text{IV}$$
* **Transmission Wrapper:** Transmitted packets are serialized into JSON envelopes containing structural routing fields:
  ```json
  {
    "type": "secure_packet",
    "iv": "hex_string",
    "ciphertext": "hex_string",
    "nonce": "random_64bit_hex",
    "timestamp": "ISO_8601_UTC_string",
    "hmac": "hex_string"
  }
  ```

#### Step 5 — HMAC Integrity Verification (IDS Layer)
To protect against Man-in-the-Middle (MITM) packet alteration or active network injection, the system implements an integrity layer.
* **Custom HMAC-SHA256 Implementation:** Keyed-Hash Message Authentication Codes (HMAC) are calculated without library wrappers. The algorithm hashes a combination of inner-padded and outer-padded keys XORed with the message data:
  $$\text{HMAC}(K, m) = \text{SHA256}\big((K \oplus \text{opad}) \mathbin{\Vert} \text{SHA256}((K \oplus \text{ipad}) \mathbin{\Vert} m)\big)$$
  * $\text{ipad}$ is the byte `0x36` repeated 64 times.
  * $\text{opad}$ is the byte `0x5C` repeated 64 times.
* **IDS Signature Check:** The client signs each secure packet over the concatenated payload string: `iv_hex + ciphertext_hex + nonce + timestamp`.
* **Tampering Mitigation:** The server's Intrusion Detection System (IDS) re-computes the HMAC-SHA256 signature upon receipt using the active session key. If the computed signature does not match the packet's `hmac` field, the server flags the packet as **TAMPERED**, drops it instantly, alerts the live dashboard, and increments the threat level.

---

### Phase 2: Cyberattack Emulation and Defense

```
Normal Mode (Threat Level 0) ---> Alert (Level 1) ---> Block IP (Level 2) ---> Honeypot Mode (Level 3)
```

#### Step 6 — Brute-Force Attack Detection and IP Blocking
The system protects against dictionary attacks and automated credential cracking at the authentication boundary.
* **Attack Emulation:** The client features a `run_brute_force()` module that targets a specific account (e.g., `alice`) by iterating through a candidate password list: `["admin123", "password", "123456", "superman", "cyberdefense"]`. The client generates valid encrypted login envelopes for each attempt, transmitting wrong SHA-256 password digests.
* **IDS Detection & Rate-Limiting:** The server maintains an in-memory tracker of failed login attempts grouped by client IP (`failed_logins`).
* **Active Firewall Block:** Upon detecting three (3) consecutive failed authentication attempts from a single IP address, the server blocks the source IP for 30 seconds (`blocked_ips`) and transitions the threat level upwards. Any subsequent packets from the blocked IP are instantly dropped.

#### Step 7 — Replay Attack Detection (Nonce + Timestamp)
The platform guards against replay attacks, where an attacker intercepts a valid encrypted packet and re-transmits it to execute duplicate actions.
* **Attack Emulation:** The client stores its last successfully processed secure packet in `self.last_valid_packet`. The `run_replay_attack()` function re-injects this identical JSON packet into the network byte-for-byte.
* **Multi-Layer Verification:** The server's IDS validates packet freshness using two independent layers:
  1. **Time-Drift Check (15-second window):** The server parses the packet's UTC `timestamp`. If the absolute drift compared to the server's current clock exceeds 15 seconds, the packet is flagged as expired and dropped.
  2. **Nonce De-duplication Set:** Every incoming packet must contain a unique 64-bit cryptographic `nonce`. The server maintains a history of processed nonces in a lookup set (`used_nonces`). If an incoming nonce is already present in this set, it is flagged as a **REPLAY ATTACK**. The server blocks the attacker's IP for 30 seconds and transitions the system threat level to prevent unauthorized duplicates.

#### Step 8 — Adaptive Session Rekeying
To limit the exposure window if a symmetric session key is somehow compromised, the server implements an active key-rotation defense.
* **Telemetry Message Counter:** The server monitors active communication channels by keeping an active session count of successful messages (`rekey_count`).
* **Dynamic Rekeying Trigger:** Upon receiving five (5) successful messages within a single session, the server invalidates the current session key and sends an unencrypted rotation instruction: `{"type": "rekey_request"}`.
* **Transparent Re-Keying Handshake:** The client intercepts this request, temporarily pauses standard communications, and transparently initiates a new RSA-AES key exchange (Step 3) to establish a fresh 256-bit AES key. The client then automatically re-authenticates the active session using the new key, keeping the rotation invisible to the user.

#### Step 9 — Honeypot Deception System (CRITICAL Threat Level)
When the active threat level rises to **CRITICAL (Threat Level 3)**, the server transitions from a passive defense posture to active deception, isolating and neutralizing the attacker.
* **Deceptive Interception:** Any communication received from a blocked IP or classified as hostile is redirected to an isolated decoy container (`get_honeypot_fake_reply()`).
* **Decoy Authentication:** If the attacker attempts a brute-force login while the honeypot is active, the server returns an encrypted "Success" packet, granting access to a sandbox terminal and feeding them a fake session token: `DECOY_ROOT_AUTH_TOKEN_99812739182379A`.
* **Zero-Dependency Decoy PDF Generator:** If the attacker requests classified financials, the server dynamically generates a structurally valid, uncompressed **PDF byte stream** from scratch using basic ASCII formatting. The file includes a metadata header, catalog, text streams, and a visible flag:
  `FLAG{YOU_HAVE_BEEN_TRAPPED_BY_CYBER_SHIELD_HONEYPOT}`.
* **Decoy Encryption:** The decoy payloads are fully encrypted with the attacker's active AES key. This keeps the deception indistinguishable from a legitimate server response, tricking the attacker into believing they successfully breached the system.

#### Step 10 — Live Web Dashboard Monitoring
The system features dual Server-Sent Events (SSE) telemetry consoles that stream real-time logs, network routing details, and cryptographic states to web browsers.
* **Server Telemetry Dashboard (`/dashboard`):** Displays overall server health, live threat levels (Safe ➔ Elevated ➔ High ➔ Critical), active IP blocks with countdown timers, a packet visualizer displaying hex payloads, and real-time logs pushed via SSE connection (`/events`).
* **Client Operations Terminal (`/client`):** A browser-based CLI dashboard serving `client_dashboard.html`. It lets users trigger key exchanges, log in, send chats, tamper packets, launch attacks, or probe honeypots. 
* **Integrated Client Download Handler:** When a secure PDF payload is returned, the client dashboard automatically processes the base64 data stream:
  * In **Normal Mode**, it triggers an automatic browser-based download of **`classified_financials.pdf`** directly to the client's local downloads folder.
  * In **Honeypot Mode**, it triggers an automatic browser-based download of **`decoy_financials.pdf`** to showcase the successful capture of decoy assets on the client machine.
