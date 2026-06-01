# 🛡️ Adaptive CryptoShield

> **A secure client-server communication system with custom cryptographic primitives, live cyberattack emulation, and an adaptive honeypot defense engine — built entirely from scratch in Python.**

*Cryptography AAT — 23CS4ESCRP | B.M.S. College of Engineering*

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Cryptographic Primitives](#cryptographic-primitives)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Running the System](#running-the-system)
- [Web Dashboards](#web-dashboards)
- [Attack Simulations](#attack-simulations)
- [Testing](#testing)
- [The 10-Step Demo Flow](#the-10-step-demo-flow)
- [Demo Credentials](#demo-credentials)

---

## Overview

Adaptive CryptoShield is a full-stack secure communication system that demonstrates applied cryptography in an adversarial environment. It implements **four cryptographic algorithms completely from scratch** (zero external crypto libraries), integrates them into a live TCP client-server protocol, and wraps the whole system in a real-time browser dashboard.

The system operates in two modes:
- **Friendly Mode** — legitimate encrypted communication (key exchange → login → secure chat → file transfer)
- **Attacker Mode** — adversarial simulation (brute-force, replay attack, MITM packet tampering, honeypot probing)

When attacks are detected, the server's **threat level state machine** escalates through four levels and ultimately deploys a **honeypot deception layer** that feeds cryptographically-encrypted decoy data to confirmed attackers.

---

## Features

### 🔐 Security Protocol
- **RSA-1024 Asymmetric Key Exchange** — server public key sent to client; client encrypts AES session key with it
- **AES-256-CBC Symmetric Encryption** — all application messages encrypted end-to-end after handshake
- **HMAC-SHA256 Packet Integrity** — every packet carries a MAC over `(IV || Ciphertext || Nonce || Timestamp)`
- **SHA-256 Password Hashing** — passwords never transmitted in plaintext; hashed client-side before sending
- **Replay Attack Prevention** — dual protection via nonce tracking + 15-second timestamp window
- **Adaptive Session Rekeying** — AES session key automatically rotated every 5 messages

### 🚨 Intrusion Detection & Defense
- **Brute-Force Detection** — IP blocked for 30s after 3 failed login attempts
- **MITM Tamper Detection** — HMAC mismatch immediately detected and packet rejected
- **Replay Attack Detection** — server maintains `used_nonces` set per session
- **4-Level Threat State Machine** — `SAFE → ELEVATED → HIGH → CRITICAL`
- **Honeypot Deception Engine** — at CRITICAL level, server serves encrypted fake responses (decoy credentials, decoy PDFs with trap flags)

### 📊 Real-Time Dashboards
- **Server Telemetry Dashboard** — live threat level indicator, packet telemetry, event log, blocked IP panel (SSE-powered)
- **Client Control Panel** — browser-based button interface to trigger all operations, with live log and result display

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       SYSTEM OVERVIEW                        │
└─────────────────────────────────────────────────────────────┘

  Browser                    Server (server.py)              Client (client.py)
  ───────                    ──────────────────              ──────────────────
  Dashboard  ◄──── SSE ────  HTTP :8080        ◄── TCP ──── AdaptiveSecureClient
  /client    ──── POST ────► /client-action    ──► TCP ────► encrypt_and_send()

                             TCP :9999
                             ├── RSA Key Exchange
                             ├── AES-256-CBC Decrypt
                             ├── HMAC Verification
                             ├── Replay/Brute-Force IDS
                             └── Honeypot Engine

  crypto_scratch.py (NO external crypto libs)
  ├── sha256 / sha256_hex
  ├── hmac_sha256 / hmac_sha256_hex
  ├── aes_256_cbc_encrypt / aes_256_cbc_decrypt
  └── generate_rsa_keys / rsa_encrypt / rsa_decrypt
```

**Threat Level State Machine:**
```
  SAFE (0) ──[brute-force attempt]──► ELEVATED (1)
  ELEVATED ──[IP blocked]──────────► HIGH (2)
  HIGH ────[replay/hammer blocked]──► CRITICAL (3) → HONEYPOT ACTIVE
  CRITICAL ──[disconnect/reset]────► SAFE (0)
```

---

## Cryptographic Primitives

All implemented in [`crypto_scratch.py`](crypto_scratch.py) with **no external cryptographic libraries**.

| Algorithm | Implementation Details |
|---|---|
| **SHA-256** | Merkle-Damgård construction, 64-round compression, `rotr`/`Ch`/`Maj`/`Σ0`/`Σ1` bitwise ops, 64 round constants |
| **HMAC-SHA256** | `H((K⊕opad) ∥ H((K⊕ipad) ∥ M))` — RFC 2104 compliant double-hash |
| **AES-256-CBC** | Full SubBytes (S-Box), ShiftRows, MixColumns (GF(2⁸) arithmetic), AddRoundKey, 14 rounds, PKCS#7 padding |
| **RSA-1024** | Miller-Rabin primality (k=30), Extended Euclidean for `d`, binary modular exponentiation, 512-bit prime generation |

---

## Project Structure

```
CrpAAT/
│
├── crypto_scratch.py        # All crypto primitives from scratch (SHA-256, HMAC, AES-256, RSA-1024)
├── server.py                # TCP secure server + HTTP dashboard server + honeypot engine
├── client.py                # Secure client + cyberattack emulator (brute-force, replay, tamper)
├── simulate.py              # Automated end-to-end 10-step demo script
│
├── dashboard.html           # Server telemetry dashboard (threat level, logs, packet telemetry)
├── client_dashboard.html    # Client control panel (button-driven ops, live SSE log)
│
├── test_crypto.py           # Unit tests for all cryptographic algorithms
├── verify_pdf_honeypot.py   # Integration test: verifies real PDF vs. decoy honeypot PDF
│
├── classified_financials.pdf  # Generated at runtime (legitimate user download)
├── decoy_financials.pdf       # Generated at runtime (honeypot decoy with trap flag)
│
└── README.md
```

---

## Getting Started

### Prerequisites

- **Python 3.8+** — no external packages required; uses only the standard library
- A modern browser (Chrome, Firefox, Edge) for the dashboards

### Clone / Navigate to the Project

```bash
cd CrpAAT
```

### Verify Python Version

```bash
python --version
# Should output Python 3.8 or higher
```

---

## Running the System

### Step 1 — Start the Server

```bash
python server.py
```

Expected output:
```
==========================================================
   ADAPTIVE SECURE SERVER WITH LIVE CRYPTANALYSIS DEFENSE
==========================================================
[*] Generating Server RSA-1024 Keypair (scratch math)...
[+] RSA-1024 Keypair Generated Successfully.
[+] TCP Secure Socket Server listening on 0.0.0.0:9999
[+] Web Dashboard Server running at http://localhost:8080/
```

> **Note:** RSA key generation takes 5–20 seconds depending on machine speed (prime generation uses Miller-Rabin).

### Step 2 — Open the Dashboards

Open two browser tabs:

| Dashboard | URL | Purpose |
|---|---|---|
| Server Telemetry | `http://localhost:8080/` | Threat level, event logs, packet telemetry |
| Client Control Panel | `http://localhost:8080/client` | Trigger operations, view results |

### Step 3 — Use the Client Panel

From the **Client Dashboard**, click buttons in order:
1. **Key Exchange** — establishes RSA+AES secure tunnel
2. **Login** (alice / alice123) — authenticates over the encrypted channel
3. **Send Chat** — sends an AES-256-CBC encrypted message
4. **Download Financials** — transfers a classified PDF over the secure channel

Then try the attack simulations (see [Attack Simulations](#attack-simulations) below).

---

### Automated Demo (Optional)

To run all 10 steps automatically without browser interaction:

```bash
# Terminal 1 - ensure server is running first
python server.py

# Terminal 2 - run the automated simulator
python simulate.py
```

This runs the complete friendly + attacker flow sequentially and prints each step.

---

## Web Dashboards

### Server Telemetry Dashboard (`/`)

| Panel | What It Shows |
|---|---|
| **Threat Level Indicator** | Live colour-coded badge: 🟢 SAFE / 🟡 ELEVATED / 🟠 HIGH / 🔴 CRITICAL |
| **Event Log** | Real-time stream of categorised events (SYSTEM, CRYPTO, SECURE, ATTACK, DEFENSE, HONEYPOT) |
| **Packet Telemetry** | Every packet's direction, type, HMAC status (passed / tampered / replay) |
| **Blocked IPs** | Active IP blocks with countdown timers |

### Client Control Panel (`/client`)

| Section | What It Does |
|---|---|
| **Status Strip** | Shows connection state, AES key prefix, logged-in username |
| **Phase 1 buttons** | Key Exchange, Login, Send Chat, Download Financials, Tamper Packet |
| **Phase 2 buttons** | Brute-Force Attack, Replay Attack, Honeypot Probe, Disconnect & Reset |
| **Live Log** | Colour-coded SSE log stream mirroring client.py console output |
| **Result Panel** | Displays structured result of each operation (success/error/warning) |

---

## Attack Simulations

All attacks are available from the **Client Dashboard** (Phase 2 section):

### 🔨 Brute-Force Attack
Iterates through a password list (`admin123`, `password`, `123456`, `superman`, `cyberdefense`) against user `alice`. Server blocks the IP after 3 failures and raises threat level to HIGH.

### ↩️ Replay Attack
Captures a legitimate encrypted packet sent earlier and re-sends it byte-for-byte. Server rejects it because the nonce is already in `used_nonces`. If the packet is older than 15 seconds, it's also rejected by timestamp expiry.

### ✂️ MITM Tamper Demo
Builds a valid AES-CBC encrypted packet then deliberately corrupts the HMAC field before sending. Server detects HMAC mismatch and rejects with `{"status": "tampered"}`.

### 🕵️ Honeypot Probe
At CRITICAL threat level, sends bad credentials. Server returns a convincing fake login success with a decoy root token (`DECOY_ROOT_AUTH_TOKEN_99812739182379A`). A follow-up financials request receives a decoy PDF containing:
```
Honeypot Flag: FLAG{YOU_HAVE_BEEN_TRAPPED_BY_CYBER_SHIELD_HONEYPOT}
```

**To trigger honeypot mode:** Run Brute-Force first (raises threat to HIGH/IP-blocked), then Honeypot Probe. This escalates to CRITICAL.

**To reset:** Click **Disconnect & Reset** — clears all IP blocks and resets threat to SAFE.

---

## Testing

### Cryptographic Unit Tests

Verifies SHA-256, HMAC-SHA256, AES-256-CBC, and RSA-1024 against known vectors:

```bash
python test_crypto.py
```

Expected output:
```
====================================================
RUNNING CRYPTOGRAPHIC VERIFICATION (FROM SCRATCH)
====================================================

[+] Testing SHA-256:
  SHA-256 matches official vector! SUCCESS.

[+] Testing HMAC-SHA256:
  HMAC calculation succeeded! SUCCESS.

[+] Testing AES-256-CBC (256-bit key):
  AES-256-CBC encrypt/decrypt matches! SUCCESS.

[+] Testing RSA-1024 Key Generation & Cryptography:
  RSA Encryption/Decryption matches! SUCCESS.
====================================================
VERIFICATION COMPLETED!
====================================================
```

### PDF & Honeypot Integration Test

Verifies that the legitimate and decoy PDFs are generated correctly (requires server to be running):

```bash
# Terminal 1
python server.py

# Terminal 2
python verify_pdf_honeypot.py
```

Checks:
- `classified_financials.pdf` — valid PDF-1.4 header, contains `CLASSIFIED FINANCIAL RECORDS`
- `decoy_financials.pdf` — valid PDF-1.4 header, contains `DECOY FEEDER ACTIVE` and honeypot flag

---

## The 10-Step Demo Flow

| Step | Description | Mode |
|---|---|---|
| **1** | Server starts, RSA-1024 keypair generated (Miller-Rabin prime generation) | Server |
| **2** | Client hashes password with custom SHA-256 for authentication | Client |
| **3** | RSA + AES hybrid key exchange — establishes shared AES-256 session key | Both |
| **4** | Encrypted communication via AES-256-CBC (chat, file transfer) | Both |
| **5** | HMAC-SHA256 integrity check on every packet; tamper demo triggers IDS | IDS |
| **6** | Brute-force attack → IP blocking after 3 failures → ELEVATED/HIGH threat | Attack |
| **7** | Replay attack → nonce/timestamp detection → IP block → HIGH threat | Attack |
| **8** | Adaptive session rekeying triggered after every 5 messages automatically | Defense |
| **9** | Honeypot mode at CRITICAL — encrypted decoy responses fed to attacker | Honeypot |
| **10** | Live web dashboard — real-time SSE telemetry for all events and packets | Dashboard |

---

## Demo Credentials

| Username | Password | Role |
|---|---|---|
| `alice` | `alice123` | Standard user |
| `bob` | `bobpassword` | Standard user |

Passwords are stored on the server as SHA-256 digests only. The client computes `sha256_hex(password)` locally before sending over the encrypted channel.

---

## Implementation Notes

- **No external crypto libraries used.** All algorithms (`hashlib`, `pycryptodome`, `cryptography`, etc.) are replaced by implementations in `crypto_scratch.py`.
- **PDF generation is from scratch.** The server builds valid PDF-1.4 byte streams manually (cross-reference tables, object offsets, stream lengths) without any PDF library.
- **SSE (Server-Sent Events)** are used for dashboard streaming — no WebSockets, no polling.
- The client dashboard is served by the same Python HTTP server that handles TCP crypto connections — no Node.js or separate web server needed.
- Threat level resets to SAFE when **Disconnect & Reset** is triggered from the client panel.

---

*B.M.S. College of Engineering — Department of CSE | Cryptography (23CS4ESCRP) AAT*
