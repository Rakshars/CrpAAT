#!/usr/bin/env python3
"""
simulate.py
Automated End-to-End Simulator for the 10 Steps of the Project.
"""

import time
import sys
from client import AdaptiveSecureClient, Colors

def log_step(step_num, title, desc):
    print(f"\n{Colors.BOLD}{Colors.PURPLE}====================================================")
    print(f" STEP {step_num}: {title}")
    print(f" {desc}")
    print(f"===================================================={Colors.END}")

def main():
    host = '127.0.0.1'
    if len(sys.argv) > 1:
        host = sys.argv[1]
        
    print(f"{Colors.GREEN}[*] Starting Adaptive Secure Server 10-Step Simulator on host {host}...{Colors.END}")
    
    # -------------------------------------------------------------
    # PHASE 1: FRIENDLY MODE
    # -------------------------------------------------------------
    
    log_step("1 & 3", "Server Starts & Key Exchange", "Establishing RSA Asymmetric Key exchange to securely share a 256-bit AES symmetric key.")
    client = AdaptiveSecureClient(host=host)
    if not client.connect():
        print(f"{Colors.RED}[-] Server offline. Make sure server.py is running.{Colors.END}")
        return
        
    # Execute Key Exchange
    time.sleep(1)
    if not client.do_key_exchange():
        print(f"{Colors.RED}[-] Key exchange failed.{Colors.END}")
        return
    time.sleep(2)
    
    log_step("2", "Client Secure Login", "Hashing user password (alice/alice123) with custom SHA-256 and sending encrypted authentication payload.")
    client.do_login("alice", "alice123")
    time.sleep(3)
    
    log_step("4 & 5", "Secure Encrypted Communication & Packet Verification", "Sending encrypted chats (AES-256-CBC) and computing HMAC signatures for integrity check.")
    client.do_send_message("Initializing server configuration. All systems green.")
    time.sleep(2.5)
    client.do_send_message("Requesting standard telemetry update.")
    time.sleep(2.5)
    
    # Showcase accessing classified financials successfully in friendly mode
    client.do_get_classified_financials()
    time.sleep(3)
    
    log_step("5 (IDS)", "Packet Tampering Protection Test", "Deliberately corrupting ciphertext bytes and HMAC to demonstrate Server IDS catching transit modifications.")
    client.do_tamper_demo()
    time.sleep(4)
    
    log_step("8", "Adaptive Defense Rekey Rotation", "Sending more chats to hit the rekey limit (5 successful messages) and trigger dynamic key replacement.")
    client.do_send_message("Sending message 3/5 towards key rotation.")
    time.sleep(2)
    client.do_send_message("Sending message 4/5 towards key rotation.")
    time.sleep(2)
    client.do_send_message("Triggering rotating rekeying on message 5/5...")
    # This 5th message triggers automatic key rotation on client.py (client does do_key_exchange dynamically in background)
    client.do_send_message("Message post-rekey: Establishing fresh cipher block chain.")
    time.sleep(4)
    
    # Disconnect friendly client
    client.close()
    time.sleep(2)
    
    # -------------------------------------------------------------
    # PHASE 2: ATTACKER MODE
    # -------------------------------------------------------------
    
    log_step("6", "Brute Force Password Attack", "Simulating Laptop 2 entering attacker mode, hammering authentication with multiple fake password attempts.")
    attacker_client = AdaptiveSecureClient(host=host)
    if not attacker_client.connect():
        return
        
    # Attacker needs key exchange first to speak AES
    if not attacker_client.do_key_exchange():
        return
        
    # Run brute force cracking attempts (triggers IP block and raises threat to HIGH)
    attacker_client.run_brute_force()
    time.sleep(4)
    attacker_client.close()
    
    log_step("7", "Replay Attack Prevention", "Simulating intercepting an old valid message and resending it. Server Nonce & Timestamp checks block it instantly.")
    # We will connect a new simulator to execute replay
    replay_client = AdaptiveSecureClient(host=host)
    if not replay_client.connect():
        return
    if not replay_client.do_key_exchange():
        return
    # Send a legitimate chat first to capture its packet in replay_client
    replay_client.do_send_message("Legitimate transmission capture block.")
    time.sleep(2)
    # Replay it! This raises threat level and blocks client
    replay_client.run_replay_attack()
    time.sleep(4)
    replay_client.close()
    
    log_step("9 & 10", "Adaptive Honeypot Response System & Dashboard Monitoring", "Attacker continues hammering blocked server. Threat goes to CRITICAL, trapping attacker in Decoy Honeypot.")
    
    # We will run a honeypot check to show attacker lured into decoy root console and getting fake database credentials
    honeypot_client = AdaptiveSecureClient(host=host)
    if not honeypot_client.connect():
        return
    if not honeypot_client.do_key_exchange():
        return
        
    # Probe server (Since threat level is HIGH and IP block is active or has escalated, honeypot activates)
    # To ensure CRITICAL (Level 3) threat is reached, honeypot_client will run probe
    honeypot_client.check_honeypot_trap()
    time.sleep(5)
    
    honeypot_client.close()
    
    print(f"\n{Colors.BOLD}{Colors.GREEN}====================================================")
    print(" SIMULATION COMPLETE! ALL 10 STEPS DEMONSTRATED.")
    print("===================================================={Colors.END}")

if __name__ == '__main__':
    main()
