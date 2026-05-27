import urllib.request
import json
import time
import base64

def run_test():
    print("[*] Starting Dynamic PDF & Honeypot Decoy Verification Test...")

    # =========================================================================
    # TEST 1: Real User Flow
    # =========================================================================
    print("\n--- TEST 1: Real Authorized User ---")
    try:
        # Step 1. Establish Key Exchange
        kex_req = urllib.request.Request(
            "http://localhost:8080/client-action", 
            data=json.dumps({"action": "key_exchange"}).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        urllib.request.urlopen(kex_req)
        print("[+] Key Exchange triggered.")
        time.sleep(1.5)

        # Step 2. Login
        login_req = urllib.request.Request(
            "http://localhost:8080/client-action", 
            data=json.dumps({"action": "login", "username": "alice", "password": "alice123"}).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        urllib.request.urlopen(login_req)
        print("[+] Login triggered for alice.")
        time.sleep(1.5)

        # Step 3. Request Financials PDF
        fin_req = urllib.request.Request(
            "http://localhost:8080/client-action", 
            data=json.dumps({"action": "financials"}).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        urllib.request.urlopen(fin_req)
        print("[+] Financials PDF download triggered.")
        time.sleep(1.5)

        # Verify the saved local file
        import os
        if os.path.exists("classified_financials.pdf"):
            with open("classified_financials.pdf", "rb") as f:
                header = f.read(8)
                f.seek(0)
                full_text = f.read().decode('ascii', errors='ignore')
            
            if header == b"%PDF-1.4":
                print("[+] SUCCESS: classified_financials.pdf is a valid PDF-1.4 file!")
            else:
                print(f"[-] FAILED: PDF header mismatch: {header}")
                
            if "CLASSIFIED FINANCIAL RECORDS" in full_text:
                print("[+] SUCCESS: PDF content verified (contains 'CLASSIFIED FINANCIAL RECORDS').")
            else:
                print("[-] FAILED: PDF content did not match expected structure.")
        else:
            print("[-] FAILED: classified_financials.pdf not found in local directory.")

    except Exception as e:
        print(f"[-] TEST 1 Exception: {e}")

    # =========================================================================
    # TEST 2: Attacker Honeypot Flow
    # =========================================================================
    print("\n--- TEST 2: Attacker Honeypot Trap ---")
    try:
        # Step 1. Trigger Brute-Force to raise threat level and lock IP
        print("[*] Launching brute-force to elevate threat level...")
        brute_req = urllib.request.Request(
            "http://localhost:8080/client-action", 
            data=json.dumps({"action": "brute_force"}).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        urllib.request.urlopen(brute_req)
        time.sleep(10) # wait for brute force iterations to run and IP to lock (threat level escalates)

        # Step 2. Trigger Honeypot Probe login (takes us to level 3)
        print("[*] Probing Honeypot Trap...")
        hp_req = urllib.request.Request(
            "http://localhost:8080/client-action", 
            data=json.dumps({"action": "honeypot"}).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        urllib.request.urlopen(hp_req)
        time.sleep(2)

        # Step 3. Request financials PDF (decoy should feed now!)
        print("[*] Requesting financials from Honeypot...")
        fin_req2 = urllib.request.Request(
            "http://localhost:8080/client-level-decoy", 
            data=json.dumps({"action": "financials"}).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        # We trigger the standard financials action
        fin_req2 = urllib.request.Request(
            "http://localhost:8080/client-action", 
            data=json.dumps({"action": "financials"}).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        urllib.request.urlopen(fin_req2)
        time.sleep(2)

        if os.path.exists("decoy_financials.pdf"):
            with open("decoy_financials.pdf", "rb") as f:
                header = f.read(8)
                f.seek(0)
                full_text = f.read().decode('ascii', errors='ignore')
            
            if header == b"%PDF-1.4":
                print("[+] SUCCESS: decoy_financials.pdf is a valid PDF-1.4 file!")
            else:
                print(f"[-] FAILED: Decoy PDF header mismatch: {header}")
                
            if "WARNING: DECOY FEEDER ACTIVE" in full_text:
                print("[+] SUCCESS: Decoy content verified (contains 'DECOY FEEDER ACTIVE').")
            else:
                print("[-] FAILED: Decoy PDF did not contain warnings.")
                
            if "FLAG{YOU_HAVE_BEEN_TRAPPED" in full_text:
                print("[+] SUCCESS: Decoy PDF successfully caught the flag!")
            else:
                print("[-] FAILED: Honeypot flag missing in decoy PDF.")
        else:
            print("[-] FAILED: decoy_financials.pdf not found.")

        # Step 4. Cleanup and Reset
        print("[*] Cleaning up and resetting threat level...")
        cleanup_req = urllib.request.Request(
            "http://localhost:8080/client-action", 
            data=json.dumps({"action": "disconnect"}).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        urllib.request.urlopen(cleanup_req)
        time.sleep(1)

    except Exception as e:
        print(f"[-] TEST 2 Exception: {e}")

if __name__ == "__main__":
    run_test()

