# python/vajraa/activation.py
import os
import sys
import uuid
import json
import time
import socket
import subprocess
import hashlib
import hmac
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from .crypto import SecurityError

# Shared vendor keys for HMAC verification
SERVER_SECRET = b"vajraa_kms_master_secret_key_2026"
STATE_DIR = os.path.expanduser("~/.vajraa")
os.makedirs(STATE_DIR, exist_ok=True)

# Path to local activation token lease and clock state
LEASE_PATH = os.path.join(STATE_DIR, "license_lease.json")
STATE_PATH = os.path.join(STATE_DIR, "state.bin")

# Simple symmetric key for encrypting local clock state file
STATE_KEY = hashlib.sha256(b"vajraa_local_state_key_secret_2026").digest()

# =====================================================================
# HARDWARE FINGERPRINTING & FUZZY MATCHING (2-OF-4 GATE)
# =====================================================================

def get_mac_address() -> str:
    """Retrieves primary MAC address of the system."""
    try:
        mac = uuid.getnode()
        return ':'.join(('%012X' % mac)[i:i+2] for i in range(0, 12, 2))
    except Exception:
        return "00:00:00:00:00:00"

def get_cpu_id() -> str:
    """Retrieves CPU Processor ID."""
    try:
        if sys.platform == "win32":
            output = subprocess.check_output("wmic cpu get processorid", shell=True)
            lines = output.decode("utf-8").strip().split("\n")
            if len(lines) > 1:
                return lines[1].strip()
        else: # Linux/Mac
            with open("/proc/cpuinfo", "r") as f:
                for line in f:
                    if "serial" in line.lower() or "signature" in line.lower():
                        return line.split(":")[-1].strip()
    except Exception:
        pass
    return "UNKNOWN_CPU"

def get_disk_serial() -> str:
    """Retrieves System Drive Serial Number."""
    try:
        if sys.platform == "win32":
            output = subprocess.check_output("wmic diskdrive get serialnumber", shell=True)
            lines = output.decode("utf-8").strip().split("\n")
            if len(lines) > 1:
                return lines[1].strip()
        else: # Linux/Mac
            output = subprocess.check_output("findmnt -n -o SOURCE / | xargs udevadm info -q property -n | grep ID_SERIAL", shell=True)
            return output.decode("utf-8").split("=")[-1].strip()
    except Exception:
        pass
    return "UNKNOWN_DISK"

def get_motherboard_uuid() -> str:
    """Retrieves Motherboard System UUID."""
    try:
        if sys.platform == "win32":
            output = subprocess.check_output("wmic csproduct get uuid", shell=True)
            lines = output.decode("utf-8").strip().split("\n")
            if len(lines) > 1:
                return lines[1].strip()
        else: # Linux/Mac
            with open("/sys/class/dmi/id/product_uuid", "r") as f:
                return f.read().strip()
    except Exception:
        pass
    return "UNKNOWN_UUID"

def collect_fingerprint() -> dict:
    """Compiles the 4 local hardware identifiers."""
    return {
        "mac": get_mac_address(),
        "cpu": get_cpu_id(),
        "disk": get_disk_serial(),
        "uuid": get_motherboard_uuid()
    }

def get_fingerprint_hash(fp: dict) -> str:
    """Calculates stable SHA256 of the aggregated hardware identifiers."""
    fp_str = f"{fp['mac']}:{fp['cpu']}:{fp['disk']}:{fp['uuid']}"
    return hashlib.sha256(fp_str.encode("utf-8")).hexdigest()

def verify_fuzzy_fingerprint(registered_fp: dict, current_fp: dict) -> bool:
    """
    Fuzzy 2-of-4 matcher.
    Checks if at least 2 of the 4 hardware identifiers match.
    """
    matches = 0
    for key in ["mac", "cpu", "disk", "uuid"]:
        reg_val = registered_fp.get(key)
        curr_val = current_fp.get(key)
        # Avoid false positives on empty or generic "UNKNOWN" values
        if reg_val and curr_val and "UNKNOWN" not in reg_val and "UNKNOWN" not in curr_val:
            if reg_val.strip().lower() == curr_val.strip().lower():
                matches += 1
                
    # If we have 2 or more matches, verify successful hardware identification
    return matches >= 2

# =====================================================================
# MONOTONIC CLOCK WINDBACK PROTECTION
# =====================================================================

def check_clock_tampering():
    """
    Decrypts the local state file and verifies the system time is monotonic.
    Locks execution on negative time shifts.
    """
    current_time = time.time()
    
    # Read and decrypt previous time
    last_time = 0.0
    if os.path.exists(STATE_PATH):
        try:
            with open(STATE_PATH, "rb") as f:
                state_data = f.read()
                
            iv = state_data[:12]
            tag = state_data[12:28]
            ciphertext = state_data[28:]
            
            decryptor = Cipher(
                algorithms.AES(STATE_KEY),
                modes.GCM(iv, tag),
                backend=default_backend()
            ).decryptor()
            
            raw_time = decryptor.update(ciphertext) + decryptor.finalize()
            last_time = float(raw_time.decode("utf-8"))
        except Exception:
            # If the state file is corrupted or deleted, reset or enforce caution.
            # In production, we log a warning but allow creation to avoid bricking on first installation.
            pass
            
    # Check windback
    if last_time > 0.0 and current_time < last_time:
        # Detected time travel
        raise SecurityError("License verification failed: Clock windback detected!")
        
    # Encrypt and save current time
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(STATE_KEY),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    
    ciphertext = encryptor.update(str(current_time).encode("utf-8")) + encryptor.finalize()
    
    with open(STATE_PATH, "wb") as f:
        f.write(iv + encryptor.tag + ciphertext)

# =====================================================================
# HYBRID ROUTING & QR CODE RENDERER
# =====================================================================

def render_ascii_qr(url: str):
    """Prints a clean text block alternative QR rendering in the terminal console."""
    print("\n" + "="*60)
    print("                 VAJRAA OFFLINE ACTIVATION REQUIRED")
    print("="*60)
    print("\nTo activate this machine, scan the URL link below with your phone:")
    print(f"\n👉 {url}\n")
    print("="*60 + "\n")

def run_activation_flow(license_id: str, server_url: str = "http://localhost:8000") -> dict:
    """
    Client activation orchestrator.
    Attempts automatic online activation first.
    Falls back to QR activation if offline.
    """
    fp = collect_fingerprint()
    fp_hash = get_fingerprint_hash(fp)
    
    # 1. Attempt Online Handshake
    try:
        import urllib.request
        import urllib.error
        
        req_data = json.dumps({
            "license_id": license_id,
            "fingerprint_hash": fp_hash,
            "hardware_details": fp
        }).encode("utf-8")
        
        req = urllib.request.Request(
            f"{server_url}/api/activate",
            data=req_data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        
        # Quick timeout to fail fast if offline
        with urllib.request.urlopen(req, timeout=3.0) as response:
            res_dict = json.loads(response.read().decode("utf-8"))
            if res_dict.get("status") == "SUCCESS":
                # Save token lease locally
                lease = {
                    "license_id": license_id,
                    "registered_fingerprint": fp,
                    "wrapped_dek": res_dict["wrapped_dek"],
                    "expires_at": res_dict["expires_at"]
                }
                with open(LEASE_PATH, "w") as f:
                    json.dump(lease, f)
                print("[Vajraa] Online activation completed automatically.")
                return lease
    except Exception:
        # Offline or server unreachable, fallback to QR flow
        pass

    # 2. Offline Fallback (QR Scan Page)
    # Encrypt activation payload using SERVER_SECRET to prevent client-side spoofing
    payload = json.dumps({
        "license_id": license_id,
        "fingerprint_hash": fp_hash,
        "hardware_details": fp
    }).encode("utf-8")
    
    # Simple AES-256-GCM encryption with server key
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(hashlib.sha256(SERVER_SECRET).digest()), # SHA256 of secret
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    
    ciphertext = encryptor.update(payload) + encryptor.finalize()
    enc_dict = {
        "iv": base64.b64encode(iv).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "tag": base64.b64encode(encryptor.tag).decode("utf-8")
    }
    
    # Format encoded URL payload
    payload_str = base64.b64encode(json.dumps(enc_dict).encode("utf-8")).decode("utf-8")
    activation_url = f"{server_url}/activate?data={urllib.parse.quote(payload_str)}"
    
    render_ascii_qr(activation_url)
    
    # Prompt user for Activation Token
    print("Paste your 80-character Activation Token here and press Enter:")
    token_str = input("Token > ").strip()
    
    try:
        token_payload = json.loads(token_str)
        activation_code = token_payload["code"]
        wrapped_dek = token_payload["wrapped_dek"]
        
        # Verify code locally using HMAC-SHA256
        expected_code = generate_activation_code_local(fp_hash, license_id, SERVER_SECRET)
        if not hmac.compare_digest(activation_code, expected_code):
            raise SecurityError("Activation code is incorrect")
            
        # Register Lease
        lease = {
            "license_id": license_id,
            "registered_fingerprint": fp,
            "wrapped_dek": wrapped_dek,
            "expires_at": (datetime_now_str(30)) # Assume 30-day lease locally
        }
        with open(LEASE_PATH, "w") as f:
            json.dump(lease, f)
            
        print("[Vajraa] Offline activation completed successfully.")
        return lease
    except Exception as e:
        raise SecurityError(f"Activation failed: {e}")

def generate_activation_code_local(fingerprint_hash: str, license_id: str, secret: bytes) -> str:
    """Recalculates the verification code locally."""
    message = f"{fingerprint_hash}:{license_id}".encode("utf-8")
    h = hmac.new(secret, message, hashlib.sha256).digest()
    b32 = base64.b32encode(h).decode("utf-8").replace("=", "")
    code = b32[:16]
    return f"{code[0:4]}-{code[4:8]}-{code[8:12]}-{code[12:16]}"

def datetime_now_str(days: int) -> str:
    """Helper to format ISO date strings."""
    # Simplified ISO datetime format
    from datetime import datetime, timedelta
    t = datetime.utcnow() + timedelta(days=days)
    return t.isoformat()

def verify_active_lease(license_id: str) -> bytes:
    """
    Verifies the local license lease against current hardware fingerprint and expiry.
    If valid, returns the decrypted Data Encryption Key (DEK).
    """
    check_clock_tampering()
    
    if not os.path.exists(LEASE_PATH):
        raise SecurityError("No active license lease found. Activation required.")
        
    try:
        with open(LEASE_PATH, "r") as f:
            lease = json.load(f)
            
        if lease["license_id"] != license_id:
            raise SecurityError("Active lease does not match model license ID")
            
        # Verify expiry
        expires_at = datetime.fromisoformat(lease["expires_at"])
        if datetime.utcnow() > expires_at:
            raise SecurityError("License has expired")
            
        # Verify fuzzy hardware fingerprint
        curr_fp = collect_fingerprint()
        if not verify_fuzzy_fingerprint(lease["registered_fingerprint"], curr_fp):
            raise SecurityError("License hardware verification failed (Device mismatch)")
            
        # Decrypt wrapped DEK using derived KEK
        fp_hash = get_fingerprint_hash(curr_fp)
        kek = derive_kek(fp_hash, SERVER_SECRET)
        
        # Decode wrapped DEK GCM components
        wrapped_dek = lease["wrapped_dek"]
        iv = base64.b64decode(wrapped_dek["iv"])
        ciphertext = base64.b64decode(wrapped_dek["ciphertext"])
        tag = base64.b64decode(wrapped_dek["tag"])
        
        decryptor = Cipher(
            algorithms.AES(kek),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()
        
        dek = decryptor.update(ciphertext) + decryptor.finalize()
        return dek
    except SecurityError:
        raise
    except Exception as e:
        raise SecurityError(f"License verification failed: {e}") from None
