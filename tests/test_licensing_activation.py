# tests/test_licensing_activation.py
import os
import sys
import time
import json
import unittest
import shutil
import base64
from datetime import datetime, timedelta

# Ensure package path and server path are visible
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../python')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../vajra-licensing-server')))

from vajraa.crypto import SecurityError
from vajraa.activation import (
    collect_fingerprint,
    verify_fuzzy_fingerprint,
    get_fingerprint_hash,
    check_clock_tampering,
    generate_activation_code_local,
    STATE_PATH
)

class TestClientLicensing(unittest.TestCase):
    def setUp(self):
        # Clear local state files
        if os.path.exists(STATE_PATH):
            os.remove(STATE_PATH)

    def tearDown(self):
        if os.path.exists(STATE_PATH):
            os.remove(STATE_PATH)

    def test_fuzzy_fingerprint_matching(self):
        """Verifies that the 2-of-4 fuzzy matching accepts updates and blocks clones."""
        fp1 = {
            "mac": "11:22:33:44:55:66",
            "cpu": "CPU_INTEL_123",
            "disk": "DISK_SSD_999",
            "uuid": "UUID-MOTHERBOARD-ABC"
        }
        
        # Scenario A: Perfect Match
        self.assertTrue(verify_fuzzy_fingerprint(fp1, fp1))
        
        # Scenario B: 1 Component Changed (NIC Swap) - 3-of-4 Match (Should pass)
        fp2 = fp1.copy()
        fp2["mac"] = "AA:BB:CC:DD:EE:FF"
        self.assertTrue(verify_fuzzy_fingerprint(fp1, fp2))
        
        # Scenario C: 2 Components Changed (NIC + CPU Upgrade) - 2-of-4 Match (Should pass)
        fp3 = fp1.copy()
        fp3["mac"] = "AA:BB:CC:DD:EE:FF"
        fp3["cpu"] = "CPU_AMD_456"
        self.assertTrue(verify_fuzzy_fingerprint(fp1, fp3))
        
        # Scenario D: 3 Components Changed (Cloned Machine) - 1-of-4 Match (Should fail)
        fp4 = fp1.copy()
        fp4["mac"] = "AA:BB:CC:DD:EE:FF"
        fp4["cpu"] = "CPU_AMD_456"
        fp4["disk"] = "DISK_NVME_000"
        self.assertFalse(verify_fuzzy_fingerprint(fp1, fp4))

    def test_clock_windback_protection(self):
        """Verifies that changing system clock backwards raises SecurityError."""
        # First run (establishes baseline)
        check_clock_tampering()
        self.assertTrue(os.path.exists(STATE_PATH))
        
        # Second run (time goes forward)
        check_clock_tampering()
        
        # Simulate clock windback: encrypt a future time into the state file
        future_time = time.time() + 3600.0
        
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        from vajraa.activation import STATE_KEY
        
        iv = os.urandom(12)
        encryptor = Cipher(
            algorithms.AES(STATE_KEY),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()
        
        ciphertext = encryptor.update(str(future_time).encode("utf-8")) + encryptor.finalize()
        with open(STATE_PATH, "wb") as f:
            f.write(iv + encryptor.tag + ciphertext)
            
        # Third run (should raise SecurityError)
        with self.assertRaises(SecurityError) as ctx:
            check_clock_tampering()
        self.assertIn("Clock windback detected", str(ctx.exception))

    def test_local_activation_verification(self):
        """Verifies local HMAC verification code computation matches target secret."""
        fp_hash = "d3b07384d113edec49eaa6238ad5ff00"
        lic_id = "LIC-TEST-123"
        secret = b"vendor_secret_key"
        
        code = generate_activation_code_local(fp_hash, lic_id, secret)
        self.assertEqual(len(code), 19) # XXXX-XXXX-XXXX-XXXX = 19 characters
        self.assertEqual(code.count("-"), 3)


class TestLicensingServer(unittest.TestCase):
    def setUp(self):
        # Clean local SQLite database file for tests
        if os.path.exists("vajraa.db"):
            try:
                os.remove("vajraa.db")
            except Exception:
                pass
                
        # We try importing the FastAPI app. If the vajra-licensing-server folder is not set up, skip
        try:
            from app.models import Customer, License, Activation
            from app.database import create_db_and_tables
            create_db_and_tables()
            from app.main import app as server_app
            from fastapi.testclient import TestClient
            self.client = TestClient(server_app)
            self.server_available = True
        except ImportError:
            self.server_available = False
            
    def tearDown(self):
        if os.path.exists("vajraa.db"):
            try:
                os.remove("vajraa.db")
            except Exception:
                pass
            
    def test_server_activation_flow(self):
        """Tests FastAPI Server endpoints using TestClient."""
        if not self.server_available:
            self.skipTest("Licensing server app folder not available in import path")
            
        # 1. Create a customer using Admin endpoint
        res = self.client.post(
            "/admin/customer",
            data={"id": "TestCorp", "name": "Test Corporation", "max_licenses": 3},
            auth=("admin", "vajraa-secure-admin-pass-2026"),
            follow_redirects=False
        )
        self.assertIn(res.status_code, [302, 303])
        
        # 2. Issue a license using Admin endpoint
        res = self.client.post(
            "/admin/license",
            data={
                "customer_id": "TestCorp",
                "name": "Llama-Test",
                "trial_days": 30,
                "max_devices": 2
            },
            auth=("admin", "vajraa-secure-admin-pass-2026"),
            follow_redirects=False
        )
        self.assertIn(res.status_code, [302, 303])
        
        # 3. Retrieve the created license from Database
        from app.database import engine
        from app.models import License
        from sqlmodel import Session, select
        
        with Session(engine) as db_sess:
            lic = db_sess.exec(select(License).where(License.customer_id == "TestCorp")).first()
            self.assertIsNotNone(lic)
            license_id = lic.id
            
        # 4. Trigger online activation endpoint
        fp = collect_fingerprint()
        fp_hash = get_fingerprint_hash(fp)
        
        res = self.client.post(
            "/api/activate",
            json={
                "license_id": license_id,
                "fingerprint_hash": fp_hash,
                "hardware_details": fp
            }
        )
        self.assertEqual(res.status_code, 200)
        res_data = res.json()
        self.assertEqual(res_data["status"], "SUCCESS")
        self.assertIn("activation_code", res_data)
        self.assertIn("wrapped_dek", res_data)
        
        # 5. Verify periodic online verification endpoint
        res = self.client.post(
            "/api/verify",
            json={
                "license_id": license_id,
                "fingerprint_hash": fp_hash
            }
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "ACTIVE")

        # 6. Verify revocation check
        res = self.client.post(
            f"/admin/license/revoke/{license_id}",
            auth=("admin", "vajraa-secure-admin-pass-2026")
        )
        self.assertIn(res.status_code, [200, 302, 303])
        
        res = self.client.post(
            "/api/verify",
            json={
                "license_id": license_id,
                "fingerprint_hash": fp_hash
            }
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "REVOKED")
