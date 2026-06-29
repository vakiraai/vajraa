# tests/test_crypto.py
import unittest
import numpy as np
import os
import sys

# Ensure package path is visible
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../python')))

from vajraa.crypto import encrypt_tensor, decrypt_tensor, generate_license, decrypt_license

class TestCrypto(unittest.TestCase):
    def setUp(self):
        self.master_key = os.urandom(32) # AES-256 Key
        self.customer_key = os.urandom(32)
        self.customer_id = "cust_abc_123"

    def test_tensor_encryption(self):
        # 1. Generate test numpy array
        original_arr = np.random.randn(10, 20).astype(np.float32)
        
        # 2. Encrypt
        enc_dict = encrypt_tensor(original_arr, self.master_key)
        self.assertIn("ciphertext", enc_dict)
        self.assertIn("iv", enc_dict)
        self.assertIn("tag", enc_dict)
        self.assertEqual(enc_dict["shape"], [10, 20])
        
        # 3. Decrypt and verify
        decrypted_arr = decrypt_tensor(enc_dict, self.master_key)
        np.testing.assert_array_almost_equal(original_arr, decrypted_arr)

    def test_license_wrapping(self):
        # 1. Generate key-wrapped license
        lic_bytes = generate_license(self.customer_id, self.master_key, self.customer_key)
        self.assertTrue(len(lic_bytes) > 0)
        
        # 2. Decrypt license and verify keys match
        lic_data = decrypt_license(lic_bytes, self.customer_key)
        self.assertEqual(lic_data["customer_id"], self.customer_id)
        self.assertEqual(lic_data["master_key"], self.master_key)

    def test_license_expiry(self):
        from vajraa.crypto import SecurityError
        
        # Test active license (1 day expiry)
        lic_bytes_active = generate_license(self.customer_id, self.master_key, self.customer_key, expiry_days=1.0)
        lic_data_active = decrypt_license(lic_bytes_active, self.customer_key)
        self.assertEqual(lic_data_active["master_key"], self.master_key)
        
        # Test expired license (-1 day expiry)
        lic_bytes_expired = generate_license(self.customer_id, self.master_key, self.customer_key, expiry_days=-1.0)
        with self.assertRaises(SecurityError):
            decrypt_license(lic_bytes_expired, self.customer_key)

if __name__ == '__main__':
    unittest.main()
