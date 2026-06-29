# tests/test_memory_wipe.py
import unittest
import numpy as np
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../python')))

from vajraa.pal import (
    pal_alloc_secure,
    pal_unlock,
    pal_lock,
    pal_secure_zero,
    pal_free_secure,
    pal_store_key,
    pal_retrieve_key
)

class TestMemoryWipe(unittest.TestCase):
    def test_secure_allocation_lifecycle(self):
        size = 4096 # One page size
        
        # 1. Allocate page (set to PAGE_NOACCESS / PROT_NONE)
        ptr = pal_alloc_secure(size)
        self.assertNotEqual(ptr, 0)
        
        # 2. Unlock page for reading/writing
        success = pal_unlock(ptr, size)
        self.assertTrue(success)
        
        # 3. Write data into the page using ctypes
        import ctypes
        array_type = ctypes.c_char * 12
        address_array = array_type.from_address(ptr)
        
        test_string = b"hello_world\x00"
        ctypes.memmove(address_array, test_string, len(test_string))
        self.assertEqual(address_array.value, b"hello_world")
        
        # 4. Lock page (sets to PAGE_NOACCESS / PROT_NONE)
        # Note: If we read now, the program will crash (Access Violation / Segfault).
        success = pal_lock(ptr, size)
        self.assertTrue(success)
        
        # 5. Unlock again to zero-out
        success = pal_unlock(ptr, size)
        self.assertTrue(success)
        
        # 6. Secure zero memory
        pal_secure_zero(ptr, size)
        self.assertEqual(address_array[:], b"\x00" * 12)
        
        # 7. Free page
        pal_free_secure(ptr, size)

    def test_secure_key_storage(self):
        secret_key = b"super_secret_master_key_12345!"
        
        # 1. Store key in secure memory (DPAPI on Windows, XOR shares on Linux/macOS)
        success = pal_store_key(secret_key)
        self.assertTrue(success)
        
        # 2. Retrieve key and verify it matches
        retrieved = pal_retrieve_key()
        self.assertEqual(retrieved, secret_key)

if __name__ == '__main__':
    unittest.main()
