# python/vajraa/onnx_wrapper.py
import onnxruntime as ort
import os
import sys
import ctypes
from .crypto import decrypt_license, SecurityError
from .pal import pal_secure_zero

class SecureONNXSession:
    def __init__(self, model_path: str, license_path: str, customer_key: bytes):
        """
        Loads a secured ONNX (.ems) model.
        1. Decrypts the license file to extract the master key.
        2. Locates and loads the C++ custom operator dynamic library.
        3. Stores the master key securely in the C++ DLL's global memory vault.
        4. Registers the custom C++ operator DLL with ONNX Runtime.
        5. Initializes the secure inference session.
        """
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found: {model_path}")
        if not os.path.exists(license_path):
            raise FileNotFoundError(f"License not found: {license_path}")
            
        # 1. Load and decrypt master key from license file
        with open(license_path, "rb") as f:
            lic_bytes = f.read()
        lic_data = decrypt_license(lic_bytes, customer_key)
        master_key = lic_data["master_key"]
        
        # 2. Locate compiled C++ custom operator library (cross-platform extensions)
        possible_dll_paths = [
            os.path.abspath(os.path.join(os.path.dirname(__file__), "../../build/Release/vajraa.dll")),
            os.path.abspath(os.path.join(os.path.dirname(__file__), "../../build/vajraa.dll")),
            os.path.abspath(os.path.join(os.path.dirname(__file__), "vajraa.dll")),
            os.path.abspath(os.path.join(os.path.dirname(__file__), "../../build/libvajraa.so")),
            os.path.abspath(os.path.join(os.path.dirname(__file__), "libvajraa.so")),
            os.path.abspath(os.path.join(os.path.dirname(__file__), "../../build/libvajraa.dylib")),
            os.path.abspath(os.path.join(os.path.dirname(__file__), "libvajraa.dylib")),
        ]
        
        lib_path = None
        for path in possible_dll_paths:
            if os.path.exists(path):
                lib_path = path
                break
                
        if lib_path is None:
            raise FileNotFoundError("Vajraa: Compiled native shared library (vajraa.dll/libvajraa.so) not found. Build C++ project first.")
            
        # 3. Store the decryption key securely in the C++ DLL's memory vault
        try:
            dll = ctypes.CDLL(lib_path)
            dll.pal_store_key.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
            dll.pal_store_key.restype = ctypes.c_bool
            
            # Derive key_crypto matching the compiler's derivation logic
            import hashlib
            key_crypto = hashlib.sha256(master_key + b"_crypto").digest()
            
            key_bytes = (ctypes.c_uint8 * len(key_crypto)).from_buffer_copy(key_crypto)
            success = dll.pal_store_key(key_bytes, len(key_crypto))
            
            # Wiping the temporary key variables from Python heap immediately
            pal_secure_zero(ctypes.addressof(key_bytes), len(key_crypto))
            del key_bytes
            del key_crypto
            
            # Wiping master key from dict and stack
            lic_data["master_key"] = b"\x00" * len(master_key)
            del master_key
            del lic_data
            
            if not success:
                raise SecurityError("Vajraa: Failed to store decryption key in C++ memory vault.")
        except Exception as e:
            raise SecurityError(f"Vajraa: Failed to bind key storage in native DLL: {e}")
            
        # 4. Set Session Options and register custom C++ operators library
        self.opts = ort.SessionOptions()
        self.opts.register_custom_ops_library(lib_path)
        
        # 5. Initialize ONNX Runtime Session
        self.session = ort.InferenceSession(model_path, self.opts, providers=["CPUExecutionProvider"])

    def run(self, output_names: list, input_feed: dict) -> list:
        """
        Runs secure inference. Weights are decrypted on-the-fly inside the C++ operator, 
        and immediately zero-wiped from memory.
        """
        return self.session.run(output_names, input_feed)
