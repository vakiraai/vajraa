# python/vajraa/onnx_wrapper.py
import onnxruntime as ort
import onnx
import os
import sys
import ctypes
import json
import threading
import time
from .crypto import decrypt_license, SecurityError
from .pal import pal_secure_zero, pal_get_available_memory
from .pytorch_wrapper import VajraaConfig

class SecureONNXSession:
    def __init__(self, model_path: str, license_path: str, customer_key: bytes, config: VajraaConfig = None):
        """
        Loads a secured ONNX (.ems) model and configures the C++ memory pool.
        """
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found: {model_path}")
        if not os.path.exists(license_path):
            raise FileNotFoundError(f"License not found: {license_path}")
            
        self.config = config or VajraaConfig()
        self.compaction_timer = None
        self.lock = threading.Lock()
        
        # 1. Load and decrypt master key from license file
        with open(license_path, "rb") as f:
            lic_bytes = f.read()
        lic_data = decrypt_license(lic_bytes, customer_key)
        master_key = lic_data["master_key"]
        
        # 2. Extract model size metadata properties directly from the ONNX model
        max_layer_size = 0
        try:
            model_onnx = onnx.load(model_path)
            for prop in model_onnx.metadata_props:
                if prop.key == "max_layer_size_bytes":
                    max_layer_size = int(prop.value)
                    break
        except Exception:
            pass # Fallback to standard JIT if metadata extraction fails
            
        # 3. Locate compiled C++ custom operator library (cross-platform extensions)
        possible_dll_paths = [
            os.path.abspath(os.path.join(os.path.dirname(__file__), "../../build/Release/vajraa.dll")),
            os.path.abspath(os.path.join(os.path.dirname(__file__), "../../build/vajraa.dll")),
            os.path.abspath(os.path.join(os.path.dirname(__file__), "vajraa.dll")),
            os.path.abspath(os.path.join(os.path.dirname(__file__), "../../build/Release/libvajraa.so")),
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
            raise FileNotFoundError("Vajraa: Compiled native shared library not found. Build C++ project first.")
            
        # 4. Store the decryption key and configure the memory pool in C++ DLL
        self.dll = None
        try:
            dll = ctypes.CDLL(lib_path)
            self.dll = dll
            
            # Setup pal_store_key
            dll.pal_store_key.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
            dll.pal_store_key.restype = ctypes.c_bool
            
            import hashlib
            key_crypto = hashlib.sha256(master_key + b"_crypto").digest()
            
            key_bytes = (ctypes.c_uint8 * len(key_crypto)).from_buffer_copy(key_crypto)
            success = dll.pal_store_key(key_bytes, len(key_crypto))
            
            # Wiping key from Python heap
            pal_secure_zero(ctypes.addressof(key_bytes), len(key_crypto))
            del key_bytes
            del key_crypto
            
            # Wiping master key
            lic_data["master_key"] = b"\x00" * len(master_key)
            del master_key
            del lic_data
            
            if not success:
                raise SecurityError("Vajraa: Failed to store decryption key in C++ memory vault.")
                
            # Bind and configure the C++ level page pool
            if hasattr(dll, "pal_configure_pool"):
                dll.pal_configure_pool.argtypes = [
                    ctypes.c_bool,  # use_shuffling
                    ctypes.c_bool,  # use_tiered
                    ctypes.c_size_t, # capped_pool_size
                    ctypes.c_bool,  # use_hybrid
                    ctypes.c_size_t, # max_layer_size
                    ctypes.c_size_t  # avail_ram
                ]
                dll.pal_configure_pool.restype = ctypes.c_bool
                
                if hasattr(dll, "pal_compact_pool"):
                    dll.pal_compact_pool.argtypes = []
                    dll.pal_compact_pool.restype = ctypes.c_bool
                
                avail_ram = pal_get_available_memory()
                dll.pal_configure_pool(
                    self.config.use_shuffling,
                    self.config.use_tiered_pools,
                    self.config.capped_pool_size_bytes,
                    self.config.use_hybrid_mode,
                    max_layer_size,
                    avail_ram
                )
        except Exception as e:
            raise SecurityError(f"Vajraa: Failed to configure native C++ runtime library: {e}")
            
        # 5. Set Session Options and register custom C++ operators library
        self.opts = ort.SessionOptions()
        self.opts.register_custom_ops_library(lib_path)
        
        # 6. Initialize ONNX Runtime Session
        self.session = ort.InferenceSession(model_path, self.opts, providers=["CPUExecutionProvider"])

    def run(self, output_names: list, input_feed: dict) -> list:
        with self.lock:
            if self.compaction_timer:
                self.compaction_timer.cancel()
                self.compaction_timer = None
        
        res = self.session.run(output_names, input_feed)
        
        with self.lock:
            self.schedule_compaction()
        return res

    def schedule_compaction(self):
        if self.config.idle_timeout > 0:
            if self.compaction_timer:
                self.compaction_timer.cancel()
            self.compaction_timer = threading.Timer(self.config.idle_timeout, self.compact)
            self.compaction_timer.daemon = True
            self.compaction_timer.start()

    def compact(self):
        with self.lock:
            if self.dll and hasattr(self.dll, "pal_compact_pool"):
                try:
                    self.dll.pal_compact_pool()
                    print("[Vajraa] Dynamic Cache Compaction: Released idle C++ memory pool slots.")
                except Exception:
                    pass
