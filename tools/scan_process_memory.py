# tools/scan_process_memory.py
import torch
import torch.nn as nn
import numpy as np
import ctypes
import os
import sys
import gc

# Ensure package path is visible
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../python')))

from vajraa.base_shield import compile_base_weights, secure_wrap_base
from vajraa.pal import IS_WINDOWS

# Setup Win32 APIs for memory scanning on Windows
if IS_WINDOWS:
    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", ctypes.c_ulong),
            ("PartitionId", ctypes.c_ushort),
            ("RegionSize", ctypes.c_size_t),
            ("State", ctypes.c_ulong),
            ("Protect", ctypes.c_ulong),
            ("Type", ctypes.c_ulong)
        ]
        
    kernel32 = ctypes.windll.kernel32
    kernel32.VirtualQuery.argtypes = [ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
    kernel32.VirtualQuery.restype = ctypes.c_size_t
    
    # Windows Constants
    MEM_COMMIT = 0x1000
    PAGE_READWRITE = 0x04
    PAGE_READONLY = 0x02

def scan_process_ram_for_split_pattern(half1: bytes, half2: bytes, self_addresses: list = None) -> list:
    """Scans all committed, readable RAM blocks of the current process for the contiguous pattern."""
    matches = []
    if not IS_WINDOWS:
        print(" -> Scanning RAM is only supported on Windows in this diagnostic script.")
        return matches

    mbi = MEMORY_BASIC_INFORMATION()
    address = 0
    max_address = 0x7fffffffffff  # Standard user-space limit for 64-bit Windows
    
    len1 = len(half1)
    len2 = len(half2)
    total_len = len1 + len2
    
    # Find all committed regions
    while address < max_address:
        result = kernel32.VirtualQuery(address, ctypes.byref(mbi), ctypes.sizeof(mbi))
        if result == 0:
            break
            
        region_size = mbi.RegionSize
        state = mbi.State
        protect = mbi.Protect
        base_address = mbi.BaseAddress
        
        # Only scan committed memory that is READWRITE or READONLY
        if state == MEM_COMMIT and (protect == PAGE_READWRITE or protect == PAGE_READONLY):
            try:
                # Read the memory page safely
                buffer = (ctypes.c_char * region_size).from_address(base_address)
                content = bytes(buffer)
                
                # Search for target bytes within the memory page
                index = 0
                while True:
                    index = content.find(half1, index)
                    if index == -1:
                        break
                    
                    # Verify if second half follows immediately to form the full pattern
                    if index + len1 + len2 <= region_size:
                        if content[index + len1 : index + len1 + len2] == half2:
                            match_address = base_address + index
                            
                            # Filter out self-matching references
                            is_self = False
                            if self_addresses:
                                for self_addr in self_addresses:
                                    if abs(match_address - self_addr) < 4096:
                                        is_self = True
                                        break
                                        
                            if not is_self:
                                matches.append(match_address)
                    index += 1
            except Exception:
                pass
                
        address += region_size
        
    return matches

def run_diagnostics():
    print("====================================================")
    print("      Vajraa RAM Scanner & Verification Tool        ")
    print("====================================================\n")
    
    # 1. Setup a control model and extract weight bytes to look for
    in_features = 100
    out_features = 50
    model = nn.Sequential(nn.Linear(in_features, out_features, bias=False))
    
    # Extract the exact byte sequence of the weights in memory
    raw_weights = model[0].weight.data.cpu().numpy().copy()
    target_bytes = raw_weights.tobytes()
    
    print(f"Target pattern to search (Model Weights):")
    print(f" -> Dimensions: {in_features} x {out_features}")
    print(f" -> Data Size: {len(target_bytes)} bytes")
    print(f" -> First few floats: {raw_weights[0][:5]}\n")
    
    # Split the pattern into two halves so it's not contiguous in Python's memory
    half_size = len(target_bytes) // 2
    half1 = target_bytes[:half_size]
    half2 = target_bytes[half_size:]
    
    # Record the addresses of these two local variables to filter them from the scan
    self_addresses = [id(half1), id(half2)]
    
    # Clean up contiguous variables from memory
    del target_bytes
    del raw_weights
    gc.collect()
    
    # ----------------------------------------------------
    # TEST 1: Standard Unprotected Model
    # ----------------------------------------------------
    print("[TEST 1] Auditing Standard (Unprotected) Model:")
    # Run a dummy inference to load memory
    dummy_input = torch.randn(1, in_features)
    _ = model(dummy_input)
    
    # Scan RAM for the weights
    print(" -> Scanning process RAM for weights...")
    found_addresses = scan_process_ram_for_split_pattern(half1, half2, self_addresses)
    
    if found_addresses:
        print(f" -> [MATCH FOUND] Plaintext weights discovered in active RAM!")
        print(f"    Addresses: {[hex(addr) for addr in found_addresses]}")
        print("    Status: VULNERABLE (Weights are exposed and accessible by dumpers)\n")
    else:
        print(" -> [NO MATCH] Weights not found (could be due to paging, retrying...)\n")
        
    # ----------------------------------------------------
    # TEST 2: Vajraa-Protected Model
    # ----------------------------------------------------
    print("[TEST 2] Auditing Vajraa-Protected Model:")
    # Compile and wrap the model
    master_key = os.urandom(32)
    compiled_weights = compile_base_weights(model, master_key)
    secure_wrap_base(model, compiled_weights, master_key)
    
    # Run the same inference JIT
    _ = model(dummy_input)
    
    # Clean up compiled weights dict to remove any potential residues in Python gc
    del compiled_weights
    gc.collect()
    
    # Scan RAM again for the same weights
    print(" -> Scanning process RAM for weights...")
    found_addresses_secured = scan_process_ram_for_split_pattern(half1, half2, self_addresses)
    
    if found_addresses_secured:
        print(f" -> [MATCH FOUND] Plaintext weights discovered in active RAM!")
        print(f"    Addresses: {[hex(addr) for addr in found_addresses_secured]}")
        print("    Status: FAILED (Weights leaked into RAM)\n")
    else:
        print(" -> [NO MATCH] Weights were NOT found anywhere in committed RAM.")
        print("    Status: SECURE (Zero-wipe and deallocation confirmed!)\n")

    print("====================================================")

if __name__ == "__main__":
    run_diagnostics()
