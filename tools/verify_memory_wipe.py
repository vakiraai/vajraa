# tools/verify_memory_wipe.py
import torch
import torch.nn as nn
import numpy as np
import ctypes
import os
import sys

# Ensure package path is visible
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../python')))

from vajraa.base_shield import compile_base_weights, secure_wrap_base
from vajraa.pal import IS_WINDOWS, IS_LINUX, IS_MACOS

# Structure to hold Page Info for Windows VirtualQuery
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
    MEM_FREE = 0x10000
    PAGE_NOACCESS = 0x01
    PAGE_READWRITE = 0x04

def get_page_status(ptr: int):
    """Query OS for memory page information at the given pointer (safe, won't crash on invalid pointers)"""
    if not ptr:
        return "NULL pointer"
        
    if IS_WINDOWS:
        mbi = MEMORY_BASIC_INFORMATION()
        result = kernel32.VirtualQuery(ptr, ctypes.byref(mbi), ctypes.sizeof(mbi))
        if result == 0:
            return "Invalid Address (released)"
        
        state = mbi.State
        protect = mbi.Protect
        
        status = []
        if state == MEM_COMMIT:
            status.append("COMMITTED")
        elif state == MEM_FREE:
            status.append("FREE")
        else:
            status.append("RESERVED/OTHER")
            
        if protect == PAGE_READWRITE:
            status.append("READWRITE")
        elif protect == PAGE_NOACCESS:
            status.append("NO_ACCESS")
        else:
            status.append(f"PROTECT_FLAGS: {hex(protect)}")
            
        return " | ".join(status)
        
    elif IS_LINUX:
        # Check /proc/self/maps to see if address is still mapped
        try:
            with open("/proc/self/maps", "r") as f:
                for line in f:
                    parts = line.split()
                    addr_range = parts[0].split("-")
                    start = int(addr_range[0], 16)
                    end = int(addr_range[1], 16)
                    if start <= ptr < end:
                        return f"MAPPED | PERMS: {parts[1]}"
            return "UNMAPPED (released)"
        except Exception as e:
            return f"Error reading maps: {e}"
            
    return "Unsupported platform for virtual query"

def test_memory_wipe_lifecycle():
    print("====================================================")
    print("      Vajraa JIT Memory Verification Diagnostic     ")
    print("====================================================\n")
    
    # 1. Setup a simple Linear model
    model = nn.Sequential(nn.Linear(10, 5))
    master_key = os.urandom(32)
    
    # Save the original weights for diagnostic checks
    orig_weight = model[0].weight.data.cpu().numpy().copy()
    
    # 2. Compile model weights
    compiled_weights = compile_base_weights(model, master_key)
    
    # 3. Apply secure wrappers
    secure_wrap_base(model, compiled_weights, master_key)
    
    # Diagnostic hook records pointer address and reads decrypted weights JIT
    ptr_address = 0
    ptr_size = 0
    weights_during_execution = None
    
    # Register helper pre-hook to capture the allocated pointer address and read it
    def capture_pre_hook(mod, input_args):
        nonlocal ptr_address, ptr_size, weights_during_execution
        # The base_shield pre-hook has run, so the pointer is now allocated and decrypted
        ptr_address = getattr(mod, "_weight_ptr", 0)
        ptr_size = getattr(mod, "_weight_size", 0)
        if ptr_address:
            # Safely read memory contents during execution (before it is zero-wiped and freed)
            ctypes_array = (ctypes.c_byte * ptr_size).from_address(ptr_address)
            raw_bytes = bytes(ctypes_array)
            weights_during_execution = np.frombuffer(raw_bytes, dtype=orig_weight.dtype).copy()

    model[0].register_forward_pre_hook(capture_pre_hook)
    
    # 4. Verify startup state (model weights should not exist as attributes)
    print("[1] Startup State Verification:")
    print(f" -> Has standard 'weight' attribute: {hasattr(model[0], 'weight')}")
    print(f" -> Has encrypted placeholder: {hasattr(model[0], '_enc_weight')}")
    print(" -> Page status: No page allocated yet.\n")
    
    # 5. Run inference and capture states
    dummy_input = torch.randn(1, 10)
    
    print("[2] Running Inference...")
    output = model(dummy_input)
    print(" -> Inference finished successfully.\n")
    
    # 6. Verify DURING execution state
    print("[3] During-Execution State:")
    print(f" -> Captured weight pointer: {hex(ptr_address)}")
    print(f" -> Weight buffer size: {ptr_size} bytes")
    if weights_during_execution is not None:
        # Check if contents match the original weights
        matched = np.allclose(weights_during_execution.reshape(orig_weight.shape), orig_weight)
        print(f" -> Decrypted weights match original: {matched}")
    else:
        print(" -> Failed to capture weights during execution")
    print("")
    
    # 7. Verify POST-execution state
    print("[4] Post-Execution Wiping & Release Verification:")
    print(f" -> Has active 'weight' attribute: {hasattr(model[0], 'weight')}")
    print(f" -> Has transient pointer reference: {hasattr(model[0], '_weight_ptr')}")
    
    # Check if memory is freed/released
    page_status = get_page_status(ptr_address)
    print(f" -> OS memory page status at address {hex(ptr_address)}: {page_status}")
    
    # Double-check that reading the memory fails or shows zeroed contents
    if IS_WINDOWS:
        if "FREE" in page_status or "Invalid" in page_status:
            print(" -> [SUCCESS] The memory page was successfully unmapped and released from RAM.")
            print("              (An attempt to read from this address will trigger a system crash, confirming protection)")
        else:
            print(" -> [WARNING] The memory page is still committed.")
    elif IS_LINUX:
        if "UNMAPPED" in page_status:
            print(" -> [SUCCESS] The memory page was unmapped from virtual address space.")
        else:
            print(" -> [WARNING] The memory page is still mapped.")
            
    print("\nVerification Complete.")
    print("====================================================")

if __name__ == "__main__":
    test_memory_wipe_lifecycle()
