# python/model_shield/pal.py
import sys
import ctypes
import os

# Platform detection
IS_WINDOWS = sys.platform.startswith("win")
IS_LINUX = sys.platform.startswith("linux")
IS_MACOS = sys.platform.startswith("darwin")

_vajraa_dll = None
possible_dll_paths = [
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../build/Release/vajraa.dll")),
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../build/vajraa.dll")),
    os.path.abspath(os.path.join(os.path.dirname(__file__), "vajraa.dll")),
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../build/Release/libvajraa.so")),
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../build/libvajraa.so")),
    os.path.abspath(os.path.join(os.path.dirname(__file__), "libvajraa.so")),
]
for path in possible_dll_paths:
    if os.path.exists(path):
        try:
            _vajraa_dll = ctypes.CDLL(path)
            _vajraa_dll.pal_secure_zero.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            _vajraa_dll.pal_secure_zero.restype = None
            break
        except Exception:
            pass

# Ctypes setups
if IS_WINDOWS:
    from ctypes import wintypes
    kernel32 = ctypes.windll.kernel32
    crypt32 = ctypes.windll.crypt32
    
    # Constants
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    MEM_RELEASE = 0x8000
    PAGE_NOACCESS = 0x01
    PAGE_READWRITE = 0x04
    CRYPTPROTECTMEMORY_SAME_PROCESS = 0x00
    
    # Types configuration
    kernel32.VirtualAlloc.restype = ctypes.c_void_p
    kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
    
    kernel32.VirtualProtect.restype = wintypes.BOOL
    kernel32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    
    kernel32.VirtualFree.restype = wintypes.BOOL
    kernel32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD]
    
    crypt32.CryptProtectMemory.restype = wintypes.BOOL
    crypt32.CryptProtectMemory.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
    
    crypt32.CryptUnprotectMemory.restype = wintypes.BOOL
    crypt32.CryptUnprotectMemory.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]

elif IS_LINUX or IS_MACOS:
    # Load standard libc
    libc = ctypes.CDLL(None)
    
    # Constants
    MAP_PRIVATE = 0x02
    MAP_ANONYMOUS = 0x20 if IS_LINUX else 0x1000
    PROT_NONE = 0x00
    PROT_READ = 0x01
    PROT_WRITE = 0x02
    
    libc.mmap.restype = ctypes.c_void_p
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
    
    libc.mprotect.restype = ctypes.c_int
    libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    
    libc.munmap.restype = ctypes.c_int
    libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]

# ==========================================
# 1. Secure Memory Allocation & Protection
# ==========================================

def pal_alloc_secure(size: int) -> int:
    """
    Allocates secure memory page and sets it to PAGE_NOACCESS.
    Returns memory address (int) or 0 on failure.
    """
    if IS_WINDOWS:
        ptr = kernel32.VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS)
        return ptr if ptr else 0
    elif IS_LINUX or IS_MACOS:
        ptr = libc.mmap(None, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
        return ptr if ptr != -1 else 0
    return 0

def pal_unlock(ptr: int, size: int) -> bool:
    """
    Sets memory page to READWRITE.
    """
    if ptr == 0:
        return False
    if IS_WINDOWS:
        old_protect = wintypes.DWORD(0)
        return bool(kernel32.VirtualProtect(ptr, size, PAGE_READWRITE, ctypes.byref(old_protect)))
    elif IS_LINUX or IS_MACOS:
        return libc.mprotect(ptr, size, PROT_READ | PROT_WRITE) == 0
    return False

def pal_lock(ptr: int, size: int) -> bool:
    """
    Restores memory page to NOACCESS.
    """
    if ptr == 0:
        return False
    if IS_WINDOWS:
        old_protect = wintypes.DWORD(0)
        return bool(kernel32.VirtualProtect(ptr, size, PAGE_NOACCESS, ctypes.byref(old_protect)))
    elif IS_LINUX or IS_MACOS:
        return libc.mprotect(ptr, size, PROT_NONE) == 0
    return False

def pal_secure_zero(ptr: int, size: int):
    """
    Securely zeroes out a memory region.
    """
    if ptr != 0 and size > 0:
        if _vajraa_dll is not None:
            try:
                _vajraa_dll.pal_secure_zero(ctypes.c_void_p(ptr), ctypes.c_size_t(size))
                return
            except Exception:
                pass
        ctypes.memset(ptr, 0, size)

def pal_free_secure(ptr: int, size: int):
    """
    Frees secure allocated page.
    """
    if ptr != 0:
        if IS_WINDOWS:
            kernel32.VirtualFree(ptr, 0, MEM_RELEASE)
        elif IS_LINUX or IS_MACOS:
            libc.munmap(ptr, size)

# ==========================================
# 2. Anti-Debugging
# ==========================================

def pal_is_debugger_attached() -> bool:
    """
    Check if a debugger is attached using native OS calls.
    """
    if IS_WINDOWS:
        if kernel32.IsDebuggerPresent():
            return True
        is_remote = wintypes.BOOL(False)
        if kernel32.CheckRemoteDebuggerPresent(kernel32.GetCurrentProcess(), ctypes.byref(is_remote)):
            if is_remote:
                return True
    elif IS_LINUX:
        try:
            with open("/proc/self/status", "r") as f:
                for line in f:
                    if line.startswith("TracerPid:"):
                        pid = int(line.split()[1])
                        if pid != 0:
                            return True
        except Exception:
            pass
    return False

def pal_kill_if_debugged():
    """
    Terminates the process instantly.
    """
    if IS_WINDOWS:
        kernel32.ExitProcess(0xC0000005)
    else:
        os._exit(1)

# ==========================================
# 3. Secure Key Storage (DPAPI/XOR Fallbacks)
# ==========================================

# Buffer for encrypted key storage
_encrypted_key_buf = None
_original_key_len = 0
_aligned_key_len = 0

def pal_store_key(key: bytes) -> bool:
    """
    Stores key in memory encrypted via DPAPI (Windows) or XOR-obfuscation (Linux/macOS).
    """
    global _encrypted_key_buf, _original_key_len, _aligned_key_len
    len_key = len(key)
    if len_key == 0:
        return False
        
    _original_key_len = len_key
    
    if IS_WINDOWS:
        # Align to 16-byte boundary for DPAPI
        _aligned_key_len = ((len_key + 15) // 16) * 16
        
        # Create ctypes buffer and copy key bytes
        buf = ctypes.create_string_buffer(_aligned_key_len)
        ctypes.memmove(buf, key, len_key)
        
        # Encrypt in memory
        success = crypt32.CryptProtectMemory(buf, _aligned_key_len, CRYPTPROTECTMEMORY_SAME_PROCESS)
        if success:
            _encrypted_key_buf = buf
            return True
    else:
        # XOR fallback
        _aligned_key_len = len_key
        share1 = os.urandom(len_key)
        share2 = bytes(a ^ b for a, b in zip(key, share1))
        _encrypted_key_buf = (share1, share2)
        return True
    return False

def pal_retrieve_key() -> bytes:
    """
    Retrieves key decrypted from memory storage.
    """
    global _encrypted_key_buf, _original_key_len, _aligned_key_len
    if _encrypted_key_buf is None:
        return b""
        
    if IS_WINDOWS:
        # Create temp buffer copy to avoid corrupting static storage on decrypt
        temp_buf = ctypes.create_string_buffer(_aligned_key_len)
        ctypes.memmove(temp_buf, _encrypted_key_buf, _aligned_key_len)
        
        # Decrypt
        success = crypt32.CryptUnprotectMemory(temp_buf, _aligned_key_len, CRYPTPROTECTMEMORY_SAME_PROCESS)
        if success:
            decrypted = bytearray(temp_buf.raw[:_original_key_len])
            # Zero out temp stack copy
            ctypes.memset(temp_buf, 0, _aligned_key_len)
            return decrypted
    else:
        # XOR fallback
        share1, share2 = _encrypted_key_buf
        return bytearray(a ^ b for a, b in zip(share1, share2))
    return bytearray()
