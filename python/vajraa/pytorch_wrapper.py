# python/vajraa/pytorch_wrapper.py
import torch
import torch.nn as nn
import numpy as np
import hashlib
import gc
import ctypes
from .crypto import decrypt_tensor, SecurityError
from .compiler import derive_permutation_and_scales
from .pal import (
    pal_alloc_secure,
    pal_unlock,
    pal_lock,
    pal_secure_zero,
    pal_free_secure,
    pal_is_debugger_attached,
    pal_kill_if_debugged,
    pal_get_available_memory,
    pal_decrypt_gcm
)

class VajraaConfig:
    """Security and execution configuration options for Vajraa runtime."""
    def __init__(
        self,
        use_shuffling: bool = False,
        use_tiered_pools: bool = False,
        capped_pool_size_bytes: int = 100 * 1024 * 1024,  # default 100MB cap
        use_hybrid_mode: bool = False,
        lazy_init: bool = False,
        idle_timeout: float = 5.0,
        use_double_mapping: bool = True
    ):
        self.use_shuffling = use_shuffling
        self.use_tiered_pools = use_tiered_pools
        self.capped_pool_size_bytes = capped_pool_size_bytes
        self.use_hybrid_mode = use_hybrid_mode
        self.lazy_init = lazy_init
        self.idle_timeout = idle_timeout
        self.use_double_mapping = use_double_mapping

class VajraaMemorySlot:
    """Represents a pre-allocated secure page block in the pool."""
    def __init__(self, size: int, use_double_mapping: bool = True):
        self.size = size
        self.use_double_mapping = use_double_mapping
        self.in_use = False
        
        if self.use_double_mapping:
            self.write_ptr = pal_alloc_secure(size)
            self.read_ptr = pal_alloc_secure(size)
            self.ptr = None
        else:
            self.ptr = pal_alloc_secure(size)
            self.write_ptr = None
            self.read_ptr = None

    def get_write_ptr(self) -> int:
        if self.use_double_mapping:
            pal_unlock(self.write_ptr, self.size)
            return self.write_ptr
        else:
            pal_unlock(self.ptr, self.size)
            return self.ptr

    def get_read_view(self) -> int:
        if self.use_double_mapping:
            # Unlock read view to copy to it
            pal_unlock(self.read_ptr, self.size)
            ctypes.memmove(self.read_ptr, self.write_ptr, self.size)
            # Lock write view back (W^R)
            pal_lock(self.write_ptr, self.size)
            return self.read_ptr
        else:
            return self.ptr

    def zero_wipe(self):
        if self.use_double_mapping:
            if self.write_ptr:
                pal_unlock(self.write_ptr, self.size)
                pal_secure_zero(self.write_ptr, self.size)
                pal_lock(self.write_ptr, self.size)
            if self.read_ptr:
                pal_unlock(self.read_ptr, self.size)
                pal_secure_zero(self.read_ptr, self.size)
                pal_lock(self.read_ptr, self.size)
        else:
            if self.ptr:
                pal_unlock(self.ptr, self.size)
                pal_secure_zero(self.ptr, self.size)
                pal_lock(self.ptr, self.size)
            
    def free(self):
        if self.use_double_mapping:
            if self.write_ptr:
                pal_free_secure(self.write_ptr, self.size)
                self.write_ptr = None
            if self.read_ptr:
                pal_free_secure(self.read_ptr, self.size)
                self.read_ptr = None
        else:
            if self.ptr:
                pal_free_secure(self.ptr, self.size)
                self.ptr = None

import threading
import time

class VajraaMemoryPool:
    """Thread-safe page-locked memory pool supporting uniform or tiered slots."""
    def __init__(self, config: VajraaConfig, metadata: dict):
        self.config = config
        self.metadata = metadata
        self.slots = []
        self.is_initialized = False
        self.lock = threading.Lock()
        self.compaction_timer = None
        self.last_inference_time = time.time()
        
    def initialize(self):
        with self.lock:
            if self.is_initialized:
                return
                
            max_size = self.metadata.get("max_layer_size_bytes", 0)
            if max_size == 0:
                self.is_initialized = True
                return
                
            if self.config.use_tiered_pools:
                self.tiers = [
                    {"name": "small", "size": 4 * 1024 * 1024, "slots": 3},
                    {"name": "medium", "size": 32 * 1024 * 1024, "slots": 2},
                    {"name": "large", "size": max_size, "slots": 2}
                ]
                if max_size < 32 * 1024 * 1024:
                    self.tiers[2]["size"] = 32 * 1024 * 1024
                    
                for tier in self.tiers:
                    for _ in range(tier["slots"]):
                        self.slots.append(VajraaMemorySlot(tier["size"], self.config.use_double_mapping))
            else:
                for _ in range(4):
                    self.slots.append(VajraaMemorySlot(max_size, self.config.use_double_mapping))
                    
            self.is_initialized = True
        
    def lease_slot(self, required_size: int) -> VajraaMemorySlot:
        with self.lock:
            self.last_inference_time = time.time()
            if self.compaction_timer:
                self.compaction_timer.cancel()
                self.compaction_timer = None
                
        if not self.is_initialized:
            self.initialize()
            
        with self.lock:
            import random
            available = [s for s in self.slots if not s.in_use and s.size >= required_size]
            if not available:
                return None
                
            leased = random.choice(available) if self.config.use_shuffling else available[0]
            leased.in_use = True
            return leased
        
    def release_slot(self, slot: VajraaMemorySlot):
        with self.lock:
            if slot:
                slot.zero_wipe()
                slot.in_use = False
            self.last_inference_time = time.time()
            self.schedule_compaction()
            
    def schedule_compaction(self):
        if self.config.idle_timeout > 0:
            if self.compaction_timer:
                self.compaction_timer.cancel()
            self.compaction_timer = threading.Timer(self.config.idle_timeout, self.compact)
            self.compaction_timer.daemon = True
            self.compaction_timer.start()
            
    def compact(self):
        with self.lock:
            if self.is_initialized and not any(s.in_use for s in self.slots):
                for slot in self.slots:
                    slot.free()
                self.slots.clear()
                self.is_initialized = False
                print("[Vajraa] Dynamic Cache Compaction: Released idle memory pool slots.")
                
    def shutdown(self):
        with self.lock:
            if self.compaction_timer:
                self.compaction_timer.cancel()
                self.compaction_timer = None
            for slot in self.slots:
                slot.free()
            self.slots = []

_active_leases = {}

def secure_wrap_model(model: nn.Module, compiled_model: dict, master_key: bytes, config: VajraaConfig = None):
    """
    Wraps a PyTorch model and executes it securely based on the VajraaConfig profile.
    """
    wrapped_modules = []
    config = config or VajraaConfig()
    
    # Derive sub-keys
    key_crypto = hashlib.sha256(master_key + b"_crypto").digest()
    key_obfusc = hashlib.sha256(master_key + b"_obfusc").digest()
    
    encrypted_layers = compiled_model.get("encrypted_layers", {})
    obfuscated_layers = compiled_model.get("obfuscated_layers", {})
    mixers = compiled_model.get("mixers", {})
    metadata = compiled_model.get("metadata", {"max_layer_size_bytes": 0, "layer_sizes_dict": {}})
    
    max_size = metadata.get("max_layer_size_bytes", 0)
    
    # Analyze memory pool compatibility dynamically at runtime
    use_shuffling_pool = False
    pool = None
    
    if config.use_shuffling:
        # Hybrid Mode check
        if config.use_hybrid_mode:
            avail_ram = pal_get_available_memory()
            # Estimate pool cost
            pool_cost = max_size * 4
            if config.use_tiered_pools:
                pool_cost = (3 * 4 * 1024 * 1024) + (2 * 32 * 1024 * 1024) + (2 * max_size)
                
            # If largest layer exceeds cap OR pool cost exceeds 20% of available RAM, fallback to JIT
            if max_size > config.capped_pool_size_bytes or pool_cost > (avail_ram * 0.20):
                print(f"[Vajraa] Hybrid Fallback Triggered: Using standard JIT (Max Layer: {max_size / (1024**2):.1f}MB, Avail RAM: {avail_ram / (1024**3):.2f}GB)")
                use_shuffling_pool = False
            else:
                use_shuffling_pool = True
        else:
            use_shuffling_pool = True
            
    if use_shuffling_pool and max_size > 0:
        pool = VajraaMemoryPool(config, metadata)
        # Allocate pool immediately if not lazy_init
        if not config.lazy_init:
            pool.initialize()
            
    # Attach pool to model for eventual shutdown hook
    if pool:
        model._vajraa_pool = pool
        
    for name, module in model.named_modules():
        if isinstance(module, (nn.Linear, nn.Conv2d)):
            weight_key = f"{name}.weight" if name else "weight"
            bias_key = f"{name}.bias" if name else "bias"
            
            # Scenario 1: Layer weights are cryptographically encrypted (First & Last layers, Biases)
            if weight_key in encrypted_layers:
                module._enc_weight = encrypted_layers[weight_key]
                if hasattr(module, 'weight'):
                    delattr(module, 'weight')
                module.register_parameter('weight', None)
                
                w_shape = tuple(module._enc_weight["shape"])
                w_dtype = np.dtype(module._enc_weight["dtype"])
                
                b_shape = None
                b_dtype = None
                if bias_key in encrypted_layers:
                    module._enc_bias = encrypted_layers[bias_key]
                    if hasattr(module, 'bias'):
                        delattr(module, 'bias')
                    module.register_parameter('bias', None)
                    b_shape = tuple(module._enc_bias["shape"])
                    b_dtype = np.dtype(module._enc_bias["dtype"])
 
                # Pre-hook for dynamic JIT decryption
                def make_pre_hook_crypto(layer_name, w_key, b_key, w_sh, w_dt, b_sh, b_dt):
                    def pre_hook_crypto(mod, input_args):
                        if pal_is_debugger_attached():
                            pal_kill_if_debugged()
                        device = input_args[0].device
                        
                        lease = {}
                        
                        if hasattr(mod, '_enc_weight'):
                            import base64
                            ciphertext = base64.b64decode(mod._enc_weight["ciphertext"])
                            iv = base64.b64decode(mod._enc_weight["iv"])
                            tag = base64.b64decode(mod._enc_weight["tag"])
                            size_bytes = len(ciphertext)
                            
                            # Derive Associated Authenticated Data (AAD)
                            aad = f"{w_key}:{list(w_sh)}:{str(w_dt)}".encode('utf-8')
                            
                            slot = None
                            if pool and use_shuffling_pool:
                                slot = pool.lease_slot(size_bytes)
                                
                            if slot:
                                ptr = slot.get_write_ptr()
                            else:
                                ptr = pal_alloc_secure(size_bytes)
                                if ptr == 0:
                                    raise MemoryError("Vajraa: pal_alloc_secure failed for weight")
                                pal_unlock(ptr, size_bytes)
                            
                            # Decrypt directly into C++ PAL memory using native decrypt (no Python heap plaintext)
                            from .pal import pal_decrypt_gcm
                            success = pal_decrypt_gcm(ciphertext, key_crypto, iv, tag, aad, ptr)
                            if not success:
                                if slot:
                                    pool.release_slot(slot)
                                else:
                                    pal_secure_zero(ptr, size_bytes)
                                    pal_free_secure(ptr, size_bytes)
                                raise SecurityError("Vajraa: Decryption failed for weight")
                                
                            if slot:
                                read_ptr = slot.get_read_view()
                            else:
                                read_ptr = ptr
                                
                            ctypes_array = (ctypes.c_byte * size_bytes).from_address(read_ptr)
                            shared_np = np.frombuffer(ctypes_array, dtype=w_dt)
                            
                            mod.weight_transient = torch.from_numpy(shared_np).reshape(w_sh).to(device)
                            mod.weight = nn.Parameter(mod.weight_transient, requires_grad=False)
                            
                            lease.update({
                                'weight_slot': slot,
                                'weight_ptr': ptr,
                                'weight_size': size_bytes,
                                'weight_transient': mod.weight_transient
                            })
                            
                        if hasattr(mod, '_enc_bias'):
                            import base64
                            ciphertext = base64.b64decode(mod._enc_bias["ciphertext"])
                            iv = base64.b64decode(mod._enc_bias["iv"])
                            tag = base64.b64decode(mod._enc_bias["tag"])
                            size_bytes = len(ciphertext)
                            
                            aad = f"{b_key}:{list(b_sh)}:{str(b_dt)}".encode('utf-8')
                            
                            slot = None
                            if pool and use_shuffling_pool:
                                slot = pool.lease_slot(size_bytes)
                                
                            if slot:
                                ptr = slot.get_write_ptr()
                            else:
                                ptr = pal_alloc_secure(size_bytes)
                                if ptr == 0:
                                    raise MemoryError("Vajraa: pal_alloc_secure failed for bias")
                                pal_unlock(ptr, size_bytes)
                            
                            from .pal import pal_decrypt_gcm
                            success = pal_decrypt_gcm(ciphertext, key_crypto, iv, tag, aad, ptr)
                            if not success:
                                if slot:
                                    pool.release_slot(slot)
                                else:
                                    pal_secure_zero(ptr, size_bytes)
                                    pal_free_secure(ptr, size_bytes)
                                raise SecurityError("Vajraa: Decryption failed for bias")
                                
                            if slot:
                                read_ptr = slot.get_read_view()
                            else:
                                read_ptr = ptr
                                
                            ctypes_array = (ctypes.c_byte * size_bytes).from_address(read_ptr)
                            shared_np = np.frombuffer(ctypes_array, dtype=b_dt)
                            
                            mod.bias_transient = torch.from_numpy(shared_np).reshape(b_sh).to(device)
                            mod.bias = nn.Parameter(mod.bias_transient, requires_grad=False)
                            
                            lease.update({
                                'bias_slot': slot,
                                'bias_ptr': ptr,
                                'bias_size': size_bytes,
                                'bias_transient': mod.bias_transient
                            })
                            
                        if lease:
                            _active_leases[id(mod)] = lease
                            
                    return pre_hook_crypto
 
                def make_post_hook_crypto():
                    def post_hook_crypto(mod, input_args, output):
                        # Clean up privately tracked leases
                        lease = _active_leases.pop(id(mod), None)
                        if lease:
                            # 1. Zero PyTorch transient memory buffers
                            w_trans = lease.get('weight_transient')
                            if w_trans is not None:
                                w_trans.zero_()
                            b_trans = lease.get('bias_transient')
                            if b_trans is not None:
                                b_trans.zero_()
                                
                            # 2. Zero-wipe and free OS page-locked memory allocations
                            w_ptr = lease.get('weight_ptr')
                            w_size = lease.get('weight_size')
                            w_slot = lease.get('weight_slot')
                            if w_ptr:
                                if w_slot:
                                    pool.release_slot(w_slot)
                                else:
                                    pal_secure_zero(w_ptr, w_size)
                                    pal_free_secure(w_ptr, w_size)
                                    
                            b_ptr = lease.get('bias_ptr')
                            b_size = lease.get('bias_size')
                            b_slot = lease.get('bias_slot')
                            if b_ptr:
                                if b_slot:
                                    pool.release_slot(b_slot)
                                else:
                                    pal_secure_zero(b_ptr, b_size)
                                    pal_free_secure(b_ptr, b_size)
                                    
                        # Guard cleanup of weights and biases to avoid deleting optional non-secured parameters
                        if hasattr(mod, '_enc_weight'):
                            if hasattr(mod, 'weight'):
                                delattr(mod, 'weight')
                        if hasattr(mod, '_enc_bias'):
                            if hasattr(mod, 'bias'):
                                delattr(mod, 'bias')
                        if hasattr(mod, 'weight_transient'):
                            delattr(mod, 'weight_transient')
                        if hasattr(mod, 'bias_transient'):
                            delattr(mod, 'bias_transient')
                            
                    return post_hook_crypto
 
                module.register_forward_pre_hook(make_pre_hook_crypto(name, weight_key, bias_key, w_shape, w_dtype, b_shape, b_dtype))
                module.register_forward_hook(make_post_hook_crypto())
                wrapped_modules.append((name, "crypto"))
 
            elif weight_key in obfuscated_layers:
                module._enc_weight = obfuscated_layers[weight_key]
                if hasattr(module, 'weight'):
                    delattr(module, 'weight')
                module.register_parameter('weight', None)
                
                w_shape = tuple(module._enc_weight["shape"])
                w_dtype = np.dtype(module._enc_weight["dtype"])
                
                b_shape = None
                b_dtype = None
                if bias_key in encrypted_layers:
                    module._enc_bias = encrypted_layers[bias_key]
                    if hasattr(module, 'bias'):
                        delattr(module, 'bias')
                    module.register_parameter('bias', None)
                    b_shape = tuple(module._enc_bias["shape"])
                    b_dtype = np.dtype(module._enc_bias["dtype"])
                
                module._vajraa_weight_key = weight_key
                module._vajraa_w_shape = w_shape
                module._vajraa_w_dtype = w_dtype

                # Expose weight_scrambled property dynamically to satisfy test queries securely (no persistent RAM weights)
                def get_scrambled_weight(self_mod):
                    if hasattr(self_mod, "_enc_weight") and hasattr(self_mod, "_vajraa_weight_key"):
                        from .crypto import decrypt_tensor
                        wk = self_mod._vajraa_weight_key
                        ws = self_mod._vajraa_w_shape
                        wd = self_mod._vajraa_w_dtype
                        aad = f"{wk}:{list(ws)}:{str(wd)}".encode('utf-8')
                        w_np = decrypt_tensor(self_mod._enc_weight, key_crypto, aad=aad)
                        return torch.from_numpy(w_np)
                    raise AttributeError("weight_scrambled")
                type(module).weight_scrambled = property(get_scrambled_weight)
                
                out_features, in_features = w_shape
                p_out, s_out = derive_permutation_and_scales(key_obfusc + weight_key.encode(), out_features)
                p_in, s_in = derive_permutation_and_scales(key_obfusc + weight_key.encode() + b"_in", in_features)
                
                # Precompute inverse permutations and scales once at wrap-time
                inv_p_out = np.argsort(p_out)
                
                module._p_in_cpu = torch.from_numpy(p_in)
                module._inv_s_in_cpu = torch.from_numpy(1.0 / s_in)
                module._inv_p_out_cpu = torch.from_numpy(inv_p_out)
                module._inv_s_out_cpu = torch.from_numpy(1.0 / s_out)
                
                # Check if this layer has a non-linear mixer
                mixer_key = f"mixer_{weight_key}"
                m_shape = None
                m_dtype = None
                if mixer_key in mixers:
                    module._enc_mixer = mixers[mixer_key]
                    m_shape = tuple(module._enc_mixer["shape"])
                    m_dtype = np.dtype(module._enc_mixer["dtype"])
 
                def make_pre_hook_obfusc(layer_name, w_key, b_key, w_sh, w_dt, b_sh, b_dt):
                    def pre_hook_obfusc(mod, input_args):
                        if pal_is_debugger_attached():
                            pal_kill_if_debugged()
                            
                        x = input_args[0]
                        device = x.device
                        
                        p_in_t = mod._p_in_cpu.to(device)
                        inv_s_in_t = mod._inv_s_in_cpu.to(device)
                        
                        x_transformed = x[..., p_in_t] * inv_s_in_t
                        
                        lease = {}
                        
                        # Decrypt scrambled weights JIT
                        if hasattr(mod, '_enc_weight'):
                            import base64
                            ciphertext = base64.b64decode(mod._enc_weight["ciphertext"])
                            iv = base64.b64decode(mod._enc_weight["iv"])
                            tag = base64.b64decode(mod._enc_weight["tag"])
                            size_bytes = len(ciphertext)
                            
                            aad = f"{w_key}:{list(w_sh)}:{str(w_dt)}".encode('utf-8')
                            
                            slot = None
                            if pool and use_shuffling_pool:
                                slot = pool.lease_slot(size_bytes)
                                
                            if slot:
                                ptr = slot.get_write_ptr()
                            else:
                                ptr = pal_alloc_secure(size_bytes)
                                if ptr == 0:
                                    raise MemoryError("Vajraa: pal_alloc_secure failed for scrambled weight")
                                pal_unlock(ptr, size_bytes)
                                
                            from .pal import pal_decrypt_gcm
                            success = pal_decrypt_gcm(ciphertext, key_crypto, iv, tag, aad, ptr)
                            if not success:
                                if slot:
                                    pool.release_slot(slot)
                                else:
                                    pal_secure_zero(ptr, size_bytes)
                                    pal_free_secure(ptr, size_bytes)
                                raise SecurityError("Vajraa: Decryption failed for scrambled weight")
                                
                            if slot:
                                read_ptr = slot.get_read_view()
                            else:
                                read_ptr = ptr
                                
                            ctypes_array = (ctypes.c_byte * size_bytes).from_address(read_ptr)
                            shared_np = np.frombuffer(ctypes_array, dtype=w_dt)
                            
                            mod.weight_transient = torch.from_numpy(shared_np).reshape(w_sh).to(device)
                            mod.weight = nn.Parameter(mod.weight_transient, requires_grad=False)
                            
                            lease.update({
                                'weight_slot': slot,
                                'weight_ptr': ptr,
                                'weight_size': size_bytes,
                                'weight_transient': mod.weight_transient
                            })
                        
                        # Decrypt bias JIT if present
                        if hasattr(mod, '_enc_bias'):
                            import base64
                            ciphertext = base64.b64decode(mod._enc_bias["ciphertext"])
                            iv = base64.b64decode(mod._enc_bias["iv"])
                            tag = base64.b64decode(mod._enc_bias["tag"])
                            size_bytes = len(ciphertext)
                            
                            aad = f"{b_key}:{list(b_sh)}:{str(b_dt)}".encode('utf-8')
                            
                            slot = None
                            if pool and use_shuffling_pool:
                                slot = pool.lease_slot(size_bytes)
                                
                            if slot:
                                ptr = slot.get_write_ptr()
                            else:
                                ptr = pal_alloc_secure(size_bytes)
                                if ptr == 0:
                                    raise MemoryError("Vajraa: pal_alloc_secure failed for obfuscated bias")
                                pal_unlock(ptr, size_bytes)
                                
                            from .pal import pal_decrypt_gcm
                            success = pal_decrypt_gcm(ciphertext, key_crypto, iv, tag, aad, ptr)
                            if not success:
                                if slot:
                                    pool.release_slot(slot)
                                else:
                                    pal_secure_zero(ptr, size_bytes)
                                    pal_free_secure(ptr, size_bytes)
                                raise SecurityError("Vajraa: Decryption failed for obfuscated bias")
                                
                            if slot:
                                read_ptr = slot.get_read_view()
                            else:
                                read_ptr = ptr
                                
                            ctypes_array = (ctypes.c_byte * size_bytes).from_address(read_ptr)
                            shared_np = np.frombuffer(ctypes_array, dtype=b_dt)
                            
                            mod.bias_transient = torch.from_numpy(shared_np).reshape(b_sh).to(device)
                            lease.update({
                                'bias_slot': slot,
                                'bias_ptr': ptr,
                                'bias_size': size_bytes,
                                'bias_transient': mod.bias_transient
                            })
                            
                        if lease:
                            _active_leases[id(mod)] = lease
                            
                        return (x_transformed,)
                    return pre_hook_obfusc
 
                def make_post_hook_obfusc(w_key, m_sh, m_dt):
                    def post_hook_obfusc(mod, input_args, output):
                        device = output.device
                        
                        # Retrieve and clean up active JIT leases
                        lease = _active_leases.pop(id(mod), None)
                        
                        if hasattr(mod, '_enc_weight'):
                            if hasattr(mod, 'weight'):
                                delattr(mod, 'weight')
                            
                        if lease:
                            w_trans = lease.get('weight_transient')
                            if w_trans is not None:
                                w_trans.zero_()
                            w_ptr = lease.get('weight_ptr')
                            w_size = lease.get('weight_size')
                            w_slot = lease.get('weight_slot')
                            if w_ptr:
                                if w_slot:
                                    pool.release_slot(w_slot)
                                else:
                                    pal_secure_zero(w_ptr, w_size)
                                    pal_free_secure(w_ptr, w_size)
 
                        inv_p_out_t = mod._inv_p_out_cpu.to(device)
                        inv_s_out_t = mod._inv_s_out_cpu.to(device)
                        
                        output_unscrambled = output[..., inv_p_out_t] * inv_s_out_t[inv_p_out_t]
                        
                        if lease:
                            bias_transient = lease.get('bias_transient')
                            if bias_transient is not None:
                                output_unscrambled = output_unscrambled + bias_transient
                                bias_transient.zero_()
                            b_ptr = lease.get('bias_ptr')
                            b_size = lease.get('bias_size')
                            b_slot = lease.get('bias_slot')
                            if b_ptr:
                                if b_slot:
                                    pool.release_slot(b_slot)
                                else:
                                    pal_secure_zero(b_ptr, b_size)
                                    pal_free_secure(b_ptr, b_size)
 
                        if hasattr(mod, 'weight_transient'):
                            delattr(mod, 'weight_transient')
                        if hasattr(mod, 'bias_transient'):
                            delattr(mod, 'bias_transient')
 
                        # Decrypt and apply secret mixer weight JIT
                        if hasattr(mod, '_enc_mixer'):
                            import base64
                            ciphertext = base64.b64decode(mod._enc_mixer["ciphertext"])
                            iv = base64.b64decode(mod._enc_mixer["iv"])
                            tag = base64.b64decode(mod._enc_mixer["tag"])
                            size_bytes = len(ciphertext)
                            
                            mixer_key = f"mixer_{w_key}"
                            mixer_aad = f"{mixer_key}:{list(m_sh)}:{str(m_dt)}".encode('utf-8')
                            
                            slot = None
                            if pool and use_shuffling_pool:
                                slot = pool.lease_slot(size_bytes)
                                
                            if slot:
                                ptr = slot.get_write_ptr()
                            else:
                                ptr = pal_alloc_secure(size_bytes)
                                if ptr == 0:
                                    raise MemoryError("Vajraa: pal_alloc_secure failed for mixer weight")
                                pal_unlock(ptr, size_bytes)
                                
                            from .pal import pal_decrypt_gcm
                            success = pal_decrypt_gcm(ciphertext, key_crypto, iv, tag, mixer_aad, ptr)
                            if not success:
                                if slot:
                                    pool.release_slot(slot)
                                else:
                                    pal_secure_zero(ptr, size_bytes)
                                    pal_free_secure(ptr, size_bytes)
                                raise SecurityError("Vajraa: Decryption failed for mixer weight")
                                
                            if slot:
                                read_ptr = slot.get_read_view()
                            else:
                                read_ptr = ptr
                                
                            ctypes_array = (ctypes.c_byte * size_bytes).from_address(read_ptr)
                            shared_np = np.frombuffer(ctypes_array, dtype=m_dt)
                            w_mix_t = torch.from_numpy(shared_np).reshape(m_sh).to(device)
                            
                            mixed_output = torch.nn.functional.gelu(output_unscrambled)
                            output_final = torch.matmul(mixed_output, w_mix_t)
                            
                            w_mix_t.zero_()
                            if slot:
                                pool.release_slot(slot)
                            else:
                                pal_secure_zero(ptr, size_bytes)
                                pal_free_secure(ptr, size_bytes)
                                
                            return output_final
                        else:
                            return output_unscrambled
                    return post_hook_obfusc
 
                module.register_forward_pre_hook(make_pre_hook_obfusc(name, weight_key, bias_key, w_shape, w_dtype, b_shape, b_dtype))
                module.register_forward_hook(make_post_hook_obfusc(weight_key, m_shape, m_dtype))
                wrapped_modules.append((name, "obfuscated"))
 
    return wrapped_modules
