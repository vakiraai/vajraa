# python/vajraa/pytorch_wrapper.py
import torch
import torch.nn as nn
import numpy as np
import hashlib
import gc
import ctypes
from .crypto import decrypt_tensor
from .compiler import derive_permutation_and_scales
from .pal import (
    pal_alloc_secure,
    pal_unlock,
    pal_lock,
    pal_secure_zero,
    pal_free_secure,
    pal_is_debugger_attached,
    pal_kill_if_debugged,
    pal_get_available_memory
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
            self.is_initialized = False

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
                
                if bias_key in encrypted_layers:
                    module._enc_bias = encrypted_layers[bias_key]
                    if hasattr(module, 'bias'):
                        delattr(module, 'bias')
                    module.register_parameter('bias', None)
 
                # Pre-hook for dynamic JIT decryption
                def make_pre_hook_crypto():
                    def pre_hook_crypto(mod, input_args):
                        if pal_is_debugger_attached():
                            pal_kill_if_debugged()
                        device = input_args[0].device
                        
                        if hasattr(mod, '_enc_weight'):
                            w_np = decrypt_tensor(mod._enc_weight, key_crypto)
                            size_bytes = w_np.nbytes
                            
                            # Lease slot from pool if active, else standard dynamic allocation
                            slot = None
                            if pool and use_shuffling_pool:
                                slot = pool.lease_slot(size_bytes)
                                
                            if slot:
                                ptr = slot.get_write_ptr()
                                mod._weight_slot = slot
                            else:
                                ptr = pal_alloc_secure(size_bytes)
                                if ptr == 0:
                                    raise MemoryError("Vajraa: pal_alloc_secure failed for weight")
                                pal_unlock(ptr, size_bytes)
                                mod._weight_slot = None
                            
                            # Load into page buffer and share with torch
                            if slot:
                                read_ptr = slot.get_read_view()
                            else:
                                read_ptr = ptr
                                
                            ctypes_array = (ctypes.c_byte * size_bytes).from_address(read_ptr)
                            ctypes.memmove(ctypes_array, w_np.ctypes.data, size_bytes)
                            shared_np = np.frombuffer(ctypes_array, dtype=w_np.dtype)
                            
                            mod.weight_transient = torch.from_numpy(shared_np).reshape(w_np.shape).to(device)
                            mod.weight = nn.Parameter(mod.weight_transient, requires_grad=False)
                            mod._weight_ptr = ptr
                            mod._weight_size = size_bytes
                            
                        if hasattr(mod, '_enc_bias'):
                            b_np = decrypt_tensor(mod._enc_bias, key_crypto)
                            size_bytes = b_np.nbytes
                            
                            slot = None
                            if pool and use_shuffling_pool:
                                slot = pool.lease_slot(size_bytes)
                                
                            if slot:
                                ptr = slot.get_write_ptr()
                                mod._bias_slot = slot
                            else:
                                ptr = pal_alloc_secure(size_bytes)
                                if ptr == 0:
                                    raise MemoryError("Vajraa: pal_alloc_secure failed for bias")
                                pal_unlock(ptr, size_bytes)
                                mod._bias_slot = None
                            
                            if slot:
                                read_ptr = slot.get_read_view()
                            else:
                                read_ptr = ptr
                                
                            ctypes_array = (ctypes.c_byte * size_bytes).from_address(read_ptr)
                            ctypes.memmove(ctypes_array, b_np.ctypes.data, size_bytes)
                            shared_np = np.frombuffer(ctypes_array, dtype=b_np.dtype)
                            
                            mod.bias_transient = torch.from_numpy(shared_np).reshape(b_np.shape).to(device)
                            mod.bias = nn.Parameter(mod.bias_transient, requires_grad=False)
                            mod._bias_ptr = ptr
                            mod._bias_size = size_bytes
                    return pre_hook_crypto
 
                def make_post_hook_crypto():
                    def post_hook_crypto(mod, input_args, output):
                        # 1. Zero PyTorch transient buffers first
                        if hasattr(mod, 'weight_transient'):
                            mod.weight_transient.zero_()
                        if hasattr(mod, 'bias_transient'):
                            mod.bias_transient.zero_()
                            
                        # 2. Zero and free secure OS allocations (handling slots vs standard JIT)
                        if hasattr(mod, '_weight_ptr'):
                            slot = getattr(mod, '_weight_slot', None)
                            if slot:
                                pool.release_slot(slot)
                                delattr(mod, '_weight_slot')
                            else:
                                pal_secure_zero(mod._weight_ptr, mod._weight_size)
                                pal_free_secure(mod._weight_ptr, mod._weight_size)
                            delattr(mod, '_weight_ptr')
                            delattr(mod, '_weight_size')
                            
                        if hasattr(mod, '_bias_ptr'):
                            slot = getattr(mod, '_bias_slot', None)
                            if slot:
                                pool.release_slot(slot)
                                delattr(mod, '_bias_slot')
                            else:
                                pal_secure_zero(mod._bias_ptr, mod._bias_size)
                                pal_free_secure(mod._bias_ptr, mod._bias_size)
                            delattr(mod, '_bias_ptr')
                            delattr(mod, '_bias_size')
                            
                        # 3. Clean up references
                        if hasattr(mod, 'weight_transient'):
                            if hasattr(mod, 'weight'):
                                delattr(mod, 'weight')
                            del mod.weight_transient
                        if hasattr(mod, 'bias_transient'):
                            if hasattr(mod, 'bias'):
                                delattr(mod, 'bias')
                            del mod.bias_transient
                        gc.collect()
                    return post_hook_crypto
 
                module.register_forward_pre_hook(make_pre_hook_crypto())
                module.register_forward_hook(make_post_hook_crypto())
                wrapped_modules.append((name, "crypto"))
 
            elif weight_key in obfuscated_layers:
                obf_data = obfuscated_layers[weight_key]
                w_scrambled = decrypt_tensor(obf_data, key_crypto)
                
                # Delete standard parameter and load the scrambled weights directly into RAM
                if hasattr(module, 'weight'):
                    delattr(module, 'weight')
                module.weight_scrambled = nn.Parameter(torch.from_numpy(w_scrambled), requires_grad=False)
                module.register_parameter('weight', None)
                
                # Check and intercept bias parameters for obfuscated layers
                if bias_key in encrypted_layers:
                    module._enc_bias = encrypted_layers[bias_key]
                    if hasattr(module, 'bias'):
                        delattr(module, 'bias')
                    module.register_parameter('bias', None)
                
                # Store references to permutations and scaling factors
                if len(w_scrambled.shape) != 2:
                    raise ValueError(f"Vajraa: Obfuscation only supported for 2D weights, got shape {w_scrambled.shape}")
                out_features, in_features = w_scrambled.shape
                p_out, s_out = derive_permutation_and_scales(key_obfusc + weight_key.encode(), out_features)
                p_in, s_in = derive_permutation_and_scales(key_obfusc + weight_key.encode() + b"_in", in_features)
                
                module._p_out = p_out
                module._s_out = s_out
                module._p_in = p_in
                module._s_in = s_in
                
                # Check if this layer has a non-linear mixer
                mixer_key = f"mixer_{weight_key}"
                if mixer_key in mixers:
                    module._enc_mixer = mixers[mixer_key]
 
                def make_pre_hook_obfusc():
                    def pre_hook_obfusc(mod, input_args):
                        if pal_is_debugger_attached():
                            pal_kill_if_debugged()
                            
                        x = input_args[0]
                        device = x.device
                        
                        p_in_t = torch.from_numpy(mod._p_in).to(device)
                        inv_s_in_t = torch.from_numpy(1.0 / mod._s_in).to(device)
                        
                        x_transformed = x[..., p_in_t] * inv_s_in_t
                        
                        if hasattr(mod, '_enc_bias'):
                            b_np = decrypt_tensor(mod._enc_bias, key_crypto)
                            size_bytes = b_np.nbytes
                            
                            slot = None
                            if pool and use_shuffling_pool:
                                slot = pool.lease_slot(size_bytes)
                                
                            if slot:
                                ptr = slot.get_write_ptr()
                                mod._bias_slot = slot
                            else:
                                ptr = pal_alloc_secure(size_bytes)
                                if ptr == 0:
                                    raise MemoryError("Vajraa: pal_alloc_secure failed for obfuscated bias")
                                pal_unlock(ptr, size_bytes)
                                mod._bias_slot = None
                            
                            if slot:
                                read_ptr = slot.get_read_view()
                            else:
                                read_ptr = ptr
                                
                            ctypes_array = (ctypes.c_byte * size_bytes).from_address(read_ptr)
                            ctypes.memmove(ctypes_array, b_np.ctypes.data, size_bytes)
                            shared_np = np.frombuffer(ctypes_array, dtype=b_np.dtype)
                            
                            mod.bias_transient = torch.from_numpy(shared_np).reshape(b_np.shape).to(device)
                            mod._bias_ptr = ptr
                            mod._bias_size = size_bytes
                        
                        mod.weight = mod.weight_scrambled
                        return (x_transformed,)
                    return pre_hook_obfusc
 
                def make_post_hook_obfusc():
                    def post_hook_obfusc(mod, input_args, output):
                        device = output.device
                        
                        if hasattr(mod, 'weight'):
                            delattr(mod, 'weight')
                        
                        inv_p_out = np.argsort(mod._p_out)
                        inv_p_out_t = torch.from_numpy(inv_p_out).to(device)
                        inv_s_out_t = torch.from_numpy(1.0 / mod._s_out).to(device)
                        
                        output_unscrambled = output[..., inv_p_out_t] * inv_s_out_t[inv_p_out_t]
                        
                        if hasattr(mod, 'bias_transient'):
                            output_unscrambled = output_unscrambled + mod.bias_transient
                            mod.bias_transient.zero_()
                            
                            slot = getattr(mod, '_bias_slot', None)
                            if slot:
                                pool.release_slot(slot)
                                delattr(mod, '_bias_slot')
                            else:
                                pal_secure_zero(mod._bias_ptr, mod._bias_size)
                                pal_free_secure(mod._bias_ptr, mod._bias_size)
                            delattr(mod, 'bias_transient')
                            delattr(mod, '_bias_ptr')
                            delattr(mod, '_bias_size')
                        
                        if hasattr(mod, '_enc_mixer'):
                            w_mix = decrypt_tensor(mod._enc_mixer, key_crypto)
                            size_bytes = w_mix.nbytes
                            
                            slot = None
                            if pool and use_shuffling_pool:
                                slot = pool.lease_slot(size_bytes)
                                
                            if slot:
                                ptr = slot.get_write_ptr()
                                mod._mixer_slot = slot
                            else:
                                ptr = pal_alloc_secure(size_bytes)
                                if ptr == 0:
                                    raise MemoryError("Vajraa: pal_alloc_secure failed for mixer weight")
                                pal_unlock(ptr, size_bytes)
                                mod._mixer_slot = None
                            
                            if slot:
                                read_ptr = slot.get_read_view()
                            else:
                                read_ptr = ptr
                                
                            ctypes_array = (ctypes.c_byte * size_bytes).from_address(read_ptr)
                            ctypes.memmove(ctypes_array, w_mix.ctypes.data, size_bytes)
                            shared_np = np.frombuffer(ctypes_array, dtype=w_mix.dtype)
                            
                            w_mix_t = torch.from_numpy(shared_np).reshape(w_mix.shape).to(device)
                            
                            mixed_output = torch.nn.functional.gelu(output_unscrambled)
                            output_final = torch.matmul(mixed_output, w_mix_t)
                            
                            w_mix_t.zero_()
                            
                            slot = getattr(mod, '_mixer_slot', None)
                            if slot:
                                pool.release_slot(slot)
                                delattr(mod, '_mixer_slot')
                            else:
                                pal_secure_zero(ptr, size_bytes)
                                pal_free_secure(ptr, size_bytes)
                            
                            return output_final
                        else:
                            return output_unscrambled
                    return post_hook_obfusc
 
                module.register_forward_pre_hook(make_pre_hook_obfusc())
                module.register_forward_hook(make_post_hook_obfusc())
                wrapped_modules.append((name, "obfuscated"))
 
    return wrapped_modules
