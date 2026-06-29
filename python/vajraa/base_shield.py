# python/vajraa/base_shield.py
import torch
import torch.nn as nn
import numpy as np
import hashlib
import gc
import ctypes
from .crypto import encrypt_tensor, decrypt_tensor
from .pal import (
    pal_alloc_secure,
    pal_unlock,
    pal_secure_zero,
    pal_free_secure,
    pal_is_debugger_attached,
    pal_kill_if_debugged
)

def compile_base_weights(model: nn.Module, master_key: bytes, layers_to_encrypt: list = None) -> dict:
    """
    Encrypts base model weights (nn.Linear and nn.Conv2d parameters)
    using AES-256-GCM.
    """
    compiled_base = {}
    key_crypto = hashlib.sha256(master_key + b"_base_crypto").digest()

    for name, module in model.named_modules():
        # Target standard parameters of nn.Linear and nn.Conv2d layers
        if isinstance(module, (nn.Linear, nn.Conv2d)):
            if layers_to_encrypt is None or name in layers_to_encrypt:
                if hasattr(module, 'weight') and module.weight is not None:
                    weight_key = f"{name}.weight" if name else "weight"
                    param = module.weight.data
                    if hasattr(param, "numpy"):
                        param_np = param.cpu().numpy().copy()
                    else:
                        param_np = param.copy()
                    compiled_base[weight_key] = encrypt_tensor(param_np, key_crypto)
                    
                # Optionally secure bias as well
                if hasattr(module, 'bias') and module.bias is not None:
                    bias_key = f"{name}.bias" if name else "bias"
                    param = module.bias.data
                    if hasattr(param, "numpy"):
                        param_np = param.cpu().numpy().copy()
                    else:
                        param_np = param.copy()
                    compiled_base[bias_key] = encrypt_tensor(param_np, key_crypto)
                    
    return compiled_base

def secure_wrap_base(model: nn.Module, compiled_base_weights: dict, master_key: bytes) -> list:
    """
    Wraps base model layers.
    Replaces weights with encrypted placeholders, decrypts them JIT
    during forward passes, and instantly zero-wipes the memory.
    """
    key_crypto = hashlib.sha256(master_key + b"_base_crypto").digest()
    wrapped_layers = []

    for name, module in model.named_modules():
        if isinstance(module, (nn.Linear, nn.Conv2d)):
            weight_key = f"{name}.weight" if name else "weight"
            bias_key = f"{name}.bias" if name else "bias"
            
            has_wrapped = False
            
            # Wrap weight if compiled
            if weight_key in compiled_base_weights:
                module._enc_weight = compiled_base_weights[weight_key]
                if hasattr(module, 'weight'):
                    delattr(module, 'weight')
                module.register_parameter('weight', None)
                has_wrapped = True
                
            # Wrap bias if compiled
            if bias_key in compiled_base_weights:
                module._enc_bias = compiled_base_weights[bias_key]
                if hasattr(module, 'bias'):
                    delattr(module, 'bias')
                module.register_parameter('bias', None)
                has_wrapped = True
                
            if has_wrapped:
                # Register JIT hooks
                def make_pre_hook():
                    def pre_hook(mod, input_args):
                        if pal_is_debugger_attached():
                            pal_kill_if_debugged()
                        device = input_args[0].device
                        
                        # Decrypt and lock weight
                        if hasattr(mod, '_enc_weight'):
                            w_np = decrypt_tensor(mod._enc_weight, key_crypto)
                            size_bytes = w_np.nbytes
                            
                            ptr = pal_alloc_secure(size_bytes)
                            if ptr == 0:
                                raise MemoryError("Vajraa: pal_alloc_secure failed for weight")
                            pal_unlock(ptr, size_bytes)
                            
                            ctypes_array = (ctypes.c_byte * size_bytes).from_address(ptr)
                            ctypes.memmove(ctypes_array, w_np.ctypes.data, size_bytes)
                            shared_np = np.frombuffer(ctypes_array, dtype=w_np.dtype)
                            
                            mod.weight_transient = torch.from_numpy(shared_np).reshape(w_np.shape).to(device)
                            mod.weight = nn.Parameter(mod.weight_transient, requires_grad=False)
                            
                            mod._weight_ptr = ptr
                            mod._weight_size = size_bytes
                            
                        # Decrypt and lock bias
                        if hasattr(mod, '_enc_bias'):
                            b_np = decrypt_tensor(mod._enc_bias, key_crypto)
                            size_bytes = b_np.nbytes
                            
                            ptr = pal_alloc_secure(size_bytes)
                            if ptr == 0:
                                raise MemoryError("Vajraa: pal_alloc_secure failed for bias")
                            pal_unlock(ptr, size_bytes)
                            
                            ctypes_array = (ctypes.c_byte * size_bytes).from_address(ptr)
                            ctypes.memmove(ctypes_array, b_np.ctypes.data, size_bytes)
                            shared_np = np.frombuffer(ctypes_array, dtype=b_np.dtype)
                            
                            mod.bias_transient = torch.from_numpy(shared_np).reshape(b_np.shape).to(device)
                            mod.bias = nn.Parameter(mod.bias_transient, requires_grad=False)
                            
                            mod._bias_ptr = ptr
                            mod._bias_size = size_bytes
                            
                    return pre_hook

                def make_post_hook():
                    def post_hook(mod, input_args, output):
                        # 1. Zero-wipe PyTorch transient memory buffers first
                        if hasattr(mod, 'weight_transient'):
                            mod.weight_transient.zero_()
                        if hasattr(mod, 'bias_transient'):
                            mod.bias_transient.zero_()
                            
                        # 2. Zero-wipe and free OS page-locked memory allocations
                        if hasattr(mod, '_weight_ptr'):
                            pal_secure_zero(mod._weight_ptr, mod._weight_size)
                            pal_free_secure(mod._weight_ptr, mod._weight_size)
                            delattr(mod, '_weight_ptr')
                            delattr(mod, '_weight_size')
                            
                        if hasattr(mod, '_bias_ptr'):
                            pal_secure_zero(mod._bias_ptr, mod._bias_size)
                            pal_free_secure(mod._bias_ptr, mod._bias_size)
                            delattr(mod, '_bias_ptr')
                            delattr(mod, '_bias_size')
                            
                        # 3. Purge parameters and cleanup references
                        if hasattr(mod, 'weight_transient'):
                            if hasattr(mod, 'weight'):
                                delattr(mod, 'weight')
                            del mod.weight_transient
                        if hasattr(mod, 'bias_transient'):
                            if hasattr(mod, 'bias'):
                                delattr(mod, 'bias')
                            del mod.bias_transient
                            
                        gc.collect()
                        
                    return post_hook

                module.register_forward_pre_hook(make_pre_hook())
                module.register_forward_hook(make_post_hook())
                wrapped_layers.append(name)

    return wrapped_layers
