# python/vajraa/base_shield.py
import torch
import torch.nn as nn
import numpy as np
import hashlib
import ctypes
from .crypto import encrypt_tensor, decrypt_tensor, SecurityError
from .pal import (
    pal_alloc_secure,
    pal_unlock,
    pal_secure_zero,
    pal_free_secure,
    pal_is_debugger_attached,
    pal_kill_if_debugged,
    pal_decrypt_gcm
)

_active_leases = {}

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
                    
                    aad = f"{weight_key}:{list(param_np.shape)}:{str(param_np.dtype)}".encode('utf-8')
                    compiled_base[weight_key] = encrypt_tensor(param_np, key_crypto, aad=aad)
                    
                # Optionally secure bias as well
                if hasattr(module, 'bias') and module.bias is not None:
                    bias_key = f"{name}.bias" if name else "bias"
                    param = module.bias.data
                    if hasattr(param, "numpy"):
                        param_np = param.cpu().numpy().copy()
                    else:
                        param_np = param.copy()
                        
                    aad = f"{bias_key}:{list(param_np.shape)}:{str(param_np.dtype)}".encode('utf-8')
                    compiled_base[bias_key] = encrypt_tensor(param_np, key_crypto, aad=aad)
                    
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
                w_shape = tuple(module._enc_weight["shape"]) if hasattr(module, "_enc_weight") else None
                w_dtype = np.dtype(module._enc_weight["dtype"]) if hasattr(module, "_enc_weight") else None
                
                b_shape = tuple(module._enc_bias["shape"]) if hasattr(module, "_enc_bias") else None
                b_dtype = np.dtype(module._enc_bias["dtype"]) if hasattr(module, "_enc_bias") else None

                # Register JIT hooks
                def make_pre_hook(w_k, b_k, w_sh, w_dt, b_sh, b_dt):
                    def pre_hook(mod, input_args):
                        if pal_is_debugger_attached():
                            pal_kill_if_debugged()
                        device = input_args[0].device
                        
                        lease = {}
                        
                        # Decrypt and lock weight
                        if hasattr(mod, '_enc_weight'):
                            import base64
                            ciphertext = base64.b64decode(mod._enc_weight["ciphertext"])
                            iv = base64.b64decode(mod._enc_weight["iv"])
                            tag = base64.b64decode(mod._enc_weight["tag"])
                            size_bytes = len(ciphertext)
                            
                            aad = f"{w_k}:{list(w_sh)}:{str(w_dt)}".encode('utf-8')
                            
                            ptr = pal_alloc_secure(size_bytes)
                            if ptr == 0:
                                raise MemoryError("Vajraa: pal_alloc_secure failed for weight")
                            pal_unlock(ptr, size_bytes)
                            
                            success = pal_decrypt_gcm(ciphertext, key_crypto, iv, tag, aad, ptr)
                            if not success:
                                pal_secure_zero(ptr, size_bytes)
                                pal_free_secure(ptr, size_bytes)
                                raise SecurityError("Vajraa: Decryption failed for weight")
                            
                            ctypes_array = (ctypes.c_byte * size_bytes).from_address(ptr)
                            shared_np = np.frombuffer(ctypes_array, dtype=w_dt)
                            
                            mod.weight_transient = torch.from_numpy(shared_np).reshape(w_sh).to(device)
                            mod.weight = nn.Parameter(mod.weight_transient, requires_grad=False)
                            
                            lease.update({
                                'weight_ptr': ptr,
                                'weight_size': size_bytes,
                                'weight_transient': mod.weight_transient
                            })
                            
                        # Decrypt and lock bias
                        if hasattr(mod, '_enc_bias'):
                            import base64
                            ciphertext = base64.b64decode(mod._enc_bias["ciphertext"])
                            iv = base64.b64decode(mod._enc_bias["iv"])
                            tag = base64.b64decode(mod._enc_bias["tag"])
                            size_bytes = len(ciphertext)
                            
                            aad = f"{b_k}:{list(b_sh)}:{str(b_dt)}".encode('utf-8')
                            
                            ptr = pal_alloc_secure(size_bytes)
                            if ptr == 0:
                                raise MemoryError("Vajraa: pal_alloc_secure failed for bias")
                            pal_unlock(ptr, size_bytes)
                            
                            success = pal_decrypt_gcm(ciphertext, key_crypto, iv, tag, aad, ptr)
                            if not success:
                                pal_secure_zero(ptr, size_bytes)
                                pal_free_secure(ptr, size_bytes)
                                raise SecurityError("Vajraa: Decryption failed for bias")
                            
                            ctypes_array = (ctypes.c_byte * size_bytes).from_address(ptr)
                            shared_np = np.frombuffer(ctypes_array, dtype=b_dt)
                            
                            mod.bias_transient = torch.from_numpy(shared_np).reshape(b_sh).to(device)
                            mod.bias = nn.Parameter(mod.bias_transient, requires_grad=False)
                            
                            lease.update({
                                'bias_ptr': ptr,
                                'bias_size': size_bytes,
                                'bias_transient': mod.bias_transient
                            })
                            
                        if lease:
                            _active_leases[id(mod)] = lease
                            
                    return pre_hook

                def make_post_hook():
                    def post_hook(mod, input_args, output):
                        lease = _active_leases.pop(id(mod), None)
                        if lease:
                            # 1. Zero-wipe PyTorch transient memory buffers first
                            w_trans = lease.get('weight_transient')
                            if w_trans is not None:
                                w_trans.zero_()
                            b_trans = lease.get('bias_transient')
                            if b_trans is not None:
                                b_trans.zero_()
                                
                            # 2. Zero-wipe and free OS page-locked memory allocations
                            w_ptr = lease.get('weight_ptr')
                            w_size = lease.get('weight_size')
                            if w_ptr:
                                pal_secure_zero(w_ptr, w_size)
                                pal_free_secure(w_ptr, w_size)
                                
                            b_ptr = lease.get('bias_ptr')
                            b_size = lease.get('bias_size')
                            if b_ptr:
                                pal_secure_zero(b_ptr, b_size)
                                pal_free_secure(b_ptr, b_size)
                                
                        # 3. Purge parameters and cleanup references
                        if hasattr(mod, 'weight'):
                            delattr(mod, 'weight')
                        if hasattr(mod, 'bias'):
                            delattr(mod, 'bias')
                        if hasattr(mod, 'weight_transient'):
                            delattr(mod, 'weight_transient')
                        if hasattr(mod, 'bias_transient'):
                            delattr(mod, 'bias_transient')
                        
                    return post_hook

                module.register_forward_pre_hook(make_pre_hook(weight_key, bias_key, w_shape, w_dtype, b_shape, b_dtype))
                module.register_forward_hook(make_post_hook())
                wrapped_layers.append(name)

    return wrapped_layers
