# python/vajraa/lora_shield.py
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

def compile_lora_weights(state_dict: dict, master_key: bytes) -> dict:
    """
    Encrypts PEFT/LoRA adapter weights (lora_A and lora_B parameters)
    using AES-256-GCM.
    """
    compiled_lora = {}
    key_crypto = hashlib.sha256(master_key + b"_lora_crypto").digest()

    for name, param in state_dict.items():
        # LoRA weights typically have 'lora_A' or 'lora_B' in their parameter name
        if "lora_A" in name or "lora_B" in name:
            if hasattr(param, "numpy"):
                param_np = param.numpy().copy()
            else:
                param_np = param.copy()
                
            aad = f"{name}:{list(param_np.shape)}:{str(param_np.dtype)}".encode('utf-8')
            compiled_lora[name] = encrypt_tensor(param_np, key_crypto, aad=aad)
            
    return compiled_lora

def secure_wrap_lora(model: nn.Module, compiled_lora_weights: dict, master_key: bytes):
    """
    Wraps LoRA layers in a PEFT model.
    Replaces adapter weights with encrypted placeholders, decrypts them JIT
    during forward passes, and instantly zero-wipes the memory.
    """
    key_crypto = hashlib.sha256(master_key + b"_lora_crypto").digest()
    wrapped_adapters = []

    for name, module in model.named_modules():
        # Look for the linear layer components of the LoRA adapter (lora_A, lora_B)
        # In PEFT, these are standard nn.Linear layers inside ParameterDict modules
        is_lora = False
        if isinstance(module, nn.Linear):
            if "lora_A" in name or "lora_B" in name:
                is_lora = True
            else:
                class_name = module.__class__.__name__
                if "Lora" in class_name or "LoRA" in class_name:
                    is_lora = True
                    
        if is_lora:
            weight_key = f"{name}.weight" if name else "weight"
            
            if weight_key in compiled_lora_weights:
                module._enc_weight = compiled_lora_weights[weight_key]
                
                # Delete standard weight parameter to clear RAM
                if hasattr(module, 'weight'):
                    delattr(module, 'weight')
                module.register_parameter('weight', None)
                
                w_shape = tuple(module._enc_weight["shape"])
                w_dtype = np.dtype(module._enc_weight["dtype"])

                # Register JIT hooks
                def make_pre_hook_lora(w_k, w_sh, w_dt):
                    def pre_hook_lora(mod, input_args):
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
                            
                            aad = f"{w_k}:{list(w_sh)}:{str(w_dt)}".encode('utf-8')
                            
                            ptr = pal_alloc_secure(size_bytes)
                            if ptr == 0:
                                raise MemoryError("Vajraa: pal_alloc_secure failed for LoRA weight")
                            pal_unlock(ptr, size_bytes)
                            
                            success = pal_decrypt_gcm(ciphertext, key_crypto, iv, tag, aad, ptr)
                            if not success:
                                pal_secure_zero(ptr, size_bytes)
                                pal_free_secure(ptr, size_bytes)
                                raise SecurityError("Vajraa: Decryption failed for LoRA weight")
                            
                            ctypes_array = (ctypes.c_byte * size_bytes).from_address(ptr)
                            shared_np = np.frombuffer(ctypes_array, dtype=w_dt)
                            
                            mod.weight_transient = torch.from_numpy(shared_np).reshape(w_sh).to(device)
                            mod.weight = nn.Parameter(mod.weight_transient, requires_grad=False)
                            
                            lease.update({
                                'weight_ptr': ptr,
                                'weight_size': size_bytes,
                                'weight_transient': mod.weight_transient
                            })
                            
                        if lease:
                            _active_leases[id(mod)] = lease
                            
                    return pre_hook_lora

                def make_post_hook_lora():
                    def post_hook_lora(mod, input_args, output):
                        lease = _active_leases.pop(id(mod), None)
                        if lease:
                            # 1. Zero PyTorch transient buffer first
                            w_trans = lease.get('weight_transient')
                            if w_trans is not None:
                                w_trans.zero_()
                                
                            # 2. Zero and free secure OS allocations
                            w_ptr = lease.get('weight_ptr')
                            w_size = lease.get('weight_size')
                            if w_ptr:
                                pal_secure_zero(w_ptr, w_size)
                                pal_free_secure(w_ptr, w_size)
                                
                        # 3. Clean up references
                        if hasattr(mod, 'weight'):
                            delattr(mod, 'weight')
                        if hasattr(mod, 'weight_transient'):
                            delattr(mod, 'weight_transient')
                            
                    return post_hook_lora

                module.register_forward_pre_hook(make_pre_hook_lora(weight_key, w_shape, w_dtype))
                module.register_forward_hook(make_post_hook_lora())
                wrapped_adapters.append(name)

    return wrapped_adapters
