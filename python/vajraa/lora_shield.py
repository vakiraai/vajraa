# python/vajraa/lora_shield.py
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
            compiled_lora[name] = encrypt_tensor(param_np, key_crypto)
            
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
                
                # Register JIT hooks
                def make_pre_hook_lora(mod_name):
                    def pre_hook_lora(mod, input_args):
                        if pal_is_debugger_attached():
                            pal_kill_if_debugged()
                        device = input_args[0].device
                        
                        if hasattr(mod, '_enc_weight'):
                            # Decrypt
                            w_np = decrypt_tensor(mod._enc_weight, key_crypto)
                            size_bytes = w_np.nbytes
                            
                            # Secure page allocation
                            ptr = pal_alloc_secure(size_bytes)
                            if ptr == 0:
                                raise MemoryError("Vajraa: pal_alloc_secure failed for LoRA weight")
                            pal_unlock(ptr, size_bytes)
                            
                            ctypes_array = (ctypes.c_byte * size_bytes).from_address(ptr)
                            ctypes.memmove(ctypes_array, w_np.ctypes.data, size_bytes)
                            shared_np = np.frombuffer(ctypes_array, dtype=w_np.dtype)
                            
                            mod.weight_transient = torch.from_numpy(shared_np).reshape(w_np.shape).to(device)
                            mod.weight = nn.Parameter(mod.weight_transient, requires_grad=False)
                            
                            mod._weight_ptr = ptr
                            mod._weight_size = size_bytes
                    return pre_hook_lora

                def make_post_hook_lora(mod_name):
                    def post_hook_lora(mod, input_args, output):
                        # 1. Zero PyTorch transient buffer first
                        if hasattr(mod, 'weight_transient'):
                            mod.weight_transient.zero_()
                            
                        # 2. Zero and free secure OS allocations
                        if hasattr(mod, '_weight_ptr'):
                            pal_secure_zero(mod._weight_ptr, mod._weight_size)
                            pal_free_secure(mod._weight_ptr, mod._weight_size)
                            delattr(mod, '_weight_ptr')
                            delattr(mod, '_weight_size')
                            
                        # 3. Clean up references
                        if hasattr(mod, 'weight_transient'):
                            if hasattr(mod, 'weight'):
                                delattr(mod, 'weight')
                            del mod.weight_transient
                            
                        gc.collect()
                    return post_hook_lora

                module.register_forward_pre_hook(make_pre_hook_lora(name))
                module.register_forward_hook(make_post_hook_lora(name))
                wrapped_adapters.append(name)

    return wrapped_adapters
