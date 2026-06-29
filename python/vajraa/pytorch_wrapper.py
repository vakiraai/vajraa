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
    pal_secure_zero,
    pal_free_secure,
    pal_is_debugger_attached,
    pal_kill_if_debugged
)

def secure_wrap_model(model: nn.Module, compiled_model: dict, master_key: bytes):
    """
    Wraps a PyTorch model and executes it securely.
    1. Standard layers run via JIT decryption and immediate zero-wiping.
    2. Obfuscated layers run via key-dependent permutations & scales (weights remain scrambled in RAM).
    3. Injects and runs encrypted non-linear Secret Mixer layers in the execution path.
    """
    wrapped_modules = []
    
    # Derive sub-keys
    key_crypto = hashlib.sha256(master_key + b"_crypto").digest()
    key_obfusc = hashlib.sha256(master_key + b"_obfusc").digest()
    
    encrypted_layers = compiled_model["encrypted_layers"]
    obfuscated_layers = compiled_model["obfuscated_layers"]
    mixers = compiled_model["mixers"]

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
                            ptr = pal_alloc_secure(size_bytes)
                            if ptr == 0:
                                raise MemoryError("Vajraa: pal_alloc_secure failed for weight")
                            pal_unlock(ptr, size_bytes)
                            
                            # Load into page buffer and share with torch
                            ctypes_array = (ctypes.c_byte * size_bytes).from_address(ptr)
                            ctypes.memmove(ctypes_array, w_np.ctypes.data, size_bytes)
                            shared_np = np.frombuffer(ctypes_array, dtype=w_np.dtype)
                            
                            mod.weight_transient = torch.from_numpy(shared_np).reshape(w_np.shape).to(device)
                            mod.weight = nn.Parameter(mod.weight_transient, requires_grad=False)
                            mod._weight_ptr = ptr
                            mod._weight_size = size_bytes
                            
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
                    return pre_hook_crypto

                def make_post_hook_crypto():
                    def post_hook_crypto(mod, input_args, output):
                        # 1. Zero PyTorch transient buffers first
                        if hasattr(mod, 'weight_transient'):
                            mod.weight_transient.zero_()
                        if hasattr(mod, 'bias_transient'):
                            mod.bias_transient.zero_()
                            
                        # 2. Zero and free secure OS allocations
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
                    raise ValueError(f"Vajraa: Obfuscation is only supported for 2D weight matrices (Linear layers), but got shape {w_scrambled.shape} for layer {weight_key}")
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
                        
                        # Convert permutations & scales to torch vectors on device
                        p_in_t = torch.from_numpy(mod._p_in).to(device)
                        inv_s_in_t = torch.from_numpy(1.0 / mod._s_in).to(device)
                        
                        # Transform input activations: X_transformed = X[..., P_in] * D_in^-1
                        x_transformed = x[..., p_in_t] * inv_s_in_t
                        
                        # Decrypt bias JIT if present
                        if hasattr(mod, '_enc_bias'):
                            b_np = decrypt_tensor(mod._enc_bias, key_crypto)
                            size_bytes = b_np.nbytes
                            ptr = pal_alloc_secure(size_bytes)
                            if ptr == 0:
                                raise MemoryError("Vajraa: pal_alloc_secure failed for obfuscated bias")
                            pal_unlock(ptr, size_bytes)
                            
                            ctypes_array = (ctypes.c_byte * size_bytes).from_address(ptr)
                            ctypes.memmove(ctypes_array, b_np.ctypes.data, size_bytes)
                            shared_np = np.frombuffer(ctypes_array, dtype=b_np.dtype)
                            
                            mod.bias_transient = torch.from_numpy(shared_np).reshape(b_np.shape).to(device)
                            mod._bias_ptr = ptr
                            mod._bias_size = size_bytes
                        
                        # Temporary point weight to scrambled weight in RAM for computation
                        mod.weight = mod.weight_scrambled
                        return (x_transformed,)
                    return pre_hook_obfusc

                def make_post_hook_obfusc():
                    def post_hook_obfusc(mod, input_args, output):
                        device = output.device
                        
                        # Remove the scrambled weight pointer so standard module has no weight attribute
                        if hasattr(mod, 'weight'):
                            delattr(mod, 'weight')
                        
                        # Compute inverse permutations & scales
                        inv_p_out = np.argsort(mod._p_out)
                        inv_p_out_t = torch.from_numpy(inv_p_out).to(device)
                        inv_s_out_t = torch.from_numpy(1.0 / mod._s_out).to(device)
                        
                        # Un-shuffle & un-scale: Y = Y_scrambled[..., P_out^-1] * D_out^-1[P_out^-1]
                        output_unscrambled = output[..., inv_p_out_t] * inv_s_out_t[inv_p_out_t]
                        
                        # Add plaintext bias manually to the un-shuffled outputs
                        if hasattr(mod, 'bias_transient'):
                            output_unscrambled = output_unscrambled + mod.bias_transient
                            
                            # Wipe and free bias page securely
                            mod.bias_transient.zero_()
                            pal_secure_zero(mod._bias_ptr, mod._bias_size)
                            pal_free_secure(mod._bias_ptr, mod._bias_size)
                            delattr(mod, 'bias_transient')
                            delattr(mod, '_bias_ptr')
                            delattr(mod, '_bias_size')
                        
                        # Step 3: Run the Encrypted Secret Mixer layer if present
                        if hasattr(mod, '_enc_mixer'):
                            # Decrypt mixer weights JIT
                            w_mix = decrypt_tensor(mod._enc_mixer, key_crypto)
                            size_bytes = w_mix.nbytes
                            ptr = pal_alloc_secure(size_bytes)
                            if ptr == 0:
                                raise MemoryError("Vajraa: pal_alloc_secure failed for mixer weight")
                            pal_unlock(ptr, size_bytes)
                            
                            ctypes_array = (ctypes.c_byte * size_bytes).from_address(ptr)
                            ctypes.memmove(ctypes_array, w_mix.ctypes.data, size_bytes)
                            shared_np = np.frombuffer(ctypes_array, dtype=w_mix.dtype)
                            
                            w_mix_t = torch.from_numpy(shared_np).reshape(w_mix.shape).to(device)
                            
                            # Apply non-linear mixer mapping: Y = GeLU(Y) * W_mix
                            mixed_output = torch.nn.functional.gelu(output_unscrambled)
                            output_final = torch.matmul(mixed_output, w_mix_t)
                            
                            # Zero and free mixer weights immediately
                            w_mix_t.zero_()
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
