# python/vajraa/compiler.py
import numpy as np
import hashlib
import json
from .crypto import encrypt_tensor

def derive_permutation_and_scales(seed_key: bytes, size: int) -> tuple:
    """
    Derives a deterministic key-dependent permutation vector and scaling factors 
    using a SHA-256 hash of the seed key as a PRNG seed.
    """
    # Create a deterministic PRNG seeded by the 64-bit hash of the key
    hash_seed = int.from_bytes(hashlib.sha256(seed_key).digest()[:8], 'big')
    rng = np.random.default_rng(hash_seed)
    
    # Generate permutation vector
    perm = rng.permutation(size)
    
    # Generate positive scaling factors (e.g. between 0.5 and 2.0)
    scales = rng.uniform(0.5, 2.0, size=size).astype(np.float32)
    
    return perm, scales

def compile_model_weights(state_dict: dict, master_key: bytes) -> dict:
    """
    Compiles PyTorch/TensorFlow weights by:
    1. Encrypting critical layers (first layer, last layer) with AES-256-GCM.
    2. Scrambling intermediate layers with key-dependent channel permutations and scaling.
    3. Generating parameters for non-linear Secret Mixer layers.
    Returns a unified dict containing the secured model representation.
    """
    compiled_model = {
        "encrypted_layers": {},
        "obfuscated_layers": {},
        "mixers": {},
        "metadata": {}
    }
    
    # Preserve insertion order to follow topological execution flow
    layer_names = list(state_dict.keys())
    if not layer_names:
        return compiled_model
        
    first_layer_name = layer_names[0]
    last_layer_name = layer_names[-1]
    
    # Derive unique sub-keys for different security tasks from the master key
    key_crypto = hashlib.sha256(master_key + b"_crypto").digest()
    key_obfusc = hashlib.sha256(master_key + b"_obfusc").digest()

    for name, weight_tensor in state_dict.items():
        # Handle PyTorch Tensors vs Numpy arrays
        if hasattr(weight_tensor, "numpy"):
            weight_np = weight_tensor.numpy().copy()
        else:
            weight_np = np.array(weight_tensor).copy()

        # Step 1: Encrypt the critical boundaries (First & Last layers) using AES
        if name.startswith(first_layer_name.split('.')[0]) or name.startswith(last_layer_name.split('.')[0]):
            compiled_model["encrypted_layers"][name] = encrypt_tensor(weight_np, key_crypto)
            continue

        # Step 2: Apply Permutation & Scaling Obfuscation to Intermediate Layers
        # We only apply this to 2D weight matrices (Linear layer weights)
        if len(weight_np.shape) == 2 and "weight" in name:
            out_features, in_features = weight_np.shape
            
            # Derive deterministic permutations and scales for input and output channels
            p_out, s_out = derive_permutation_and_scales(key_obfusc + name.encode(), out_features)
            p_in, s_in = derive_permutation_and_scales(key_obfusc + name.encode() + b"_in", in_features)
            
            # Scramble weights: W_scrambled = D_out * W[P_out, P_in] * D_in
            # Applying permutations
            scrambled = weight_np[p_out, :]
            scrambled = scrambled[:, p_in]
            
            # Applying scaling factors
            scrambled = scrambled * s_out[:, np.newaxis]
            scrambled = scrambled * s_in[np.newaxis, :]
            
            compiled_model["obfuscated_layers"][name] = encrypt_tensor(scrambled, key_crypto)
            
            # Inject a Secret Mixer block parameters right after this layer
            # A Mixer is a tiny feed-forward net: GeLU(X * W_mix)
            # The mixer weights are kept 100% encrypted
            mix_size = out_features
            mixer_key = f"mixer_{name}"
            # Derive deterministic seed for mixer weights from key and mixer_key
            mixer_seed = int.from_bytes(hashlib.sha256(key_obfusc + mixer_key.encode()).digest()[:8], 'big')
            mixer_rng = np.random.default_rng(mixer_seed)
            w_mix = mixer_rng.normal(0, 0.01, size=(mix_size, mix_size)).astype(np.float32)
            compiled_model["mixers"][mixer_key] = encrypt_tensor(w_mix, key_crypto)
            
        else:
            # Fallback encrypt other parameters (like biases) for security
            compiled_model["encrypted_layers"][name] = encrypt_tensor(weight_np, key_crypto)

    return compiled_model
