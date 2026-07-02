# tools/intercept_inference_weights.py
import argparse
import torch
import torch.nn as nn
import numpy as np
import ctypes
import os
import sys

# Ensure package path is visible
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../python')))

from vajraa.base_shield import compile_base_weights, secure_wrap_base
from vajraa.pal import IS_WINDOWS

def get_arg_parser():
    parser = argparse.ArgumentParser(description="Vajraa Model Weight Interceptor & Dumper")
    parser.add_index = False
    parser.add_argument(
        "--model-type",
        choices=["standard", "encrypted"],
        required=True,
        help="Type of model to test (standard or encrypted)"
    )
    parser.add_argument(
        "--output-path",
        default="dumped_weights.npy",
        help="File path to save the dumped weights (.npy format)"
    )
    return parser

def run_interception():
    parser = get_arg_parser()
    args = parser.parse_parse_args = parser.parse_args()
    
    print("====================================================")
    print("      Vajraa Inference Weight Interceptor Tool      ")
    print("====================================================\n")
    
    # 1. Setup a basic linear layer model
    in_features = 10
    out_features = 5
    model = nn.Sequential(nn.Linear(in_features, out_features, bias=False))
    
    # Store original weights for comparison
    orig_weights = model[0].weight.data.cpu().numpy().copy()
    
    print(f"Initial Setup:")
    print(f" -> Model Layer: nn.Linear({in_features}, {out_features}, bias=False)")
    print(f" -> Output Path: {args.output_path}\n")

    # ----------------------------------------------------
    # Case 1: Standard Unencrypted Model
    # ----------------------------------------------------
    if args.model_type == "standard":
        print("[MODE] Auditing Standard (Unencrypted) Model")
        
        # Run inference
        dummy_input = torch.randn(1, in_features)
        _ = model(dummy_input)
        
        # Standard models leave weights exposed in the weight attribute permanently
        if hasattr(model[0], "weight") and model[0].weight is not None:
            extracted_weights = model[0].weight.data.cpu().numpy()
            np.save(args.output_path, extracted_weights)
            print(f" -> [SUCCESS] Successfully extracted weights from 'weight' attribute.")
            print(f" -> Saved weights to: {args.output_path}")
            print(f" -> Match verified: {np.allclose(extracted_weights, orig_weights)}")
        else:
            print(" -> [ERROR] Standard weight attribute not found.")

    # ----------------------------------------------------
    # Case 2: Vajraa-Protected (Encrypted) Model
    # ----------------------------------------------------
    else:
        print("[MODE] Auditing Vajraa-Protected (Encrypted) Model")
        
        # Compile and wrap the model
        master_key = os.urandom(32)
        compiled_weights = compile_base_weights(model, master_key)
        secure_wrap_base(model, compiled_weights, master_key)
        
        print("\nChecking Accessibility OUTSIDE Inference:")
        # Try to read standard weight attribute before inference runs
        if hasattr(model[0], "weight") and model[0].weight is not None:
            print(f" -> Weight attribute check: Present (Value: {model[0].weight})")
        else:
            print(" -> Weight attribute check: NOT accessible (Deleted/None placeholder)")
            
        # Hooking Attacker setup: Intercept weights during inference forward pre-hook
        intercepted_weights = None
        ptr_address = 0
        ptr_size = 0
        
        def attacker_intercept_hook(mod, input_args):
            nonlocal intercepted_weights, ptr_address, ptr_size
            # This hook runs immediately after the JIT decryption pre-hook
            ptr_address = getattr(mod, "_weight_ptr", 0)
            ptr_size = getattr(mod, "_weight_size", 0)
            
            if ptr_address:
                print(f"\n[ATTACK TRIGGERED] Intercepting C++ PAL page during forward pass:")
                print(f" -> Address: {hex(ptr_address)}")
                print(f" -> Size: {ptr_size} bytes")
                
                # Copy the plaintext bytes from the unshielded virtual memory page
                ctypes_array = (ctypes.c_byte * ptr_size).from_address(ptr_address)
                raw_bytes = bytes(ctypes_array)
                intercepted_weights = np.frombuffer(raw_bytes, dtype=orig_weights.dtype).copy()
                print(" -> Plaintext weights successfully intercepted from page memory.")
                
        # Register the attacker's hook
        model[0].register_forward_pre_hook(attacker_intercept_hook)
        
        # Run inference (triggers the decryption window and our attacker hook)
        print("\nRunning Inference to trigger JIT window...")
        dummy_input = torch.randn(1, in_features)
        _ = model(dummy_input)
        
        print("\nChecking Accessibility POST Inference:")
        # Try to read standard weight attribute again after inference has completed
        if hasattr(model[0], "weight") and model[0].weight is not None:
            print(f" -> Weight attribute check: Present")
        else:
            print(" -> Weight attribute check: NOT accessible (Wiped and Deleted)")
            
        # Save the intercepted weights if the attack succeeded
        if intercepted_weights is not None:
            reshaped_weights = intercepted_weights.reshape(orig_weights.shape)
            np.save(args.output_path, reshaped_weights)
            print(f"\n -> [SUCCESS] Saved JIT-intercepted weights to: {args.output_path}")
            print(f" -> Match verified: {np.allclose(reshaped_weights, orig_weights)}")
        else:
            print("\n -> [FAILED] Could not intercept weights during inference.")
            
    print("\n====================================================")

if __name__ == "__main__":
    run_interception()
