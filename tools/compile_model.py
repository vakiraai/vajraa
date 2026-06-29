# tools/compile_model.py
import argparse
import os
import sys
import torch
import torch.nn as nn
import json

# Ensure package path is visible
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../python')))

from vajraa.compiler import compile_model_weights

class DemoModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.input_layer = nn.Linear(4, 8)
        self.hidden_layer = nn.Linear(8, 8)
        self.output_layer = nn.Linear(8, 2)

    def forward(self, x):
        x = torch.relu(self.input_layer(x))
        x = torch.relu(self.hidden_layer(x))
        return self.output_layer(x)

def main():
    parser = argparse.ArgumentParser(description="Vajraa Model Compiler")
    parser.add_argument("--output", type=str, default="model.ems", help="Output path for the compiled model")
    parser.add_argument("--key", type=str, required=True, help="Master key (32-byte hex string)")
    args = parser.parse_args()

    # Convert hex key to bytes
    try:
        master_key = bytes.fromhex(args.key)
        if len(master_key) != 32:
            raise ValueError("Key must be exactly 32 bytes (64 hex characters).")
    except Exception as e:
        print(f"Error parsing key: {e}")
        sys.exit(1)

    print("Initializing demo PyTorch model for compilation...")
    model = DemoModel()
    
    # Save the original model architecture and state dict
    state_dict = model.state_dict()
    
    print("Compiling weights (shuffling intermediate channels, encrypting boundaries, injecting non-linear mixers)...")
    compiled_data = compile_model_weights(state_dict, master_key)
    
    # Save compiled data to file
    with open(args.output, "w") as f:
        json.dump(compiled_data, f, indent=2)
        
    print(f"Compilation complete! Secured model saved to: {args.output}")

if __name__ == "__main__":
    main()
