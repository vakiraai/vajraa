# tests/test_compiler_and_mixer.py
import unittest
import torch
import torch.nn as nn
import numpy as np
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../python')))

from vajraa.compiler import compile_model_weights
from vajraa.pytorch_wrapper import secure_wrap_model

class ComplexDemoModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.fc1 = nn.Linear(4, 8)
        self.fc2 = nn.Linear(8, 8)
        self.fc3 = nn.Linear(8, 2)
        
        # Initialize fixed weights for deterministic output
        self.fc1.weight.data.fill_(0.5)
        self.fc1.bias.data.fill_(0.1)
        self.fc2.weight.data.fill_(0.2)
        self.fc2.bias.data.fill_(0.2)
        self.fc3.weight.data.fill_(0.1)
        self.fc3.bias.data.fill_(0.3)

    def forward(self, x):
        x = torch.relu(self.fc1(x))
        x = torch.relu(self.fc2(x))
        return self.fc3(x)

class TestCompilerAndMixer(unittest.TestCase):
    def setUp(self):
        self.master_key = os.urandom(32)
        self.model = ComplexDemoModel()
        
        # Calculate expected output of the plaintext model
        self.dummy_input = torch.tensor([[1.0, 2.0, 3.0, 4.0]], dtype=torch.float32)
        with torch.no_grad():
            self.expected_output = self.model(self.dummy_input).numpy()

    def test_compile_and_run_without_mixer(self):
        # 1. Compile model weights offline
        compiled_model = compile_model_weights(self.model.state_dict(), self.master_key)
        
        # Remove mixers to verify mathematical equivalence of pure shuffling/scaling
        compiled_model["mixers"] = {}
        
        # Create a new model instance and wrap it
        wrapped_model = ComplexDemoModel()
        secure_wrap_model(wrapped_model, compiled_model, self.master_key)
        
        # Verify that the intermediate layer's weights in memory DO NOT match the original weights
        scrambled_weight_in_ram = wrapped_model.fc2.weight_scrambled.numpy()
        original_weight = self.model.fc2.weight.data.numpy()
        self.assertFalse(np.array_equal(original_weight, scrambled_weight_in_ram))
        
        # 2. Run inference on the wrapped model
        with torch.no_grad():
            wrapped_output = wrapped_model(self.dummy_input).numpy()
            
        # 3. Verify that the output matches the original model output EXACTLY
        # (shuffling and scaling math is 100% correct)
        np.testing.assert_array_almost_equal(self.expected_output, wrapped_output, decimal=4)

    def test_compile_and_run_with_mixer(self):
        # 1. Compile model weights offline with mixers enabled
        compiled_model = compile_model_weights(self.model.state_dict(), self.master_key)
        
        # Create a new model instance and wrap it
        wrapped_model = ComplexDemoModel()
        secure_wrap_model(wrapped_model, compiled_model, self.master_key)
        
        # 2. Run inference on the wrapped model
        with torch.no_grad():
            wrapped_output = wrapped_model(self.dummy_input).numpy()
            
        # 3. Verify that the output does NOT match the original (proves mixer is executed and transforms features)
        self.assertFalse(np.allclose(self.expected_output, wrapped_output, atol=1e-4))
        
        # 4. Verify that the Secret Mixer weights are immediately wiped from memory after execution
        self.assertFalse(hasattr(wrapped_model.fc2, 'weight_transient'))
        self.assertFalse(hasattr(wrapped_model.fc2, '_weight_ptr'))
        self.assertFalse(hasattr(wrapped_model.fc2, '_enc_mixer_transient'))

if __name__ == '__main__':
    unittest.main()
