# tests/test_lora_shield.py
import unittest
import torch
import torch.nn as nn
import numpy as np
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../python')))

from vajraa.lora_shield import compile_lora_weights, secure_wrap_lora

# A mockup of a PEFT/LoRA Linear Layer
class MockLoRALinear(nn.Module):
    def __init__(self):
        super().__init__()
        self.base_layer = nn.Linear(4, 2)
        # LoRA adapters
        self.lora_A = nn.Linear(4, 2, bias=False)
        self.lora_B = nn.Linear(2, 2, bias=False)
        self.scaling = 0.5

        # Initialize fixed values
        self.base_layer.weight.data.fill_(0.1)
        self.base_layer.bias.data.fill_(0.1)
        self.lora_A.weight.data.fill_(0.5)
        self.lora_B.weight.data.fill_(0.2)

    def forward(self, x):
        # PEFT style: base_output + lora_B(lora_A(x)) * scaling
        base_out = self.base_layer(x)
        lora_out = self.lora_B(self.lora_A(x)) * self.scaling
        return base_out + lora_out

class TestLoRAShield(unittest.TestCase):
    def setUp(self):
        self.master_key = os.urandom(32)
        self.model = MockLoRALinear()
        self.dummy_input = torch.tensor([[1.0, 2.0, 3.0, 4.0]], dtype=torch.float32)

        # Get expected plaintext output
        with torch.no_grad():
            self.expected_output = self.model(self.dummy_input).numpy()

    def test_lora_encryption_and_inference(self):
        # 1. Compile LoRA weights
        compiled_lora = compile_lora_weights(self.model.state_dict(), self.master_key)
        self.assertIn("lora_A.weight", compiled_lora)
        self.assertIn("lora_B.weight", compiled_lora)

        # Create a new instance and wrap it
        wrapped_model = MockLoRALinear()
        secure_wrap_lora(wrapped_model, compiled_lora, self.master_key)

        # Verify that weights are deleted from RAM at rest
        self.assertIsNone(getattr(wrapped_model.lora_A, 'weight', None))
        self.assertIsNone(getattr(wrapped_model.lora_B, 'weight', None))

        # 2. Run inference
        with torch.no_grad():
            wrapped_output = wrapped_model(self.dummy_input).numpy()

        # 3. Verify that outputs are mathematically identical
        np.testing.assert_array_almost_equal(self.expected_output, wrapped_output, decimal=5)

        # 4. Verify memory is wiped
        self.assertIsNone(getattr(wrapped_model.lora_A, 'weight', None))
        self.assertIsNone(getattr(wrapped_model.lora_B, 'weight', None))
        self.assertFalse(hasattr(wrapped_model.lora_A, 'weight_transient'))
        self.assertFalse(hasattr(wrapped_model.lora_B, 'weight_transient'))

if __name__ == '__main__':
    unittest.main()
