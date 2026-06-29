# tests/test_base_shield.py
import unittest
import torch
import torch.nn as nn
import numpy as np
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../python')))

from vajraa.base_shield import compile_base_weights, secure_wrap_base

class SimpleModel(nn.Module):
    def __init__(self):
        super(SimpleModel, self).__init__()
        self.fc = nn.Linear(4, 2)
        self.conv = nn.Conv2d(1, 1, kernel_size=2)
        
        # Initialize with deterministic values
        self.fc.weight.data.fill_(1.0)
        self.fc.bias.data.fill_(0.5)
        self.conv.weight.data.fill_(0.5)
        self.conv.bias.data.fill_(0.1)

    def forward(self, x, x_img):
        out_fc = self.fc(x)
        out_conv = self.conv(x_img)
        return out_fc, out_conv

class TestBaseShield(unittest.TestCase):
    def setUp(self):
        self.master_key = os.urandom(32)
        self.model = SimpleModel()
        
        # Input samples
        self.dummy_x = torch.ones(1, 4)
        self.dummy_img = torch.ones(1, 1, 2, 2)
        
        # Run baseline
        with torch.no_grad():
            self.expected_fc, self.expected_conv = self.model(self.dummy_x, self.dummy_img)

    def test_base_weight_shield_lifecycle(self):
        # 1. Compile base weights
        state_dict = self.model.state_dict()
        compiled_weights = compile_base_weights(self.model, self.master_key)
        
        # Verify weight is captured
        self.assertIn("fc.weight", compiled_weights)
        self.assertIn("fc.bias", compiled_weights)
        self.assertIn("conv.weight", compiled_weights)
        self.assertIn("conv.bias", compiled_weights)
        
        # 2. Secure wrap model
        wrapped = secure_wrap_base(self.model, compiled_weights, self.master_key)
        self.assertEqual(len(wrapped), 2)
        
        # Verify standard parameter attribute is deleted
        self.assertIsNone(getattr(self.model.fc, 'weight', None))
        self.assertIsNone(getattr(self.model.fc, 'bias', None))
        self.assertIsNone(getattr(self.model.conv, 'weight', None))
        self.assertIsNone(getattr(self.model.conv, 'bias', None))
        
        # 3. Run forward pass JIT
        out_fc, out_conv = self.model(self.dummy_x, self.dummy_img)
        
        # Verify output is mathematically identical
        np.testing.assert_array_almost_equal(self.expected_fc.detach().numpy(), out_fc.detach().numpy(), decimal=5)
        np.testing.assert_array_almost_equal(self.expected_conv.detach().numpy(), out_conv.detach().numpy(), decimal=5)
        
        # 4. Verify post-hook wiped transient memory
        self.assertIsNone(getattr(self.model.fc, 'weight', None))
        self.assertFalse(hasattr(self.model.fc, 'weight_transient'))
        self.assertFalse(hasattr(self.model.fc, '_weight_ptr'))

if __name__ == '__main__':
    unittest.main()
