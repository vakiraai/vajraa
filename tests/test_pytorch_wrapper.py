# tests/test_pytorch_wrapper.py
import unittest
import torch
import torch.nn as nn
import numpy as np
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../python')))

from vajraa.crypto import encrypt_tensor
from vajraa.pytorch_wrapper import secure_wrap_model

class SimpleModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.fc = nn.Linear(4, 2)
        # Fix weights for testing
        self.fc.weight.data = torch.tensor([[1.0, 2.0, 3.0, 4.0], [5.0, 6.0, 7.0, 8.0]], dtype=torch.float32)
        self.fc.bias.data = torch.tensor([0.1, 0.2], dtype=torch.float32)

    def forward(self, x):
        return self.fc(x)

class MultiLayerModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.fc1 = nn.Linear(4, 4)
        self.fc2 = nn.Linear(4, 4)
        self.fc3 = nn.Linear(4, 2)

    def forward(self, x):
        return self.fc3(self.fc2(self.fc1(x)))

class TestPyTorchWrapper(unittest.TestCase):
    def setUp(self):
        self.master_key = os.urandom(32)
        self.model = SimpleModel()
        
        # Calculate expected output on a dummy input
        self.dummy_input = torch.tensor([[1.0, 1.0, 1.0, 1.0]], dtype=torch.float32)
        with torch.no_grad():
            self.expected_output = self.model(self.dummy_input).numpy()

        # Compile the model weights offline
        from vajraa.compiler import compile_model_weights
        self.compiled_model = compile_model_weights(self.model.state_dict(), self.master_key)

    def test_secure_inference(self):
        # 1. Wrap the model (deletes original parameters in memory)
        secure_wrap_model(self.model, self.compiled_model, self.master_key)
        
        # Verify that original parameters are removed from memory at rest
        self.assertIsNone(getattr(self.model.fc, 'weight', None))
        self.assertIsNone(getattr(self.model.fc, 'bias', None))

        # 2. Run inference
        with torch.no_grad():
            output = self.model(self.dummy_input).numpy()

        # Verify output is mathematically identical
        np.testing.assert_array_almost_equal(self.expected_output, output, decimal=5)

        # 3. Verify memory is wiped after execution completes
        self.assertIsNone(getattr(self.model.fc, 'weight', None))
        self.assertIsNone(getattr(self.model.fc, 'bias', None))
        self.assertFalse(hasattr(self.model.fc, 'weight_transient'))
        self.assertFalse(hasattr(self.model.fc, 'bias_transient'))

        # 4. Verify model can be run a second time (hooks successfully decrypt and wipe again)
        with torch.no_grad():
            output_second = self.model(self.dummy_input).numpy()
        np.testing.assert_array_almost_equal(self.expected_output, output_second, decimal=5)
        
        # Verify memory remains wiped
        self.assertIsNone(getattr(self.model.fc, 'weight', None))
        self.assertIsNone(getattr(self.model.fc, 'bias', None))

    def test_3d_activation_tensor_obfuscated(self):
        from vajraa.compiler import compile_model_weights
        
        # Test 1: Math equivalence without mixer
        multi_model = MultiLayerModel()
        dummy_input_3d = torch.randn(2, 5, 4, dtype=torch.float32)
        
        with torch.no_grad():
            expected_output_3d = multi_model(dummy_input_3d).numpy()
            
        compiled_multi = compile_model_weights(multi_model.state_dict(), self.master_key)
        # Remove mixers to verify exact math equivalence
        compiled_multi["mixers"] = {}
        
        secure_wrap_model(multi_model, compiled_multi, self.master_key)
        
        with torch.no_grad():
            output_3d = multi_model(dummy_input_3d).numpy()
            
        np.testing.assert_array_almost_equal(expected_output_3d, output_3d, decimal=5)
        
        # Test 2: Execution works with mixer (transforms output)
        multi_model_with_mixer = MultiLayerModel()
        with torch.no_grad():
            expected_output_original = multi_model_with_mixer(dummy_input_3d).numpy()
            
        compiled_multi_with_mixer = compile_model_weights(multi_model_with_mixer.state_dict(), self.master_key)
        secure_wrap_model(multi_model_with_mixer, compiled_multi_with_mixer, self.master_key)
        
        with torch.no_grad():
            output_with_mixer = multi_model_with_mixer(dummy_input_3d).numpy()
            
        # Verify it runs successfully without crashing, but outputs are transformed by mixer
        self.assertEqual(output_with_mixer.shape, expected_output_original.shape)
        self.assertFalse(np.allclose(expected_output_original, output_with_mixer, atol=1e-4))

if __name__ == '__main__':
    unittest.main()
