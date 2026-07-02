# tests/test_advanced_memory.py
import unittest
import torch
import torch.nn as nn
import numpy as np
import os
import sys
import tempfile

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../python')))

from vajraa.pal import pal_get_available_memory, IS_WINDOWS
from vajraa.compiler import compile_model_weights
from vajraa.pytorch_wrapper import secure_wrap_model, VajraaConfig
from vajraa.onnx_compiler import rewrite_onnx_graph
from vajraa.onnx_wrapper import SecureONNXSession
from vajraa.crypto import generate_license

class TestAdvancedMemoryControls(unittest.TestCase):
    def setUp(self):
        self.master_key = os.urandom(32)
        self.customer_key = os.urandom(32)
        self.temp_dir = tempfile.TemporaryDirectory()
        
    def tearDown(self):
        self.temp_dir.cleanup()
        
    def test_pal_memory_check(self):
        """Verify that available memory check runs and returns a valid value."""
        avail_ram = pal_get_available_memory()
        self.assertIsInstance(avail_ram, (int, float))
        self.assertGreater(avail_ram, 0)
        
    def test_model_metadata_compiled(self):
        """Verify that compile_model_weights creates the correct structure pre-analysis metadata."""
        model = nn.Sequential(
            nn.Linear(10, 20),
            nn.ReLU(),
            nn.Linear(20, 5)
        )
        compiled = compile_model_weights(model.state_dict(), self.master_key)
        
        self.assertIn("metadata", compiled)
        metadata = compiled["metadata"]
        self.assertIn("max_layer_size_bytes", metadata)
        self.assertIn("layer_sizes_dict", metadata)
        self.assertGreater(metadata["max_layer_size_bytes"], 0)
        
        # Verify that all layers have their sizes tracked
        for name in compiled["encrypted_layers"].keys():
            self.assertIn(name, metadata["layer_sizes_dict"])
        for name in compiled["obfuscated_layers"].keys():
            self.assertIn(name, metadata["layer_sizes_dict"])
            
    def test_pytorch_config_shuffling_and_tiered(self):
        """Test PyTorch execution using shuffling and tiered pools config."""
        model = nn.Sequential(nn.Linear(10, 5, bias=True))
        compiled = compile_model_weights(model.state_dict(), self.master_key)
        
        config = VajraaConfig(use_shuffling=True, use_tiered_pools=True)
        wrapped = secure_wrap_model(model, compiled, self.master_key, config=config)
        
        # Verify pool was created and attached to the model
        self.assertTrue(hasattr(model, "_vajraa_pool"))
        pool = model._vajraa_pool
        self.assertTrue(pool.is_initialized)
        self.assertGreater(len(pool.slots), 0)
        
        # Run inference and verify it completes successfully
        x = torch.randn(1, 10)
        out = model(x)
        self.assertEqual(out.shape, (1, 5))
        
        # Clean up pool
        pool.shutdown()
        
    def test_pytorch_config_lazy_init(self):
        """Verify lazy pool initialization delays slot creation until first run."""
        model = nn.Sequential(nn.Linear(10, 5, bias=False))
        compiled = compile_model_weights(model.state_dict(), self.master_key)
        
        config = VajraaConfig(use_shuffling=True, lazy_init=True)
        secure_wrap_model(model, compiled, self.master_key, config=config)
        
        pool = model._vajraa_pool
        # Pool should not be initialized yet
        self.assertFalse(pool.is_initialized)
        self.assertEqual(len(pool.slots), 0)
        
        # Run inference
        x = torch.randn(1, 10)
        _ = model(x)
        
        # Pool should now be initialized
        self.assertTrue(pool.is_initialized)
        self.assertGreater(len(pool.slots), 0)
        pool.shutdown()
        
    def test_pytorch_config_hybrid_mode(self):
        """Verify hybrid mode falls back to standard JIT if layer size exceeds cap."""
        model = nn.Sequential(nn.Linear(10, 5, bias=False))
        compiled = compile_model_weights(model.state_dict(), self.master_key)
        
        # Set a tiny cap size (e.g. 10 bytes) to force hybrid fallback
        config = VajraaConfig(use_shuffling=True, use_hybrid_mode=True, capped_pool_size_bytes=10)
        secure_wrap_model(model, compiled, self.master_key, config=config)
        
        # The pool should be None or not attached since fallback was triggered
        self.assertFalse(hasattr(model, "_vajraa_pool"))
        
        # Run inference to verify standard JIT fallback runs successfully
        x = torch.randn(1, 10)
        out = model(x)
        self.assertEqual(out.shape, (1, 5))
        
    def test_onnx_config_shuffling(self):
        """Test ONNX Runtime C++ page pool config and inference."""
        # 1. Create a dummy ONNX model
        model = nn.Sequential(nn.Linear(10, 5, bias=False))
        dummy_input = torch.randn(1, 10)
        onnx_path = os.path.join(self.temp_dir.name, "model.onnx")
        torch.onnx.export(model, dummy_input, onnx_path, input_names=["input"], output_names=["output"])
        
        # 2. Rewrite/encrypt graph
        secured_onnx_path = os.path.join(self.temp_dir.name, "model.ems")
        rewrite_onnx_graph(onnx_path, secured_onnx_path, self.master_key)
        
        # 3. Create license
        license_path = os.path.join(self.temp_dir.name, "license.lic")
        lic_bytes = generate_license("customer_123", self.master_key, self.customer_key, expiry_days=30)
        with open(license_path, "wb") as f:
            f.write(lic_bytes)
            
        # 4. Load session with shuffling enabled
        config = VajraaConfig(use_shuffling=True, use_tiered_pools=True)
        session = SecureONNXSession(secured_onnx_path, license_path, self.customer_key, config=config)
        
        # 5. Run inference to check C++ pool leases
        x_np = np.random.randn(1, 10).astype(np.float32)
        outputs = session.run(["output"], {"input": x_np})
        self.assertEqual(outputs[0].shape, (1, 5))

    def test_pytorch_dynamic_compaction(self):
        """Verify PyTorch memory pool automatically compacts (releases slots) on idle timeout."""
        import time
        model = nn.Sequential(nn.Linear(10, 5, bias=False))
        compiled = compile_model_weights(model.state_dict(), self.master_key)
        
        # Configure a short idle timeout of 0.2 seconds
        config = VajraaConfig(use_shuffling=True, idle_timeout=0.2)
        secure_wrap_model(model, compiled, self.master_key, config=config)
        
        pool = model._vajraa_pool
        # Run inference to initialize and lease
        x = torch.randn(1, 10)
        _ = model(x)
        
        self.assertTrue(pool.is_initialized)
        self.assertGreater(len(pool.slots), 0)
        
        # Wait for timeout to fire compaction
        time.sleep(0.4)
        
        # Pool should now be compacted and de-initialized
        self.assertFalse(pool.is_initialized)
        self.assertEqual(len(pool.slots), 0)
        
        # Run inference again to verify lazy re-initialization works transparently
        _ = model(x)
        self.assertTrue(pool.is_initialized)
        pool.shutdown()

    def test_pytorch_double_mapping(self):
        """Verify PyTorch double-mapping view isolation behaves correctly."""
        model = nn.Sequential(nn.Linear(10, 5, bias=False))
        compiled = compile_model_weights(model.state_dict(), self.master_key)
        
        # Enable double-mapping
        config = VajraaConfig(use_shuffling=True, use_double_mapping=True)
        secure_wrap_model(model, compiled, self.master_key, config=config)
        
        # Verify slot attributes
        pool = model._vajraa_pool
        pool.initialize()
        for slot in pool.slots:
            self.assertIsNotNone(slot.write_ptr)
            self.assertIsNotNone(slot.read_ptr)
            self.assertIsNone(slot.ptr)
            
        x = torch.randn(1, 10)
        out = model(x)
        self.assertEqual(out.shape, (1, 5))
        pool.shutdown()

    def test_onnx_dynamic_compaction(self):
        """Verify ONNX Runtime C++ level memory pool compaction triggers via timer."""
        import time
        model = nn.Sequential(nn.Linear(10, 5, bias=False))
        dummy_input = torch.randn(1, 10)
        onnx_path = os.path.join(self.temp_dir.name, "model_comp.onnx")
        torch.onnx.export(model, dummy_input, onnx_path, input_names=["input"], output_names=["output"])
        
        secured_onnx_path = os.path.join(self.temp_dir.name, "model_comp.ems")
        rewrite_onnx_graph(onnx_path, secured_onnx_path, self.master_key)
        
        license_path = os.path.join(self.temp_dir.name, "license_comp.lic")
        lic_bytes = generate_license("customer_123", self.master_key, self.customer_key, expiry_days=30)
        with open(license_path, "wb") as f:
            f.write(lic_bytes)
            
        # Set a short idle timeout of 0.2 seconds
        config = VajraaConfig(use_shuffling=True, idle_timeout=0.2)
        session = SecureONNXSession(secured_onnx_path, license_path, self.customer_key, config=config)
        
        # Run inference
        x_np = np.random.randn(1, 10).astype(np.float32)
        outputs = session.run(["output"], {"input": x_np})
        self.assertEqual(outputs[0].shape, (1, 5))
        
        # Wait for dynamic cache compaction to fire in C++
        time.sleep(0.4)
        
        # Run inference again to check lazy re-allocation is transparent
        outputs2 = session.run(["output"], {"input": x_np})
        self.assertEqual(outputs2[0].shape, (1, 5))

if __name__ == "__main__":
    unittest.main()
