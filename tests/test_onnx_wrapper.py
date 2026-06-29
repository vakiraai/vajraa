# tests/test_onnx_wrapper.py
import unittest
import onnx
from onnx import helper, TensorProto
import onnxruntime as ort
import numpy as np
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../python')))

from vajraa.onnx_compiler import rewrite_onnx_graph
from vajraa.onnx_wrapper import SecureONNXSession
from vajraa.crypto import generate_license
from vajraa.pal import pal_store_key

class TestONNXWrapper(unittest.TestCase):
    def setUp(self):
        self.input_path = "test_model.onnx"
        self.secure_path = "test_model.ems"
        self.license_path = "test_model.lic"
        self.master_key = os.urandom(32)
        self.customer_key = os.urandom(32)
        
        # 1. Build a dummy plaintext ONNX model
        # Shape: Input X [1, 4] -> MatMul with W [2, 4]^T -> Output Y [1, 2]
        x = helper.make_tensor_value_info('x', TensorProto.FLOAT, [1, 4])
        y = helper.make_tensor_value_info('y', TensorProto.FLOAT, [1, 2])
        
        self.w_val = np.array([[1.0, 2.0, 3.0, 4.0], [0.5, 0.5, 0.5, 0.5]], dtype=np.float32)
        w = helper.make_tensor('w', TensorProto.FLOAT, [2, 4], self.w_val.flatten().tolist())
        
        gemm = helper.make_node('Gemm', ['x', 'w'], ['y'], name='fc')
        graph = helper.make_graph([gemm], 'test_graph', [x], [y], [w])
        model = helper.make_model(graph, producer_name='vajraa-test', opset_imports=[helper.make_opsetid("", 18)])
        onnx.save(model, self.input_path)
        
        # Determine expected output
        self.dummy_x = np.array([[1.0, 2.0, 3.0, 4.0]], dtype=np.float32)
        self.expected_y = np.matmul(self.dummy_x, self.w_val.T)
        
        # 2. Compile model into secure format (.ems)
        rewrite_onnx_graph(self.input_path, self.secure_path, self.master_key)
        
        # 3. Generate wrapped license
        lic_bytes = generate_license("customer_123", self.master_key, self.customer_key)
        with open(self.license_path, "wb") as f:
            f.write(lic_bytes)

    def tearDown(self):
        if os.path.exists(self.input_path):
            os.remove(self.input_path)
        if os.path.exists(self.secure_path):
            os.remove(self.secure_path)
        if os.path.exists(self.license_path):
            os.remove(self.license_path)

    def test_secure_onnx_inference(self):
        # Load and run secure model
        session = SecureONNXSession(self.secure_path, self.license_path, self.customer_key)
        outputs = session.run(["y"], {"x": self.dummy_x})
        
        # Verify output matches expected plaintext inference exactly
        np.testing.assert_array_almost_equal(self.expected_y, outputs[0], decimal=5)

if __name__ == '__main__':
    unittest.main()
