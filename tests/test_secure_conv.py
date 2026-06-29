# tests/test_secure_conv.py
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

class TestSecureConv(unittest.TestCase):
    def setUp(self):
        self.input_path = "test_conv_model.onnx"
        self.secure_path = "test_conv_model.ems"
        self.license_path = "test_conv_model.lic"
        self.master_key = os.urandom(32)
        self.customer_key = os.urandom(32)
        
        # 1. Build a dummy plaintext ONNX model with Conv
        # Shape: Input X [1, 1, 3, 3] -> Conv with W [1, 1, 2, 2] + Bias [1] -> Output Y [1, 1, 2, 2]
        x = helper.make_tensor_value_info('x', TensorProto.FLOAT, [1, 1, 3, 3])
        y = helper.make_tensor_value_info('y', TensorProto.FLOAT, [1, 1, 2, 2])
        
        self.w_val = np.array([[[[1.0, 2.0], [3.0, 4.0]]]], dtype=np.float32)
        w = helper.make_tensor('w', TensorProto.FLOAT, [1, 1, 2, 2], self.w_val.flatten().tolist())
        
        self.bias_val = np.array([0.5], dtype=np.float32)
        bias = helper.make_tensor('bias', TensorProto.FLOAT, [1], self.bias_val.tolist())
        
        conv = helper.make_node(
            'Conv',
            inputs=['x', 'w', 'bias'],
            outputs=['y'],
            name='conv_layer',
            kernel_shape=[2, 2],
            strides=[1, 1],
            pads=[0, 0, 0, 0],
            dilations=[1, 1]
        )
        graph = helper.make_graph([conv], 'test_conv_graph', [x], [y], [w, bias])
        model = helper.make_model(graph, producer_name='vajraa-test', opset_imports=[helper.make_opsetid("", 18)])
        onnx.save(model, self.input_path)
        
        # Define expected output
        self.dummy_x = np.ones((1, 1, 3, 3), dtype=np.float32)
        # Expected calculation: (1*1 + 1*2 + 1*3 + 1*4) + 0.5 = 10.5 for all elements
        self.expected_y = np.ones((1, 1, 2, 2), dtype=np.float32) * 10.5
        
        # 2. Compile model into secure format (.ems)
        rewrite_onnx_graph(self.input_path, self.secure_path, self.master_key)
        
        # 3. Generate license
        lic_bytes = generate_license("customer_conv_123", self.master_key, self.customer_key)
        with open(self.license_path, "wb") as f:
            f.write(lic_bytes)

    def tearDown(self):
        for path in [self.input_path, self.secure_path, self.license_path]:
            if os.path.exists(path):
                os.remove(path)

    def test_secure_conv_inference(self):
        # Verify graph rewriter replaced standard Conv with SecureConv
        model = onnx.load(self.secure_path)
        node_types = [node.op_type for node in model.graph.node]
        self.assertIn("SecureConv", node_types)
        self.assertNotIn("Conv", node_types)
        
        # Verify custom domain is "vajraa"
        secure_node = [n for n in model.graph.node if n.op_type == "SecureConv"][0]
        self.assertEqual(secure_node.domain, "vajraa")
        
        # Load and run secure session
        session = SecureONNXSession(self.secure_path, self.license_path, self.customer_key)
        outputs = session.run(["y"], {"x": self.dummy_x})
        
        # Verify output matches expected convolution calculation exactly
        np.testing.assert_array_almost_equal(self.expected_y, outputs[0], decimal=5)

if __name__ == '__main__':
    unittest.main()
