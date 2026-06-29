# tests/test_onnx_compiler.py
import unittest
import onnx
from onnx import helper, TensorProto
import numpy as np
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../python')))

from vajraa.onnx_compiler import rewrite_onnx_graph

class TestONNXCompiler(unittest.TestCase):
    def setUp(self):
        self.input_path = "dummy.onnx"
        self.output_path = "dummy.ems"
        self.master_key = os.urandom(32)
        
        # 1. Create a simple dummy ONNX model
        x = helper.make_tensor_value_info('x', TensorProto.FLOAT, [1, 4])
        y = helper.make_tensor_value_info('y', TensorProto.FLOAT, [1, 2])
        
        # Static weight initializer
        w_data = np.array([[1.0, 2.0, 3.0, 4.0], [5.0, 6.0, 7.0, 8.0]], dtype=np.float32)
        w = helper.make_tensor('w', TensorProto.FLOAT, [2, 4], w_data.flatten().tolist())
        
        # Gemm Node
        gemm = helper.make_node('Gemm', ['x', 'w'], ['y'], name='fc')
        
        graph = helper.make_graph([gemm], 'dummy_graph', [x], [y], [w])
        model = helper.make_model(graph, producer_name='vajraa-test', opset_imports=[helper.make_opsetid("", 18)])
        
        # Save plaintext ONNX
        onnx.save(model, self.input_path)

    def tearDown(self):
        # Clean up temporary files
        if os.path.exists(self.input_path):
            os.remove(self.input_path)
        if os.path.exists(self.output_path):
            os.remove(self.output_path)

    def test_onnx_rewrite(self):
        # 1. Compile/rewrite the ONNX graph
        modified_count = rewrite_onnx_graph(self.input_path, self.output_path, self.master_key)
        self.assertEqual(modified_count, 1)
        
        # 2. Load the compiled model and verify graph changes
        compiled_model = onnx.load(self.output_path)
        graph = compiled_model.graph
        
        # Verify the standard Gemm node has been replaced with SecureGemm
        node_types = [node.op_type for node in graph.node]
        self.assertIn("SecureGemm", node_types)
        self.assertNotIn("Gemm", node_types)
        
        # Verify the node belongs to the 'vajraa' domain
        secure_node = [node for node in graph.node if node.op_type == "SecureGemm"][0]
        self.assertEqual(secure_node.domain, "vajraa")
        
        # Verify the original plaintext weight initializer 'w' has been removed
        init_names = [init.name for init in graph.initializer]
        self.assertNotIn("w", init_names)
        
        # Verify new encrypted weight, IV, and tag initializers exist
        self.assertIn("w_encrypted", init_names)
        self.assertIn("w_iv", init_names)
        self.assertIn("w_tag", init_names)

if __name__ == '__main__':
    unittest.main()
