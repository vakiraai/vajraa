# python/vajraa/onnx_compiler.py
import onnx
from onnx import helper, TensorProto, numpy_helper
import numpy as np
import hashlib
from .crypto import encrypt_tensor

def rewrite_onnx_graph(input_path: str, output_path: str, master_key: bytes, layers_to_encrypt: list = None):
    """
    Parses a standard ONNX model and rewrites the graph.
    1. Identifies Gemm, MatMul, and Conv layers to encrypt.
    2. Encrypts weight initializers using AES-256-GCM.
    3. Replaces standard nodes with Custom Secure Nodes (domain='vajraa', type='SecureGemm' / 'SecureConv').
    """
    # Load standard model
    model = onnx.load(input_path)
    graph = model.graph
    
    # Derive sub-keys
    key_crypto = hashlib.sha256(master_key + b"_crypto").digest()
    
    # Track initializers by name for easy lookup
    initializers = {init.name: init for init in graph.initializer}
    
    # List of new nodes we will construct
    new_nodes = []
    
    # Keep track of nodes we modified
    modified_node_count = 0

    for node in graph.node:
        is_modified = False
        
        # Check for Gemm / MatMul layers
        if node.op_type in ["Gemm", "MatMul"]:
            # Standard Gemm inputs: Input (0), Weight (1), Bias (2, optional)
            weight_name = node.input[1]
            
            # If the weight is a static initializer and matches our target list
            if weight_name in initializers:
                if layers_to_encrypt is None or weight_name in layers_to_encrypt:
                    # 1. Extract the plaintext weights
                    init_tensor = initializers[weight_name]
                    weight_np = numpy_helper.to_array(init_tensor).copy()
                    
                    # 2. Encrypt weights using AES
                    enc_dict = encrypt_tensor(weight_np, key_crypto)
                    
                    # 3. Create a new encrypted initializer containing the ciphertext bytes
                    # We store it as a flat uint8/int8 byte array
                    import base64
                    cipher_bytes = base64.b64decode(enc_dict["ciphertext"])
                    enc_init_name = f"{weight_name}_encrypted"
                    
                    enc_init = helper.make_tensor(
                        name=enc_init_name,
                        data_type=TensorProto.UINT8,
                        dims=[len(cipher_bytes)],
                        vals=cipher_bytes,
                        raw=True
                    )
                    graph.initializer.append(enc_init)
                    
                    # Also store IV and Tag as initializers
                    iv_bytes = base64.b64decode(enc_dict["iv"])
                    tag_bytes = base64.b64decode(enc_dict["tag"])
                    
                    iv_init = helper.make_tensor(f"{weight_name}_iv", TensorProto.UINT8, [len(iv_bytes)], vals=iv_bytes, raw=True)
                    tag_init = helper.make_tensor(f"{weight_name}_tag", TensorProto.UINT8, [len(tag_bytes)], vals=tag_bytes, raw=True)
                    graph.initializer.append(iv_init)
                    graph.initializer.append(tag_init)
                    
                    # 4. Remove original plaintext initializer to prevent it from saving
                    graph.initializer.remove(init_tensor)
                    del initializers[weight_name]
                    
                    # 5. Create the custom SecureGemm operator node
                    # Custom inputs: Input, Encrypted_Weights, IV, Tag, [Bias]
                    custom_inputs = [node.input[0], enc_init_name, f"{weight_name}_iv", f"{weight_name}_tag"]
                    if len(node.input) > 2:
                        custom_inputs.append(node.input[2]) # Keep bias as is or encrypt it
                        
                    secure_node = helper.make_node(
                        op_type="SecureGemm",
                        inputs=custom_inputs,
                        outputs=node.output,
                        name=f"{node.name}_secure",
                        domain="vajraa",
                        # Pass shape metadata as attributes
                        shape=enc_dict["shape"],
                        dtype=enc_dict["dtype"]
                    )
                    new_nodes.append(secure_node)
                    is_modified = True
                    modified_node_count += 1

        elif node.op_type in ["Conv", "ConvTranspose"]:
            weight_name = node.input[1]
            
            # If the weight is a static initializer and matches our target list
            if weight_name in initializers:
                if layers_to_encrypt is None or weight_name in layers_to_encrypt:
                    # 1. Extract the plaintext weights
                    init_tensor = initializers[weight_name]
                    weight_np = numpy_helper.to_array(init_tensor).copy()
                    
                    # 2. Encrypt weights using AES
                    enc_dict = encrypt_tensor(weight_np, key_crypto)
                    
                    # 3. Create a new encrypted initializer containing the ciphertext bytes
                    import base64
                    cipher_bytes = base64.b64decode(enc_dict["ciphertext"])
                    enc_init_name = f"{weight_name}_encrypted"
                    
                    enc_init = helper.make_tensor(
                        name=enc_init_name,
                        data_type=TensorProto.UINT8,
                        dims=[len(cipher_bytes)],
                        vals=cipher_bytes,
                        raw=True
                    )
                    graph.initializer.append(enc_init)
                    
                    # Also store IV and Tag as initializers
                    iv_bytes = base64.b64decode(enc_dict["iv"])
                    tag_bytes = base64.b64decode(enc_dict["tag"])
                    
                    iv_init = helper.make_tensor(f"{weight_name}_iv", TensorProto.UINT8, [len(iv_bytes)], vals=iv_bytes, raw=True)
                    tag_init = helper.make_tensor(f"{weight_name}_tag", TensorProto.UINT8, [len(tag_bytes)], vals=tag_bytes, raw=True)
                    graph.initializer.append(iv_init)
                    graph.initializer.append(tag_init)
                    
                    # 4. Remove original plaintext initializer to prevent it from saving
                    graph.initializer.remove(init_tensor)
                    del initializers[weight_name]
                    
                    # 5. Create the custom SecureConv / SecureConvTranspose operator node
                    custom_inputs = [node.input[0], enc_init_name, f"{weight_name}_iv", f"{weight_name}_tag"]
                    if len(node.input) > 2:
                        custom_inputs.append(node.input[2]) # Keep bias as is
                        
                    op_type = "SecureConv" if node.op_type == "Conv" else "SecureConvTranspose"
                    secure_node = helper.make_node(
                        op_type=op_type,
                        inputs=custom_inputs,
                        outputs=node.output,
                        name=f"{node.name}_secure",
                        domain="vajraa",
                        # Pass shape metadata as attributes
                        shape=enc_dict["shape"],
                        dtype=enc_dict["dtype"]
                    )
                    # Copy all attributes (pads, strides, dilations, group, etc.) from standard node
                    secure_node.attribute.extend(node.attribute)
                    
                    new_nodes.append(secure_node)
                    is_modified = True
                    modified_node_count += 1

        if not is_modified:
            # Keep original node
            new_nodes.append(node)

    # Replace old nodes list with our rewritten list
    del graph.node[:]
    graph.node.extend(new_nodes)
    
    # Save modified ONNX graph
    onnx.save(model, output_path)
    return modified_node_count
