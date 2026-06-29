# python/model_shield/__init__.py
__version__ = "0.1.0"

from .crypto import encrypt_tensor, decrypt_tensor, generate_license, decrypt_license
from .lora_shield import compile_lora_weights, secure_wrap_lora
from .base_shield import compile_base_weights, secure_wrap_base
from .onnx_compiler import rewrite_onnx_graph
from .onnx_wrapper import SecureONNXSession
