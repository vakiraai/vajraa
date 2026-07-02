# python/model_shield/crypto.py
import os
import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import json

def encrypt_tensor(tensor_np: np.ndarray, key: bytes, aad: bytes = None) -> dict:
    """
    Encrypts a numpy array using AES-256-GCM with optional AAD.
    Returns a dict containing the ciphertext, IV, tag, shape, and dtype.
    """
    import base64
    # Convert numpy array to raw bytes
    raw_data = tensor_np.tobytes()
    
    # Generate 12-byte IV for GCM
    iv = os.urandom(12)
    
    # Initialize AES-256-GCM cipher
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    
    if aad:
        encryptor.authenticate_additional_data(aad)
        
    # Encrypt
    ciphertext = encryptor.update(raw_data) + encryptor.finalize()
    
    return {
        "iv": base64.b64encode(iv).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "tag": base64.b64encode(encryptor.tag).decode("utf-8"),
        "shape": list(tensor_np.shape),
        "dtype": str(tensor_np.dtype)
    }

class SecurityError(Exception):
    """Custom exception raised for security-related validation and decryption failures."""
    pass

def decrypt_tensor(enc_dict: dict, key: bytes, aad: bytes = None) -> np.ndarray:
    """
    Decrypts an encrypted tensor dict and reconstructs the numpy array.
    Raises SecurityError on validation or decryption failure.
    """
    import base64
    try:
        iv = base64.b64decode(enc_dict["iv"])
        ciphertext = base64.b64decode(enc_dict["ciphertext"])
        tag = base64.b64decode(enc_dict["tag"])
        shape = enc_dict["shape"]
        dtype = enc_dict["dtype"]
        
        # Initialize AES-256-GCM decryptor
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()
        
        if aad:
            decryptor.authenticate_additional_data(aad)
            
        # Decrypt
        raw_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Convert back to numpy array
        arr = np.frombuffer(raw_data, dtype=dtype).copy()
        return arr.reshape(shape)
    except Exception as e:
        raise SecurityError("Tensor decryption failed") from None

def generate_license(customer_id: str, master_key: bytes, customer_key: bytes, expiry_days: float = None) -> bytes:
    """
    Generates a license byte stream by wrapping (encrypting) the master key 
    using the customer's specific key.
    """
    import base64
    import time
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(customer_key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    
    # Package metadata with the master key wrapped using RFC 3394 AES Key Wrap
    from cryptography.hazmat.primitives.keywrap import aes_key_wrap
    wrapped_master = aes_key_wrap(customer_key, master_key)
    
    license_data = {
        "customer_id": customer_id,
        "master_key": base64.b64encode(wrapped_master).decode("utf-8")
    }
    if expiry_days is not None:
        license_data["expires_at"] = time.time() + (expiry_days * 86400.0)
        
    raw_lic = json.dumps(license_data).encode("utf-8")
    
    ciphertext = encryptor.update(raw_lic) + encryptor.finalize()
    
    # Return serializable dict as bytes
    wrapped_license = {
        "iv": base64.b64encode(iv).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "tag": base64.b64encode(encryptor.tag).decode("utf-8")
    }
    return json.dumps(wrapped_license).encode("utf-8")

def decrypt_license(license_bytes: bytes, customer_key: bytes) -> dict:
    """
    Decrypts the license file to extract the master model key.
    Raises SecurityError on validation or decryption failure.
    """
    import base64
    import time
    try:
        wrapped_license = json.loads(license_bytes.decode("utf-8"))
        iv = base64.b64decode(wrapped_license["iv"])
        ciphertext = base64.b64decode(wrapped_license["ciphertext"])
        tag = base64.b64decode(wrapped_license["tag"])
        
        decryptor = Cipher(
            algorithms.AES(customer_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()
        
        raw_lic = decryptor.update(ciphertext) + decryptor.finalize()
        license_data = json.loads(raw_lic.decode("utf-8"))
        
        # Check expiry if present
        if "expires_at" in license_data:
            if time.time() > license_data["expires_at"]:
                raise SecurityError("License has expired")
                
        # Unwrap the master key using RFC 3394 AES Key Unwrap
        from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
        wrapped_master = base64.b64decode(license_data["master_key"])
        license_data["master_key"] = aes_key_unwrap(customer_key, wrapped_master)
        return license_data
    except SecurityError:
        raise
    except Exception as e:
        raise SecurityError("License verification failed") from None
