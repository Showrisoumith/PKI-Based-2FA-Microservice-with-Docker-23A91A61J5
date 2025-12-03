# In app/crypto_utils.py

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64
import subprocess

def sign_message(message: str, private_key) -> bytes:
    """Signs a message using RSA-PSS with SHA-256."""
    message_bytes = message.encode('utf-8')
    
    # CRITICAL: Use PSS padding with SHA256 hashing and MGF1
    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH 
        ),
        hashes.SHA256()
    )
    return signature

# In app/crypto_utils.py (continued)

def encrypt_with_public_key(data: bytes, public_key) -> bytes:
    """Encrypts data using RSA/OAEP with public key."""
    # CRITICAL: Use OAEP padding with SHA256 hashing and MGF1
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# (Add helper functions load_private_key and load_public_key here as well)
def load_private_key(path):
    with open(path, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())

def load_public_key(path):
    with open(path, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read(), backend=default_backend())
    
