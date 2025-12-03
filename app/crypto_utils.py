import base64
import os
import time
import binascii
import pyotp
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend


# --- UTILITY HELPERS ---

def load_private_key(path: str = "student_private.pem"):
    """Loads the RSA private key from a PEM file."""
    try:
        with open(path, "rb") as f:
            # Assuming no password is set
            return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    except Exception as e:
        # NOTE: When running in container, path is /app/student_private.pem
        print(f"ERROR: Failed to load or parse private key from {path}: {e}")
        return None

def load_public_key(path: str = "instructor_public.pem"):
    """Loads the RSA public key from a PEM file."""
    try:
        with open(path, "rb") as f:
            return serialization.load_pem_public_key(f.read(), backend=default_backend())
    except Exception as e:
        print(f"ERROR: Failed to load or parse public key from {path}: {e}")
        return None

def save_hex_seed(seed: str, path: str = "/data/seed.txt"):
    """Saves the decrypted seed to the persistent volume path."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True) 
        with open(path, 'w') as f:
            f.write(seed.strip())
            f.write("\n")
    except IOError as e:
        raise Exception(f"Failed to write seed to persistence path {path}: {e}")


# --- STEP 5: DECRYPTION LOGIC ---

def decrypt_seed(encrypted_seed_b64: str, private_key) -> str:
    """Decrypts base64-encoded encrypted seed using RSA/OAEP-SHA256."""
    if not private_key:
        raise Exception("Private key object is missing or failed to load.")

    try:
        ciphertext = base64.b64decode(encrypted_seed_b64)
    except base64.binascii.Error:
        raise ValueError("Input is not valid Base64.")

    try:
        plaintext_bytes = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception:
        raise Exception("Decryption failed (Key or Parameter Mismatch)")

    seed_hex = plaintext_bytes.decode("utf-8").strip()

    if len(seed_hex) != 64 or not all(c.lower() in set("0123456789abcdef") for c in seed_hex):
        raise ValueError(f"Invalid seed format: expected 64-char hex.")

    return seed_hex


# --- STEP 6: TOTP LOGIC ---

def hex_to_base32(hex_seed: str) -> str:
    """Converts a 64-character hex seed string into a Base32 encoded string."""
    try:
        seed_bytes = bytes.fromhex(hex_seed)
    except ValueError:
        raise ValueError("Invalid hex string provided for seed conversion.")

    # Base32 encoding (pyotp compatible)
    base32_seed = base64.b32encode(seed_bytes).decode('utf-8')
    return base32_seed

def generate_totp_code(hex_seed: str) -> dict:
    """Generate current TOTP code and remaining validity time."""
    base32_seed = hex_to_base32(hex_seed)
    totp = pyotp.TOTP(base32_seed) 
    
    code = totp.now()
    valid_for = 30 - (int(time.time()) % 30)
    
    return {"code": code, "valid_for": valid_for}

def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    """Verify TOTP code with time window tolerance."""
    base32_seed = hex_to_base32(hex_seed)
    totp = pyotp.TOTP(base32_seed)
    
    # Verify with valid_window=1 (current period +/- 1 period)
    is_valid = totp.verify(code, valid_window=valid_window)
    
    return is_valid


# --- STEP 13: PROOF GENERATION LOGIC (The Missing Functions) ---

def sign_message(message: str, private_key) -> bytes:
    """
    Sign a message using RSA-PSS with SHA-256 (for Step 13).
    (Padding: PSS, MGF: MGF1 with SHA-256, Salt Length: Maximum)
    """
    message_bytes = message.encode('utf-8')
    
    # Sign using RSA-PSS
    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH # Set Salt Length to Maximum
        ),
        hashes.SHA256()
    )
    return signature

def encrypt_with_public_key(data: bytes, public_key) -> bytes:
    """
    Encrypt data using RSA/OAEP with public key (for Step 13).
    (Padding: OAEP, MGF: MGF1 with SHA-256, Hash Algorithm: SHA-256)
    """
    # Encrypt signature bytes using RSA/OAEP
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# --- LOCAL TESTING ENTRY POINT ---

def run_local_test():
    """Local test function for Step 5 logic."""
    # (Existing local test logic here, using the functions above)
    pass 

if __name__ == "__main__":
    # If the file is executed directly, you might run run_local_test()
    pass