# scripts/decrypt_test.py
import base64
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# CONFIG: ensure this points to your private key file
PRIVATE_KEY_PATH = Path("student_private.pem")

# Paste the encrypted Base64 string you generated (the full line) below:
ENCRYPTED_B64 = (
    "PASTE_YOUR_FULL_BASE64_HERE"
)

def load_private_key(path: Path):
    pem = path.read_bytes()
    # If key is password protected, change password=None to password=b"yourpassword"
    return serialization.load_pem_private_key(pem, password=None)

def main():
    if not PRIVATE_KEY_PATH.exists():
        print("ERROR: private key not found at", PRIVATE_KEY_PATH.resolve())
        return

    try:
        priv = load_private_key(PRIVATE_KEY_PATH)
    except Exception as e:
        print("ERROR: failed loading private key:", repr(e))
        return

    try:
        ct = base64.b64decode(ENCRYPTED_B64)
    except Exception as e:
        print("ERROR: invalid base64:", repr(e))
        return

    try:
        pt = priv.decrypt(
            ct,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        print("ERROR: decryption failed:", repr(e))
        return

    try:
        decoded = pt.decode("utf-8")
    except Exception:
        decoded = repr(pt)

    print("Decryption succeeded. Plaintext (decoded):")
    print(decoded)
    print("Length:", len(decoded))

if __name__ == "__main__":
    main()
