# scripts/decrypt_test_from_file.py
import base64
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

PRIVATE_KEY_PATH = Path("student_private.pem")
B64_PATH = Path("scripts/encrypted_b64.txt")

def load_private_key(path: Path):
    pem = path.read_bytes()
    # If your private key has a password, change password=None to password=b"yourpassword"
    return serialization.load_pem_private_key(pem, password=None)

def main():
    print("Private key exists?:", PRIVATE_KEY_PATH.exists())
    print("B64 file exists?:", B64_PATH.exists())
    if not PRIVATE_KEY_PATH.exists():
        print("ERROR: private key not found at", PRIVATE_KEY_PATH.resolve()); return
    if not B64_PATH.exists():
        print("ERROR: b64 file not found at", B64_PATH.resolve()); return

    b64 = B64_PATH.read_text(encoding="utf-8").strip()
    print("Loaded base64 length:", len(b64))
    print("Preview first 60 chars:", b64[:60])
    print("Preview last 60 chars:", b64[-60:])

    try:
        ct = base64.b64decode(b64, validate=True)
        print("Base64 -> decoded bytes length:", len(ct))
    except Exception as e:
        print("ERROR: invalid base64:", repr(e))
        return

    try:
        priv = load_private_key(PRIVATE_KEY_PATH)
    except Exception as e:
        print("ERROR: failed loading private key:", repr(e))
        return

    try:
        pt = priv.decrypt(
            ct,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(),
                         label=None)
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
