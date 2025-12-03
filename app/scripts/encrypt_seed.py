# scripts/encrypt_seed.py
import os
import base64
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# CONFIG: path to your student public key (adjust if different)
PUBKEY_PATH = Path("student_public.pem")

def generate_hex_seed() -> str:
    # 32 bytes -> 64 hex chars
    return os.urandom(32).hex()

def load_public_key(path: Path):
    pem = path.read_bytes()
    pub = serialization.load_pem_public_key(pem)
    return pub

def encrypt_seed_hex(hex_seed: str, public_key) -> bytes:
    # encrypt the raw bytes of the hex string
    plaintext = hex_seed.encode("utf-8")
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def main():
    if not PUBKEY_PATH.exists():
        print(f"Public key not found at: {PUBKEY_PATH.resolve()}")
        return

    hex_seed = generate_hex_seed()
    pub = load_public_key(PUBKEY_PATH)
    ct = encrypt_seed_hex(hex_seed, pub)
    b64 = base64.b64encode(ct).decode("ascii")

    print("---- COPY THESE VALUES ----")
    print("hex_seed (local validation, keep secret):")
    print(hex_seed)
    print()
    print("encrypted_seed (Base64) — send this value to POST /decrypt-seed:")
    print(b64)
    print("---------------------------")

if __name__ == "__main__":
    main()
