# scripts/generate_proof.py

import sys
import os
sys.path.append(os.getcwd()) 
import subprocess # <- REQUIRED for git log
import base64     # <- REQUIRED for base64.b64encode

# CRITICAL FIX: Adds the project root to the search path to find 'app'


# This line imports functions from your utility file
# NOTE: Assuming your utility file is named crypto_utils.py (not cryptos_utils.py)
from app.crypto_utils import sign_message, encrypt_with_public_key, load_private_key, load_public_key 

# --- Constants ---
STUDENT_PRIVATE_KEY_PATH = "student_private.pem"
INSTRUCTOR_PUBLIC_KEY_PATH = "instructor_public.pem"

def generate_commit_proof():
    # CRITICAL: Ensure all code is committed before running this!

    # 1. Get current commit hash
    try:
        # Use subprocess to execute the git command
        result = subprocess.run(
            ['git', 'log', '-1', '--format=%H'], 
            capture_output=True, 
            text=True, 
            check=True
        )
        commit_hash = result.stdout.strip()
    except subprocess.CalledProcessError:
        print("ERROR: Git command failed. Ensure your code is committed.")
        return None, None
    
    print(f"Commit Hash: {commit_hash}")

    # 2. Load student private key
    student_private_key = load_private_key(STUDENT_PRIVATE_KEY_PATH)
    
    # 3. Sign commit hash with student private key (RSA-PSS)
    signature = sign_message(commit_hash, student_private_key)
    
    # 4. Load instructor public key
    instructor_public_key = load_public_key(INSTRUCTOR_PUBLIC_KEY_PATH)

    # 5. Encrypt signature with instructor public key (RSA/OAEP)
    encrypted_signature = encrypt_with_public_key(signature, instructor_public_key)

    # 6. Base64 encode encrypted signature
    base64_proof = base64.b64encode(encrypted_signature).decode('utf-8')
    
    print(f"Encrypted Signature: {base64_proof}")
    return commit_hash, base64_proof

if __name__ == "__main__":
    generate_commit_proof()