#!/usr/bin/env python3
import os
import pyotp
import base64
import datetime
import binascii

# --- Configuration ---
SEED_FILE = "/data/seed.txt"
TIME_STEP = 30 # Standard TOTP time step in seconds

try:
    # 1. Read hex seed from persistent storage
    with open(SEED_FILE, 'r') as f:
        # Read and strip whitespace, which usually includes the newline
        hex_seed = f.read().strip()

    if not hex_seed:
        print(f"ERROR: {SEED_FILE} is empty.")
        exit(1)

    # Convert hex seed to bytes for Base32 encoding
    seed_bytes = binascii.unhexlify(hex_seed)
    
    # Convert bytes to Base32 for pyotp
    # base64.b32encode requires bytes, and strips padding '='
    base32_seed = base64.b32encode(seed_bytes).decode().replace('=', '')
    
    # 2. Generate current TOTP code
    # Use the same TOTP generation function/parameters as the microservice
    totp = pyotp.TOTP(base32_seed, interval=TIME_STEP)
    code = totp.now()

    # 3. Get current UTC timestamp
    # Ensure timezone awareness and format
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    timestamp_str = now_utc.strftime("%Y-%m-%d %H:%M:%S")

    # 4. Output formatted line to stdout (which cron appends to a file)
    print(f"{timestamp_str} - 2FA Code: {code}")

except FileNotFoundError:
    print(f"ERROR: Seed file not found at {SEED_FILE}")
except binascii.Error:
    print("ERROR: Seed is not valid hexadecimal.")
except Exception as e:
    print(f"An unexpected error occurred: {e}")