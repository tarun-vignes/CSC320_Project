import base64
import hmac
import hashlib
import time
from datetime import datetime, timezone
import argparse

def normalize_base32(secret):
    # Pad with "=" to make the length a multiple of 8
    while len(secret) % 8 != 0:
        secret += '='
    return secret

def truncate(hmac_hash):
    offset = hmac_hash[-1] & 0x0F
    truncated_bytes = hmac_hash[offset:offset+4]
    binary = int.from_bytes(truncated_bytes, byteorder='big')
    binary &= 0x7FFFFFFF  # clear the most significant bit
    return binary % 10**6  # return the last 6 digits

def generate_otp(secret, epoch_str, interval=30):
    secret = normalize_base32(secret)
    key = base64.b32decode(secret, casefold=True)

    # Parse epoch datetime
    epoch_dt = datetime.strptime(epoch_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    
    # Get current UTC time
    now_dt = datetime.now(timezone.utc)
    
    # Calculate number of intervals since epoch
    delta_seconds = int((now_dt - epoch_dt).total_seconds())
    counter = delta_seconds // interval
    
    # Convert counter to an 8-byte array (big-endian)
    counter_bytes = counter.to_bytes(8, byteorder='big')
    
    # HMAC-SHA-1
    hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()

    # Truncate
    otp = truncate(hmac_hash)
    return f"{otp:06d}"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Tweaked TOTP Generator")
    parser.add_argument("secret", help="HOTP shared secret (base32)")
    parser.add_argument("epoch", help="Epoch datetime (format: YYYY-MM-DD HH:MM:SS)")
    parser.add_argument("--interval", type=int, default=30, help="OTP time interval (default: 30 seconds)")
    
    args = parser.parse_args()
    otp = generate_otp(args.secret, args.epoch, args.interval)
    print(otp)
