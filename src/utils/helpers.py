# src/utils/helpers.py

import time
import os
import hashlib

# Zaman damgası oluşturma
def generate_timestamp() -> int:
    return int(time.time())

# Nonce (tek kullanımlık sayı) üretme
def generate_nonce(length: int = 16) -> bytes:
    return os.urandom(length)

# Birleştirilmiş dizileri hashleme
def combine_and_hash(*args: bytes) -> bytes:
    combined = b''.join(args)
    return hashlib.sha256(combined).digest()
