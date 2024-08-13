# src/entities/trusted_authority.py

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

class TrustedAuthority:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()

    def get_public_key(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    def get_private_key(self):
        return self.private_key

# Test
if __name__ == "__main__":
    ta = TrustedAuthority()
    print(f"Trusted Authority Public Key: \n{ta.get_public_key()}")
