# src/entities/cloud_server.py

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

class CloudServer:
    def __init__(self, ta_public_key):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        self.ta_public_key = serialization.load_pem_public_key(ta_public_key.encode())
        self.user_database = {}

    def get_public_key(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    def register_user(self, user_id, user_public_key_pem):
        self.user_database[user_id] = user_public_key_pem

    def authenticate_user(self, user_id, data, signature):
        if user_id not in self.user_database:
            return False

        user_public_key = serialization.load_pem_public_key(
            self.user_database[user_id].encode()
        )
        try:
            user_public_key.verify(
                signature,
                data,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception:
            return False

# Test
if __name__ == "__main__":
    # Trusted Authority'yi oluştur
    from trusted_authority import TrustedAuthority
    ta = TrustedAuthority()

    # Cloud Server'ı başlat
    server = CloudServer(ta.get_public_key())
    print(f"Cloud Server Public Key: \n{server.get_public_key()}")
