# src/entities/smart_device.py

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

class SmartDevice:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()

    def get_public_key(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    def sign_data(self, data):
        return self.private_key.sign(
            data,
            ec.ECDSA(hashes.SHA256())
        )

# Test
if __name__ == "__main__":
    device = SmartDevice()
    print(f"Smart Device Public Key: \n{device.get_public_key()}")

    message = b"Important Data"
    signature = device.sign_data(message)
    print(f"Signed Data: {signature}")
