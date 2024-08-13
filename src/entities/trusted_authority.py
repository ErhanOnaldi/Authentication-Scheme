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
    def process_registration(self, request):
        UIDi = request['UIDi']
        e = self.generate_nonce()
        RTi = self.generate_timestamp()

        mi = h1(str(x) + str(e)) * self.G  # mi = h1(x∥e).G
        Hn = h1(UIDi + str(mi) + str(RTi))
        Vi = h1(str(x) + str(e)) ^ h2(UIDi)

        return {"Vi": Vi, "RTi": RTi}

# Test
if __name__ == "__main__":
    ta = TrustedAuthority()
    print(f"Trusted Authority Public Key: \n{ta.get_public_key()}")
