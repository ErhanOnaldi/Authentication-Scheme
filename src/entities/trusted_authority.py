# src/entities/trusted_authority.py

import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from src.utils.crypto import h0, h1, h2, generate_nonce

class TrustedAuthority:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        self.x = generate_nonce()  # Master key
        self.G = ec.SECP256R1().generator  # Elliptic curve generator point

    def get_public_key(self):
        """
        Güvenilir otoritenin genel anahtarını PEM formatında döndürür.
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    def get_private_key(self):
        """
        Güvenilir otoritenin özel anahtarını döndürür.
        """
        return self.private_key

    def generate_timestamp(self):
        """
        Şu anki zamanı unix timestamp olarak döndürür.
        """
        return int(time.time())

    def process_registration(self, request):
        """
        Kullanıcı kayıt işlemini gerçekleştirir.

        :param request: Kayıt isteği (UIDi içermeli)
        :return: Kayıt cevabı (Vi ve RTi içerir)
        """
        UIDi = request['UIDi']
        e = generate_nonce()
        RTi = self.generate_timestamp()

        mi = h1(self.x + e) * self.G  # mi = h1(x∥e).G
        Hn = h1(UIDi + str(mi) + str(RTi))
        Vi = h1(self.x + e) ^ h2(UIDi)

        return {"Vi": Vi, "RTi": RTi}

# Test
if __name__ == "__main__":
    ta = TrustedAuthority()
    print(f"Trusted Authority Public Key: \n{ta.get_public_key()}")

    # Test registration process
    test_request = {"UIDi": b"test_user_id"}
    registration_response = ta.process_registration(test_request)
    print(f"Registration Response: {registration_response}")