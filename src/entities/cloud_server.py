# src/entities/cloud_server.py

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

class CloudServer:
    def __init__(self, ta_public_key):
        """
        Cloud Server'ı başlatır.

        :param ta_public_key: Trusted Authority'nin genel anahtarı (PEM formatında)
        """
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        self.ta_public_key = serialization.load_pem_public_key(ta_public_key.encode())
        self.user_database = {}

    def get_public_key(self):
        """
        Cloud Server'ın genel anahtarını PEM formatında döndürür.
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    def register_user(self, user_id, user_public_key_pem):
        """
        Yeni bir kullanıcıyı kaydeder.

        :param user_id: Kullanıcı ID'si
        :param user_public_key_pem: Kullanıcının genel anahtarı (PEM formatında)
        """
        if user_id in self.user_database:
            raise ValueError("User ID already exists")
        try:
            # Genel anahtarın geçerliliğini kontrol et
            serialization.load_pem_public_key(user_public_key_pem.encode())
        except ValueError:
            raise ValueError("Invalid public key format")
        
        self.user_database[user_id] = user_public_key_pem

    def authenticate_user(self, user_id, data, signature):
        """
        Kullanıcının kimliğini doğrular.

        :param user_id: Kullanıcı ID'si
        :param data: İmzalanmış veri
        :param signature: Verinin imzası
        :return: Kimlik doğrulama başarılı ise True, değilse False
        """
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
        except InvalidSignature:
            return False

# Test
if __name__ == "__main__":
    # Trusted Authority'yi oluştur
    from trusted_authority import TrustedAuthority
    ta = TrustedAuthority()

    # Cloud Server'ı başlat
    server = CloudServer(ta.get_public_key())
    print(f"Cloud Server Public Key: \n{server.get_public_key()}")

    # Test: Kullanıcı kaydı
    test_user_private_key = ec.generate_private_key(ec.SECP256R1())
    test_user_public_key = test_user_private_key.public_key()
    test_user_public_key_pem = test_user_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    server.register_user("test_user", test_user_public_key_pem)
    print("Test user registered successfully")

    # Test: Kullanıcı kimlik doğrulama
    test_data = b"Test authentication data"
    test_signature = test_user_private_key.sign(
        test_data,
        ec.ECDSA(hashes.SHA256())
    )

    auth_result = server.authenticate_user("test_user", test_data, test_signature)
    print(f"Authentication result: {auth_result}")

    # Test: Var olmayan kullanıcı kimlik doğrulama
    non_existent_auth_result = server.authenticate_user("non_existent_user", test_data, test_signature)
    print(f"Non-existent user authentication result: {non_existent_auth_result}")