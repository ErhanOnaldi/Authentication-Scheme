# src/entities/fog_node.py

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

class FogNode:
    def __init__(self):
        """
        Fog Node'u başlatır ve ECC anahtar çiftini oluşturur.
        """
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()

    def get_public_key(self):
        """
        Fog Node'un genel anahtarını PEM formatında döndürür.
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    def encrypt_data(self, data, public_key_pem):
        """
        Veriyi ECIES kullanarak şifreler.

        :param data: Şifrelenecek veri (bytes)
        :param public_key_pem: Alıcının genel anahtarı (PEM formatında)
        :return: Şifrelenmiş veri (bytes)
        """
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode())
            ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
            shared_key = ephemeral_private_key.exchange(ec.ECDH(), public_key)
            
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
            ).derive(shared_key)

            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv))
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(data) + encryptor.finalize()

            ephemeral_public_key = ephemeral_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            return ephemeral_public_key + iv + encrypted_data
        except Exception as e:
            raise ValueError(f"Encryption failed: {str(e)}")

    def decrypt_data(self, encrypted_data):
        """
        ECIES ile şifrelenmiş veriyi çözer.

        :param encrypted_data: Çözülecek veri (bytes)
        :return: Çözülmüş veri (bytes)
        """
        try:
            ephemeral_public_key = serialization.load_pem_public_key(encrypted_data[:450])
            iv = encrypted_data[450:466]
            ciphertext = encrypted_data[466:]

            shared_key = self.private_key.exchange(ec.ECDH(), ephemeral_public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
            ).derive(shared_key)

            cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv))
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")

# Test
if __name__ == "__main__":
    fog_node = FogNode()
    print(f"Fog Node Public Key: \n{fog_node.get_public_key()}")

    # Test: Veri şifreleme ve çözme
    test_data = b"This is a test message for encryption and decryption"
    encrypted_data = fog_node.encrypt_data(test_data, fog_node.get_public_key())
    decrypted_data = fog_node.decrypt_data(encrypted_data)

    print(f"Original data: {test_data}")
    print(f"Decrypted data: {decrypted_data}")
    print(f"Encryption and decryption successful: {test_data == decrypted_data}")