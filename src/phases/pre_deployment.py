import os
import time
from cryptography.hazmat.primitives import serialization
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import sympy

class TrustedAuthority:
    def __init__(self, curve_name="secp384r1", polynomial_degree=3):
        self.curve = ec.SECP384R1()  # Makalede belirtilen eğri
        self.backend = default_backend()
        self.master_key = self._generate_master_key()
        self.public_key = self.master_key.public_key()
        self.p = sympy.randprime(2**383, 2**384)  
        self.f = self._generate_polynomial(polynomial_degree)
        self.g = self._generate_polynomial(polynomial_degree)
        self.order = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_C7634D81_F4372DDF_581A0DB2_48B0A77A_ECEC196A_CCC52973
        self.h0 = self._hash_function  # h0, h1, h2 aynı fonksiyonu kullanıyor
        self.h1 = self._hash_function
        self.h2 = self._hash_function

    def _generate_master_key(self):
        return ec.generate_private_key(self.curve, self.backend)

    def _generate_polynomial(self, degree):
        x, y, z = sympy.symbols('x y z')
        terms = []
        for i in range(degree + 1):
            for j in range(degree + 1):
                for k in range(degree + 1):
                    coeff = secrets.randbelow(self.p)
                    if coeff != 0:
                        terms.append(coeff * x**i * y**j * z**k)
        poly = sympy.Add(*terms)
        return sympy.poly(poly, x, y, z, domain=sympy.FF(self.p))

    def _hash_function(self, data, output_length=32):
        """General hash function for h0 and h1."""
        digest = hashes.Hash(hashes.SHA3_512(), backend=self.backend)
        digest.update(data)
        return digest.finalize()[:output_length]

    def _hash_function_z_star(self, data, output_length=32):
        """Hash function for h2 that ensures output is in Z*."""
        while True:
            result = self._hash_function(data, output_length)
            if int.from_bytes(result, 'big') != 0:
                return result

    def _generate_id(self):
        return os.urandom(32)

    def _generate_rt(self):
        return int(time.time())  # Gerçek zaman damgası

    def _generate_n(self):
        return secrets.randbelow(self.order)

    def _compute_public_key(self, n):
        """Computes the public key as n * G."""
        private_key = ec.derive_private_key(n, self.curve, self.backend)
        return private_key.public_key()

    def _encrypt(self, data, key):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext

    def _derive_key(self, shared_key):
        return HKDF(
            algorithm=hashes.SHA3_256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=self.backend
        ).derive(shared_key)

    def _register_entity(self, entity_type):
        ID = self._generate_id()
        RT = self._generate_rt()
        n = self._generate_n()

        TID = self._hash_function(ID + self.master_key.private_numbers().private_value.to_bytes(48, 'big') + n.to_bytes(48, 'big'))
        CID = self._hash_function(TID + RT.to_bytes(48, 'big') + n.to_bytes(48, 'big'))

        # Compute public key as n * G
        public_key = self._compute_public_key(n)

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        shared_key = self.master_key.exchange(ec.ECDH(), public_key)
        derived_key = self._derive_key(shared_key)

        entity_data = {
            "TID": TID,
            "CID": CID,
            "RT": RT,
            "n": n,
            "G": self.public_key,  # The G value is the TA's public key
            "Gpub": self.public_key,
            "h0": self.h0,
            "h1": self.h1,
            "h2": self.h2,
        }

        if entity_type in ["cloud", "fog"]:
            entity_data["f"] = self.f
        if entity_type in ["fog", "device"]:
            entity_data["g"] = self.g

        return entity_data, public_key_pem

    def register_cloud_server(self):
        return self._register_entity("cloud")

    def register_fog_node(self):
        return self._register_entity("fog")

    def register_smart_device(self):
        return self._register_entity("device")

if __name__ == "__main__":
    ta = TrustedAuthority()
    cloud_data, cloud_public_key_pem = ta.register_cloud_server()
    fog_data, fog_public_key_pem = ta.register_fog_node()
    device_data, device_public_key_pem = ta.register_smart_device()

    print("Cloud Server Public Key (PEM):", cloud_public_key_pem.decode('utf-8'))
    print("Fog Node Public Key (PEM):", fog_public_key_pem.decode('utf-8'))
    print("Smart Device Public Key (PEM):", device_public_key_pem.decode('utf-8'))

    print("Cloud Server Data:", cloud_data)
    print("Fog Node Data:", fog_data)
    print("Smart Device Data:", device_data)
