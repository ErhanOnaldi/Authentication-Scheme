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
        self.curve = ec.SECP384R1() 
        self.backend = default_backend()
        self.master_key = self._generate_master_key()
        self.public_key = self.master_key.public_key()
        self.p = int("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 16)  # Field prime p  
        self.f = self._generate_polynomial(polynomial_degree)
        self.g = self._generate_polynomial(polynomial_degree)
        self.order = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_C7634D81_F4372DDF_581A0DB2_48B0A77A_ECEC196A_CCC52973
        self.h0 = self._hash_function  # h0, h1 aynı fonksiyonu kullanıyor
        self.h1 = self._hash_function
        self.h2 = self._hash_function_z_star #h2
        self.G = ec.EllipticCurvePublicNumbers(
            x=0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
            y=0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f,
            curve=self.curve
        ).public_key(self.backend)
    
    def _generate_master_key(self):
        return ec.generate_private_key(self.curve, self.backend)

    def _generate_polynomial(self, degree):
        x, y, z = sympy.symbols('x y z')
        terms = []
        for i in range(degree + 1):
            for j in range(i, degree + 1):  # j'yi i'den başlatın
                for k in range(j, degree + 1):  # k'yı j'den başlatın
                    coeff = secrets.randbelow(self.p)
                    if coeff != 0:
                        # Simetrik terimleri ekleyin
                        terms.append(coeff * x**i * y**j * z**k)
                        terms.append(coeff * x**i * z**j * y**k)
                        terms.append(coeff * y**i * x**j * z**k)
                        terms.append(coeff * y**i * z**j * x**k)
                        terms.append(coeff * z**i * x**j * y**k)
                        terms.append(coeff * z**i * y**j * x**k)
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
        return int(time.time()) 

    def _generate_n(self):
        return secrets.randbelow(self.order)

    def _compute_public_key(self, private_key):
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

        private_key = ec.derive_private_key(n, self.curve, self.backend)
        public_key = private_key.public_key()

        shared_key = self.master_key.exchange(ec.ECDH(), public_key)
        derived_key = self._derive_key(shared_key)

        entity_data = {
            "TID": TID,
            "CID": CID,
            "RT": RT,
            "n": n,
            "G": self.G,
            "Gpub": self.public_key,
            "h0": self.h0,
            "h1": self.h1,
            "h2": self.h2,
        }

        if entity_type in ["cloud", "fog"]:
            entity_data["f"] = self.f
        if entity_type in ["fog", "device"]:
            entity_data["g"] = self.g

        return entity_data, public_key

    def register_cloud_server(self):
        return self._register_entity("cloud")

    def register_fog_node(self):
        return self._register_entity("fog")

    def register_smart_device(self):
        return self._register_entity("device")
    