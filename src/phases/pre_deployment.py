import os
from cryptography.hazmat.primitives import serialization
import base64
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import sympy

class TrustedAuthority:
    def __init__(self):
        self.curve = ec.SECP384R1()
        self.backend = default_backend()
        self.master_key = self._generate_master_key()
        self.public_key = self.master_key.public_key()
        self.p = sympy.randprime(2**383, 2**384)  # Large prime for finite field
        self.f = self._generate_polynomial(3)
        self.g = self._generate_polynomial(3)
        # SECP384R1 order
        self.order = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_C7634D81_F4372DDF_581A0DB2_48B0A77A_ECEC196A_CCC52973

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

    def _hash_function(self, data, output_length):
        digest = hashes.Hash(hashes.SHA3_512(), backend=self.backend)
        digest.update(data)
        return digest.finalize()[:output_length]

    def _generate_id(self):
        return os.urandom(32)

    def _generate_rt(self):
        return os.urandom(32)

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

    def register_entity(self, entity_type):
        id_value = self._generate_id()
        rt_value = self._generate_rt()
        n_value = self._generate_n()

        tid = self._hash_function(id_value + self.master_key.private_numbers().private_value.to_bytes(48, 'big') + n_value.to_bytes(48, 'big'), 32)
        cid = self._hash_function(tid + rt_value + n_value.to_bytes(48, 'big'), 32)
        
        private_key = ec.derive_private_key(n_value, self.curve, self.backend)
        public_key = self._compute_public_key(private_key)

        shared_key = self.master_key.exchange(ec.ECDH(), public_key)
        derived_key = self._derive_key(shared_key)

        entity_data = {
            "TID": tid,
            "CID": cid,
            "RT": rt_value,
            "n": n_value,
            "G": "SECP384R1 Generator Point",
            "Gpub": self.public_key,
        }

        if entity_type in ["cloud", "fog"]:
            entity_data["f"] = self.f
        if entity_type in ["fog", "device"]:
            entity_data["g"] = self.g

        encrypted_data = self._encrypt(str(entity_data).encode(), derived_key)

        return encrypted_data, public_key

    def register_cloud_server(self):
        return self.register_entity("cloud")

    def register_fog_node(self):
        return self.register_entity("fog")

    def register_smart_device(self):
        return self.register_entity("device")

# Usage
ta = TrustedAuthority()

cloud_data, cloud_public_key = ta.register_cloud_server()
fog_data, fog_public_key = ta.register_fog_node()
device_data, device_public_key = ta.register_smart_device()

cloud_public_key_base64 = base64.b64encode(
    cloud_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
).decode('utf-8')

fog_public_key_base64 = base64.b64encode(
    fog_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
).decode('utf-8')

device_public_key_base64 = base64.b64encode(
    device_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
).decode('utf-8')

print("Cloud Server Public Key (Base64):", cloud_public_key_base64)
print("Fog Node Public Key (Base64):", fog_public_key_base64)
print("Smart Device Public Key (Base64):", device_public_key_base64)