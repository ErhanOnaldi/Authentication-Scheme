# src/phases/pre_deployment.py

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import hashlib

class PreDeploymentPhase:
    def __init__(self, ta):
        self.ta = ta  # TrustedAuthority instance
        self.p = ec.generate_private_key(ec.SECP256R1()).private_numbers().private_value
        self.G = ta.public_key  # Elliptic curve point G

    def _hash_function(self, data):
        return hashlib.sha256(data).hexdigest()

    def _generate_key_pair(self):
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        return private_key, public_key

    def _generate_registration_parameters(self, id_value, private_key_component):
        random_value = ec.generate_private_key(ec.SECP256R1()).private_numbers().private_value
        tid = self._hash_function(f"{id_value}{private_key_component}{random_value}".encode())
        cid = self._hash_function(f"{tid}{id_value}{random_value}".encode())
        public_key = ec.derive_private_key(random_value, ec.SECP256R1(), default_backend()).public_key()
        return tid, cid, random_value, public_key

    def register_cloud_server(self, idc):
        tidc, cidc, nc, cpub = self._generate_registration_parameters(idc, self.ta.get_private_key().private_numbers().private_value)
        # TA publicizes Cpub
        return {
            "tidc": tidc,
            "cidc": cidc,
            "nc": nc,
            "cpub": cpub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8'),
            "parameters": {
                "G": self.G,
                "hash_functions": ["h0", "h1", "h2"],
                "public_key": self.ta.get_public_key()
            }
        }

    def register_fog_node(self, idf):
        tidf, cidf, nf, fpub = self._generate_registration_parameters(idf, self.ta.get_private_key().private_numbers().private_value)
        # TA publicizes Fpub
        return {
            "tidf": tidf,
            "cidf": cidf,
            "nf": nf,
            "fpub": fpub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8'),
            "parameters": {
                "G": self.G,
                "hash_functions": ["h0", "h1", "h2"],
                "public_key": self.ta.get_public_key()
            }
        }

    def register_smart_device(self, ids):
        tids, cids, ns, spub = self._generate_registration_parameters(ids, self.ta.get_private_key().private_numbers().private_value)
        # TA publicizes Spub
        return {
            "tids": tids,
            "cids": cids,
            "ns": ns,
            "spub": spub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8'),
            "parameters": {
                "G": self.G,
                "hash_functions": ["h0", "h1", "h2"],
                "public_key": self.ta.get_public_key()
            }
        }

# Test
if __name__ == "__main__":
    from src.entities.trusted_authority import TrustedAuthority
    
    # Trusted Authority'yi oluştur
    ta = TrustedAuthority()
    
    # Pre-Deployment Phase başlat
    pre_deployment = PreDeploymentPhase(ta)

    # Cloud Server Registration
    cloud_server_params = pre_deployment.register_cloud_server("cloud_server_id")
    print(f"Cloud Server Registration Parameters: {cloud_server_params}")

    # Fog Node Registration
    fog_node_params = pre_deployment.register_fog_node("fog_node_id")
    print(f"Fog Node Registration Parameters: {fog_node_params}")

    # Smart Device Registration
    smart_device_params = pre_deployment.register_smart_device("smart_device_id")
    print(f"Smart Device Registration Parameters: {smart_device_params}")
