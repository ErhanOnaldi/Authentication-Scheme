# src/phases/key_exchange.py

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import hashlib
import time

class KeyExchangePhase:
    def __init__(self, ta):
        self.ta = ta  # TrustedAuthority instance

    def _hash_function(self, data):
        return hashlib.sha256(data).hexdigest()

    def _generate_random_value(self):
        return ec.generate_private_key(ec.SECP256R1()).private_numbers().private_value

    def _check_timestamp(self, received_timestamp, threshold=1):
        current_timestamp = time.time()
        return abs(current_timestamp - received_timestamp) <= threshold

    def _xor(self, value1, value2):
        return bytes(a ^ b for a, b in zip(value1, value2))

    def key_exchange_smart_device_fog_node(self, smart_device, fog_node):
        # Smart Device -> Fog Node
        r1 = self._generate_random_value()
        ts1 = time.time()

        G1 = r1 * fog_node.public_key  # G1 = r1 * Fpub
        G2 = r1 * self.ta.G  # G2 = r1 * G

        Cs = self._xor(self._hash_function(f"{smart_device.CIDs}{smart_device.ns}".encode()), G1.public_bytes())
        RIDs = self._xor(self._hash_function(f"{G1.public_bytes()}{ts1}".encode()), smart_device.ns)
        M1 = self._hash_function(f"{RIDs}{smart_device.ns}{G1.public_bytes()}{ts1}".encode())

        fog_node_message = {"CIDs": smart_device.CIDs, "RIDs": RIDs, "TS1": ts1, "M1": M1}
        # Fog Node processes the message
        ts1_received = fog_node_message["TS1"]
        if not self._check_timestamp(ts1_received):
            raise ValueError("Timestamp check failed for Fog Node.")

        G1_prime = G2 * fog_node.nf  # G1' = G2 * nf
        ns = self._xor(RIDs, self._hash_function(f"{G1_prime.public_bytes()}{ts1}".encode()))
        Cs_prime = self._xor(self._hash_function(f"{smart_device.CIDs}{ns}{G1_prime.public_bytes()}".encode()), G1_prime.public_bytes())
        M1_prime = self._hash_function(f"{RIDs}{ns}{G1_prime.public_bytes()}{ts1}".encode())

        if Cs != Cs_prime:
            raise ValueError("Cs check failed for Fog Node.")
        if M1 != M1_prime:
            raise ValueError("M1 check failed for Fog Node.")

        r2 = self._generate_random_value()
        ts2 = time.time()

        G3 = r2 * smart_device.public_key  # G3 = r2 * Spub
        G4 = r2 * self.ta.G  # G4 = r2 * G

        FID = self._xor(r2.to_bytes((r2.bit_length() + 7) // 8, byteorder='big'),
                        self._hash_function(f"{fog_node.CIDf}{smart_device.CIDs}{1}{G3.public_bytes()}{G1_prime.public_bytes()}{ts2}".encode()))
        Kfs = self._hash_function(f"{fog_node.CIDf}{smart_device.CIDs}{r2}{G3.public_bytes()}{G1_prime.public_bytes()}{r2}".encode())
        M2 = self._hash_function(f"{Kfs}{G3.public_bytes()}{G1_prime.public_bytes()}".encode())

        smart_device_message = {"M2": M2, "CIDf": fog_node.CIDf, "FID": FID, "G4": G4.public_bytes(), "TS2": ts2}

        # Smart Device processes the message
        ts2_received = smart_device_message["TS2"]
        if not self._check_timestamp(ts2_received):
            raise ValueError("Timestamp check failed for Smart Device.")

        G3_prime = G4 * smart_device.ns  # G3' = G4 * ns
        r2_prime = int.from_bytes(self._xor(FID, self._hash_function(f"{fog_node.CIDf}{smart_device.CIDs}{1}{G3_prime.public_bytes()}{G1.public_bytes()}{ts2}".encode())), byteorder='big')
        Ksf = self._hash_function(f"{fog_node.CIDf}{smart_device.CIDs}{r2_prime}{G3_prime.public_bytes()}{G1.public_bytes()}{r2_prime}".encode())
        M2_prime = self._hash_function(f"{Ksf}{G3_prime.public_bytes()}{G1.public_bytes()}".encode())

        if M2 != M2_prime:
            raise ValueError("M2 check failed for Smart Device.")

        # Both Smart Device and Fog Node store the keys
        fog_node.Kfs = Kfs
        smart_device.Ksf = Ksf

        return Kfs, Ksf

    def key_exchange_fog_node_cloud_server(self, fog_node, cloud_server):
        # Fog Node -> Cloud Server
        r3 = self._generate_random_value()
        ts3 = time.time()

        G5 = r3 * cloud_server.public_key  # G5 = r3 * Cpub
        G6 = r3 * self.ta.G  # G6 = r3 * G

        Cf = self._xor(self._hash_function(f"{fog_node.CIDf}{fog_node.nf}".encode()), G5.public_bytes())
        RIDf = self._xor(self._hash_function(f"{G5.public_bytes()}{ts3}".encode()), fog_node.nf)
        M3 = self._hash_function(f"{RIDf}{fog_node.nf}{G5.public_bytes()}{ts3}".encode())

        cloud_server_message = {"CIDf": fog_node.CIDf, "RIDf": RIDf, "TS3": ts3, "M3": M3}

        # Cloud Server processes the message
        ts3_received = cloud_server_message["TS3"]
        if not self._check_timestamp(ts3_received):
            raise ValueError("Timestamp check failed for Cloud Server.")

        G5_prime = G6 * cloud_server.nc  # G5' = G6 * nc
        nf = self._xor(RIDf, self._hash_function(f"{G5_prime.public_bytes()}{ts3}".encode()))
        Cf_prime = self._xor(self._hash_function(f"{fog_node.CIDf}{nf}{G5_prime.public_bytes()}".encode()), G5_prime.public_bytes())
        M3_prime = self._hash_function(f"{RIDf}{nf}{G5_prime.public_bytes()}{ts3}".encode())

        if Cf != Cf_prime:
            raise ValueError("Cs check failed for Fog Node.")
        if M3 != M3_prime:
            raise ValueError("M3 check failed for Cloud Server.")

        r4 = self._generate_random_value()
        ts4 = time.time()

        G7 = r4 * fog_node.public_key  # G7 = r4 * Fpub
        G8 = r4 * self.ta.G  # G8 = r4 * G

        CSIDi = self._xor(r4.to_bytes((r4.bit_length() + 7) // 8, byteorder='big'),
                          self._hash_function(f"{cloud_server.CIDc}{fog_node.CIDf}{1}{G6.public_bytes()}{G7.public_bytes()}{ts4}".encode()))
        Kcf = self._hash_function(f"{cloud_server.CIDc}{fog_node.CIDf}{r4}{G7.public_bytes()}{G5_prime.public_bytes()}{r4}".encode())
        M4 = self._hash_function(f"{Kcf}{G7.public_bytes()}{G5_prime.public_bytes()}".encode())

        fog_node_message = {"M4": M4, "CIDc": cloud_server.CIDc, "CSIDi": CSIDi, "G8": G8.public_bytes(), "TS4": ts4}

        # Fog Node processes the message
        ts4_received = fog_node_message["TS4"]
        if not self._check_timestamp(ts4_received):
            raise ValueError("Timestamp check failed for Fog Node.")

        G7_prime = G8 * fog_node.nf  # G7' = G8 * nf
        r4_prime = int.from_bytes(self._xor(CSIDi, self._hash_function(f"{fog_node.CIDf}{cloud_server.CIDc}{1}{G7_prime.public_bytes()}{G5.public_bytes()}{ts4}".encode())), byteorder='big')
        Kfc = self._hash_function(f"{cloud_server.CIDc}{fog_node.CIDf}{r4_prime}{G7_prime.public_bytes()}{G5.public_bytes()}{r4_prime}".encode())
        M4_prime = self._hash_function(f"{Kfc}{G7_prime.public_bytes()}{G5.public_bytes()}".encode())

        if M4 != M4_prime:
            raise ValueError("M4 check failed for Fog Node.")

        # Both Fog Node and Cloud Server store the keys
        fog_node.Kfc = Kfc
        cloud_server.Kcf = Kcf

        return Kcf, Kfc
