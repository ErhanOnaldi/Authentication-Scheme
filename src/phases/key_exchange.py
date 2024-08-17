import os
import time
import secrets
import pre_deployment


class SecureKeyExchange:
    def __init__(self):
        # Pre-deployment phase - Load the TA data for cloud, fog, and device
        self.ta = pre_deployment.TrustedAuthority()
        self.cloud_data, self.cloud_public_key_pem = self.ta.register_cloud_server()
        self.fog_data, self.fog_public_key_pem = self.ta.register_fog_node()
        self.device_data, self.device_public_key_pem = self.ta.register_smart_device()

        # Extract the relevant keys and functions for the Smart Device
        self.device_h0 = self.device_data["h0"]
        self.device_h1 = self.device_data["h1"]
        self.device_n = self.device_data["n"]
        self.device_G = self.device_data["G"]  # Using G from the device data, as per the paper
        self.device_CID = self.device_data["CID"]

        # Extract the relevant keys and functions for the Fog Node
        self.fog_h0 = self.fog_data["h0"]
        self.fog_h1 = self.fog_data["h1"]
        self.fog_n = self.fog_data["n"]
        self.fog_Gpub = self.fog_data["Gpub"]
        self.fog_CID = self.fog_data["CID"]

    def generate_r_and_ts(self):
        r = secrets.randbelow(self.device_G.curve.key_size)  # Scalar (integer) for r1
        ts = int(time.time())  # Timestamp (TS1, TS2, etc.)
        return r, ts

    def device_to_fog(self):
        # Step 1: Generate r1 and TS1
        r1, TS1 = self.generate_r_and_ts()

        # Step 2: Compute G1 = r1 * Fpub and G2 = r1 * G (from the smart device)
        G1 = r1 * self.fog_Gpub.public_numbers().x
        G2 = r1 * self.device_G.public_numbers().x
        G1_bytes = G1.to_bytes((G1.bit_length() + 7) // 8, 'big')

        # Step 3: Compute Cs, RIDs, and M1
        Cs = int.from_bytes(self.device_h0(self.device_CID + self.device_n.to_bytes((self.device_n.bit_length() + 7) // 8, 'big')), 'big') ^ G1
        RIDs = int.from_bytes(self.device_h0(G1_bytes + TS1.to_bytes(8, 'big')), 'big') ^ self.device_n
        M1 = self.device_h0(RIDs.to_bytes((RIDs.bit_length() + 7) // 8, 'big') + self.device_n.to_bytes((self.device_n.bit_length() + 7) // 8, 'big') + G1_bytes + TS1.to_bytes(8, 'big'))

        # Step 4: Send {CIDs, RID, TS1, M1} to Fog Node
        message_to_fog = {
            "CIDs": self.device_CID,
            "RIDs": RIDs,
            "TS1": TS1,
            "M1": M1
        }

        return message_to_fog, r1, G1

    def fog_to_device(self, message_from_device, r1, G1):
        # Step 1: Receive message and verify TS1
        TS1 = message_from_device["TS1"]
        current_ts = int(time.time())
        if abs(current_ts - TS1) > 1:
            raise ValueError("Message is outdated")

        # Step 2: Compute G'1 = G2 * nf and other necessary values
        G2 = r1 * self.device_G.public_numbers().x
        G_prime_1 = G2 * self.fog_n
        G1_bytes = G1.to_bytes((G1.bit_length() + 7) // 8, 'big')
        Cs_prime = int.from_bytes(self.fog_h0(self.device_CID + self.device_n.to_bytes((self.device_n.bit_length() + 7) // 8, 'big') + G1_bytes), 'big') ^ G1
        ns = message_from_device["RIDs"] ^ int.from_bytes(self.fog_h0(G1_bytes + TS1.to_bytes(8, 'big')), 'big')

        # Step 3: Verify M1
        M1_prime = self.fog_h0(ns.to_bytes((ns.bit_length() + 7) // 8, 'big') + self.device_n.to_bytes((self.device_n.bit_length() + 7) // 8, 'big') + G1_bytes + TS1.to_bytes(8, 'big'))
        if not secrets.compare_digest(M1_prime, message_from_device["M1"]):
            raise ValueError("M1 verification failed")

        # Step 4: Generate r2 and TS2, then compute G3, G4, FID, Kfs, and M2
        r2, TS2 = self.generate_r_and_ts()
        G3 = r2 * self.device_G.public_numbers().x
        G4 = r2 * self.fog_Gpub.public_numbers().x
        FID = r2 ^ int.from_bytes(self.fog_h0(G3.to_bytes((G3.bit_length() + 7) // 8, 'big') + G1_bytes + TS2.to_bytes(8, 'big')), 'big')
        Kfs = self.fog_h0(G3.to_bytes((G3.bit_length() + 7) // 8, 'big') + G1_bytes + r2.to_bytes(8, 'big'))
        M2 = self.fog_h0(Kfs + G3.to_bytes((G3.bit_length() + 7) // 8, 'big') + G1_bytes)

        # Step 5: Send {M2, CIDf, FID, G4, TS2} to Smart Device
        message_to_device = {
            "M2": M2,
            "CIDf": self.fog_CID,
            "FID": FID,
            "G4": G4,
            "TS2": TS2
        }

        return message_to_device

    def device_response(self, message_from_fog, r1, G1):
        # Step 1: Verify TS2
        TS2 = message_from_fog["TS2"]
        current_ts = int(time.time())
        if abs(current_ts - TS2) > 1:
            raise ValueError("Message is outdated")

        # Step 2: Compute G'3 = G4 * ns, r'2 = FID ⊕ h0(...)
        G4 = message_from_fog["G4"]
        G3_prime = G4 * self.device_n
        r2_prime = message_from_fog["FID"] ^ int.from_bytes(self.device_h0(G3_prime.to_bytes((G3_prime.bit_length() + 7) // 8, 'big') + G1.to_bytes((G1.bit_length() + 7) // 8, 'big') + TS2.to_bytes(8, 'big')), 'big')

        # Step 3: Compute Ksf and verify M2
        Ksf = self.device_h0(G3_prime.to_bytes((Ksf.bit_length() + 7) // 8, 'big') + G1.to_bytes((G1.bit_length() + 7) // 8, 'big') + r2_prime.to_bytes(8, 'big'))
        M2_prime = self.device_h0(Ksf + G3_prime.to_bytes((G3_prime.bit_length() + 7) // 8, 'big') + G1.to_bytes((G1.bit_length() + 7) // 8, 'big'))

        if not secrets.compare_digest(M2_prime, message_from_fog["M2"]):
            raise ValueError("M2 verification failed")

        # Step 4: Store the key Ksf
        return Ksf


if __name__ == "__main__":
    key_exchange = SecureKeyExchange()

    # Device initiates key exchange with Fog
    message_to_fog, r1, G1 = key_exchange.device_to_fog()

    # Fog processes the message from Device and responds
    message_from_fog = key_exchange.fog_to_device(message_to_fog, r1, G1)

    # Device processes the response from Fog and completes the exchange
    Ksf = key_exchange.device_response(message_from_fog, r1, G1)

    print("Key exchange successful, Ksf =", Ksf)
