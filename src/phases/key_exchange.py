
import os
import time
import secrets
import pre_deployment
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import sympy
import utils

class SecureKeyExchange:
    def __init__(self):
        print("Initializing SecureKeyExchange...")
        # Pre-deployment phase - Load the TA data for cloud, fog, and device
        self.ta = pre_deployment.TrustedAuthority()
        self.cloud_data, self.cloud_public_key = self.ta.register_cloud_server()
        self.fog_data, self.fog_public_key = self.ta.register_fog_node()
        self.device_data, self.device_public_key = self.ta.register_smart_device()

        self.G = self.device_data["G"]
        self.Gpub = self.device_data["Gpub"]

        print("TA Data Loaded")
        # Extract the relevant keys and functions
        self.device_h0 = self.device_data["h0"]
        self.device_n = self.device_data["n"]
        self.device_G = self.device_data["G"]
        self.device_CID = self.device_data["CID"]
        self.device_Gpub = self.device_data["Gpub"]

        self.fog_h0 = self.fog_data["h0"]
        self.fog_n = self.fog_data["n"]
        self.fog_Gpub = self.fog_data["Gpub"]
        self.fog_CID = self.fog_data["CID"]

        self.cloud_h0 = self.cloud_data["h0"]
        self.cloud_n = self.cloud_data["n"]
        self.cloud_Gpub = self.cloud_data["Gpub"]
        self.cloud_CID = self.cloud_data["CID"]

    def generate_r_and_ts(self):
        print("Generating r and TS...")
        r = secrets.randbelow(self.device_G.curve.key_size)
        ts = int(time.time())
        print(f"Generated r: {r}, TS: {ts}")
        return r, ts

    def point_multiply(self, public_key, scalar):
        print(f"Multiplying point {public_key.public_numbers()} by scalar {scalar} using Double and Add method...")
        curve = public_key.curve
        result = utils.scalar_mult(scalar, public_key, curve)
        return result

    def convert_to_ff_element(self, data):
        return sympy.FF(self.ta.p)(int.from_bytes(data, 'big'))

    # Key exchange between Smart Device and Fog Node
    def device_to_fog(self):
        print("Device to Fog key exchange initiated...")
        r1, TS1 = self.generate_r_and_ts()
        G1 = self.point_multiply(self.fog_public_key, r1)
        print(f"G1: {G1.public_numbers()}")
        G2 = self.point_multiply(self.device_G, r1)
        G1_bytes = G1.public_numbers().x.to_bytes((G1.public_numbers().x.bit_length() + 7) // 8, 'big')
        print(f"G1_bytes: {G1_bytes.hex()}")

        Cs = int.from_bytes(self.device_h0(self.device_CID + self.device_n.to_bytes((self.device_n.bit_length() + 7) // 8, 'big')), 'big') ^ G1.public_numbers().x
        print(f"Cs: {Cs}")
        RIDs = int.from_bytes(self.device_h0(G1_bytes + TS1.to_bytes(8, 'big')), 'big') ^ self.device_n
        print(f"RIDs: {RIDs}")
        M1 = self.device_h0(RIDs.to_bytes((RIDs.bit_length() + 7) // 8, 'big') + self.device_n.to_bytes((self.device_n.bit_length() + 7) // 8, 'big') + G1_bytes + TS1.to_bytes(8, 'big'))
        print(f"M1: {M1.hex()}")

        
        message_to_fog = {
            "CIDs": self.device_CID,
            "RIDs": RIDs,
            "TS1": TS1,
            "M1": M1,
            "G2":G2
        }
        print("Message to Fog:", message_to_fog)
        return message_to_fog, r1, G1, G1_bytes

    def fog_to_device(self, message_from_device, r1, G1_bytes):
        print("Fog to Device response processing...")
        TS1 = message_from_device["TS1"]
        current_ts = int(time.time())
        print(f"Received TS1: {TS1}, Current TS: {current_ts}")
        if abs(current_ts - TS1) > 1:
            raise ValueError("Message is outdated")

        G2 = message_from_device["G2"]
        print(f"Received G2: {G2.public_numbers()}")
        print(f"fog_n: {self.fog_n}")
        G_prime_1 = self.point_multiply(G2, self.fog_n)
        print(f"G_prime_1: {G_prime_1.public_numbers()}")
        G_prime_1_bytes = G_prime_1.public_numbers().x.to_bytes((G_prime_1.public_numbers().x.bit_length() + 7) // 8, 'big')
        print(f"G_prime_1_bytes: {G_prime_1_bytes.hex()}")

        CIDs = message_from_device["CIDs"]
        Cs_prime = int.from_bytes(self.fog_h0(CIDs + self.device_n.to_bytes((self.device_n.bit_length() + 7) // 8, 'big') + G1_bytes), 'big') ^ G1.public_numbers().x
        ns = message_from_device["RIDs"] ^ int.from_bytes(self.fog_h0(G1_bytes + TS1.to_bytes(8, 'big')), 'big')

        M1_prime = self.fog_h0(
            message_from_device["RIDs"].to_bytes((message_from_device["RIDs"].bit_length() + 7) // 8, 'big') + 
            ns.to_bytes((ns.bit_length() + 7) // 8, 'big') + 
            G1_bytes + TS1.to_bytes(8, 'big')
        )
        print(f"M1_prime: {M1_prime.hex()}")
        if not secrets.compare_digest(M1_prime, message_from_device["M1"]):
            raise ValueError("M1 verification failed")

        r2, TS2 = self.generate_r_and_ts()
        G3 = self.point_multiply(self.device_public_key, r2)
        G4 = self.point_multiply(self.device_G, r2)

        # Convert IDs to FF elements
        fog_CID_ff = self.convert_to_ff_element(self.fog_CID)
        CIDs_ff = self.convert_to_ff_element(CIDs)

        g1 = self.ta.g(fog_CID_ff, CIDs_ff, 1) % self.ta.p
        g2 = self.ta.g(fog_CID_ff, CIDs_ff, r2) % self.ta.p

        print(f"fog_CID_ff: {fog_CID_ff}")
        print(f"CIDs_ff: {CIDs_ff}")
        print(f"g1: {g1}")
        print(f"g2: {g2}")
        print(f"G3.public_numbers().x: {G3.public_numbers().x}")
        print(f"G1_bytes: {G1_bytes.hex()}")
        print(f"TS2: {TS2}")

        FID = r2 ^ int.from_bytes(
            self.fog_h0(
                int(g1).to_bytes((int(g1).bit_length() + 7) // 8, 'big') +
                G3.public_numbers().x.to_bytes((G3.public_numbers().x.bit_length() + 7) // 8, 'big') +
                G1_bytes + TS2.to_bytes(8, 'big')
            ),
            'big'
        )

        print(f"FID: {FID}")

        Kfs = self.fog_h0(
            int(g2).to_bytes((int(g2).bit_length() + 7) // 8, 'big') +
            G3.public_numbers().x.to_bytes((G3.public_numbers().x.bit_length() + 7) // 8, 'big') +
            G1_bytes + r2.to_bytes((r2.bit_length() + 7) // 8, 'big')
        )
        print(f"Kfs: {Kfs.hex()}")

        M2 = self.fog_h0(
            Kfs + G3.public_numbers().x.to_bytes((G3.public_numbers().x.bit_length() + 7) // 8, 'big') +
            G_prime_1_bytes
        )
        print(f"M2: {M2.hex()}")

        message_to_device = {
            "M2": M2,
            "CIDf": self.fog_CID,
            "FID": FID,
            "G4": G4,
            "TS2": TS2
        }
        print("Message to Device:", message_to_device)
        return message_to_device, G4


    def device_response(self, message_from_fog, r1, G1, G1_bytes):
        print("Device processing response from Fog...")
        TS2 = message_from_fog["TS2"]
        current_ts = int(time.time())
        print(f"Received TS2: {TS2}, Current TS: {current_ts}")
        if abs(current_ts - TS2) > 1:
            raise ValueError("Message is outdated")

        CIDf = message_from_fog["CIDf"]
        G4 = message_from_fog["G4"]
        G3_prime = self.point_multiply(G4, self.device_n)
        print(f"G3_prime.public_numbers().x: {G3_prime.public_numbers().x}")

        # Convert IDs to FF elements
        device_CID_ff = self.convert_to_ff_element(self.device_CID)
        CIDf_ff = self.convert_to_ff_element(CIDf)
        print(f"device_CID_ff: {device_CID_ff}")
        print(f"CIDf_ff: {CIDf_ff}")

        g1 = self.ta.g(CIDf_ff, device_CID_ff, 1) % self.ta.p
        print(f"g1: {g1} from device")
        
        g1_prime = self.ta.g(device_CID_ff, CIDf_ff, 1) % self.ta.p
        print(f"g1_prime: {g1_prime}")
         
        
        r2_prime = message_from_fog["FID"] ^ int.from_bytes(
            self.device_h0(
                int(g1).to_bytes((int(g1).bit_length() + 7) // 8, 'big') +
                G3_prime.public_numbers().x.to_bytes((G3_prime.public_numbers().x.bit_length() + 7) // 8, 'big') +
                G1_bytes + TS2.to_bytes(8, 'big')),'big')
        
        g2_prime = self.ta.g(CIDf_ff, device_CID_ff, r2_prime) % self.ta.p
        print(f"g2_prime: {g2_prime}")

        print(f"r2_prime: {r2_prime}") 

        g3 = self.ta.g(device_CID_ff, CIDf_ff, r2_prime) % self.ta.p

        Ksf = self.device_h0(
            int(g2_prime).to_bytes((int(g2_prime).bit_length() + 7) // 8, 'big') +
            G3_prime.public_numbers().x.to_bytes((G3_prime.public_numbers().x.bit_length() + 7) // 8, 'big') +
            G1_bytes + r2_prime.to_bytes((r2_prime.bit_length() + 7) // 8, 'big')
        )
        print(f"Ksf: {Ksf.hex()}") 

        M2_prime = self.device_h0(
            Ksf + G3_prime.public_numbers().x.to_bytes((G3_prime.public_numbers().x.bit_length() + 7) // 8, 'big') +
            G1.public_numbers().x.to_bytes((G1.public_numbers().x.bit_length() + 7) // 8, 'big')
        )
        print(f"M2_prime: {M2_prime.hex()}") 

        if not secrets.compare_digest(M2_prime, message_from_fog["M2"]):
            print(f"Error: M2 from fog ({message_from_fog['M2'].hex()}) does not match M2_prime from device ({M2_prime.hex()})")
            raise ValueError("M2 verification failed")

        return Ksf

    # Key exchange between Fog Node and Cloud Server
    def fog_to_cloud(self):
        print("Fog to Cloud key exchange initiated...")
        r3, TS3 = self.generate_r_and_ts()
        G5 = self.point_multiply(self.cloud_public_key, r3)
        G6 = self.point_multiply(self.G, r3)
        G5_bytes = G5.public_numbers().x.to_bytes((G5.public_numbers().x.bit_length() + 7) // 8, 'big')
        print(f"G5_bytes: {G5_bytes.hex()}")

        Cf = int.from_bytes(self.fog_h0(self.fog_CID + self.fog_n.to_bytes((self.fog_n.bit_length() + 7) // 8, 'big')), 'big') ^ G5.public_numbers().x
        print(f"Cf: {Cf}")
        RIDf = int.from_bytes(self.fog_h0(G5_bytes + TS3.to_bytes(8, 'big')), 'big') ^ self.fog_n
        print(f"RIDf: {RIDf}")
        M3 = self.fog_h0(RIDf.to_bytes((RIDf.bit_length() + 7) // 8, 'big') + self.fog_n.to_bytes((self.fog_n.bit_length() + 7) // 8, 'big') + G5_bytes + TS3.to_bytes(8, 'big'))
        print(f"M3: {M3.hex()}")

        message_to_cloud = {
            "CIDf": self.fog_CID,
            "RIDf": RIDf,
            "TS3": TS3,
            "M3": M3
        }
        print("Message to Cloud:", message_to_cloud)
        return message_to_cloud, r3, G5, G6

    def cloud_response(self, message_from_fog, r3, G5, G6):
        print("Cloud processing response from Fog...")
        TS3 = message_from_fog["TS3"]
        current_ts = int(time.time())
        print(f"Received TS3: {TS3}, Current TS: {current_ts}")
        if abs(current_ts - TS3) > 1:
            raise ValueError("Message is outdated")
        
        G_prime_5 = self.point_multiply(G6, self.cloud_n)
        print(f"G_prime_5: {G_prime_5.public_numbers()}")

        G_prime_5_bytes = G_prime_5.public_numbers().x.to_bytes((G_prime_5.public_numbers().x.bit_length() + 7) // 8, 'big')
        print(f"G_prime_5_bytes: {G_prime_5_bytes.hex()}")
        G5_bytes = G5.public_numbers().x.to_bytes((G5.public_numbers().x.bit_length() + 7) // 8, 'big')

        nf = message_from_fog["RIDf"] ^ int.from_bytes(self.cloud_h0(G5_bytes + TS3.to_bytes(8, 'big')), 'big')
        print(f"nf: {nf}")

        Cf_prime = int.from_bytes(self.cloud_h0(
        message_from_fog["CIDf"] + 
        nf.to_bytes((nf.bit_length() + 7) // 8, 'big')), 'big') ^ G_prime_5.public_numbers().x

        print(f"Cf_prime: {Cf_prime}")
        

        M3_prime = self.cloud_h0(message_from_fog["RIDf"].to_bytes((message_from_fog["RIDf"].bit_length() + 7) // 8, 'big') +
        nf.to_bytes((nf.bit_length() + 7) // 8, 'big') +
        G_prime_5_bytes +
        TS3.to_bytes(8, 'big'))

        if not secrets.compare_digest(M3_prime, message_from_fog["M3"]):
            raise ValueError("M3 verification failed")
        
        print(f"M3_prime: {M3_prime.hex()}")    

        r4, TS4 = self.generate_r_and_ts()
        G7 = self.point_multiply(self.fog_public_key, r4)
        G8 = self.point_multiply(self.G, r4)

        # Convert IDs to FF elements
        cloud_CID_ff = self.convert_to_ff_element(self.cloud_CID)
        CIDf_ff = self.convert_to_ff_element(message_from_fog["CIDf"])

        f1 = self.ta.f(cloud_CID_ff, CIDf_ff, 1) % self.ta.p
        f2 = self.ta.f(cloud_CID_ff, CIDf_ff, r4) % self.ta.p

        print(f"cloud_CID_ff: {cloud_CID_ff}")
        print(f"CIDf_ff: {CIDf_ff}")
        print(f"f1: {f1}")
        print(f"f2: {f2}")
        print(f"G7.public_numbers().x: {G7.public_numbers().x}")
        print(f"G5_bytes: {G5_bytes.hex()}")
        print(f"TS4: {TS4}")

        # Convert f1 and f2 to int before calling to_bytes
        CSID = r4 ^ int.from_bytes(
            self.cloud_h0(
                int(f1).to_bytes((int(f1).bit_length() + 7) // 8, 'big') + 
                G7.public_numbers().x.to_bytes((G7.public_numbers().x.bit_length() + 7) // 8, 'big') + 
                G_prime_5_bytes + 
                TS4.to_bytes(8, 'big')
            ), 
            'big'
        )
        
        Kcf = self.cloud_h0(
            int(f2).to_bytes((int(f2).bit_length() + 7) // 8, 'big') + 
            G7.public_numbers().x.to_bytes((G7.public_numbers().x.bit_length() + 7) // 8, 'big') + 
            G_prime_5_bytes + 
            r4.to_bytes((r4.bit_length() + 7) // 8, 'big')
        )

        print(f"CSID: {CSID}")
        print(f"Kcf: {Kcf.hex()}")

        M4 = self.cloud_h0(
            Kcf + G7.public_numbers().x.to_bytes((G7.public_numbers().x.bit_length() + 7) // 8, 'big') +
            G_prime_5_bytes
        )
        print(f"M4: {M4.hex()}")

        message_to_fog = {
            "M4": M4,
            "CIDc": self.cloud_CID,
            "CSID": CSID,
            "G8": G8,
            "TS4": TS4
        }
        print("Message to Fog:", message_to_fog)
        return message_to_fog, nf

    def fog_response(self, message_from_cloud, r3, G5, nf):
        print("Fog processing response from Cloud...")
        TS4 = message_from_cloud["TS4"]
        current_ts = int(time.time())
        print(f"Received TS4: {TS4}, Current TS: {current_ts}")
        if abs(current_ts - TS4) > 1:
            raise ValueError("Message is outdated")

        G8 = message_from_cloud["G8"]
        G7_prime = self.point_multiply(G8, nf)
        print(f"G7_prime: {G7_prime.public_numbers()}")

        # Convert IDs to FF elements
        fog_CID_ff = self.convert_to_ff_element(self.fog_CID)
        CIDc_ff = self.convert_to_ff_element(message_from_cloud["CIDc"])

        f1_prime = self.ta.f(fog_CID_ff, CIDc_ff, 1) % self.ta.p
        print(f"f1_prime: {f1_prime}")

        r4_prime = message_from_cloud["CSID"] ^ int.from_bytes(
            self.fog_h0(
                int(f1_prime).to_bytes((int(f1_prime).bit_length() + 7) // 8, 'big') +
                G7_prime.public_numbers().x.to_bytes((G7_prime.public_numbers().x.bit_length() + 7) // 8, 'big') +
                G5.public_numbers().x.to_bytes((G5.public_numbers().x.bit_length() + 7) // 8, 'big') +
                TS4.to_bytes(8, 'big')
            ),
            'big'
        )
        print(f"r4_prime: {r4_prime}")

        f2_prime = self.ta.f(fog_CID_ff, CIDc_ff, r4_prime) % self.ta.p
        print(f"f2_prime: {f2_prime}")

        Kfc_prime = self.fog_h0(
            int(f2_prime).to_bytes((int(f2_prime).bit_length() + 7) // 8, 'big') +
            G7_prime.public_numbers().x.to_bytes((G7_prime.public_numbers().x.bit_length() + 7) // 8, 'big') +
            G5.public_numbers().x.to_bytes((G5.public_numbers().x.bit_length() + 7) // 8, 'big') +
            r4_prime.to_bytes((r4_prime.bit_length() + 7) // 8, 'big')
        )
        print(f"Kfc_prime: {Kfc_prime.hex()}")

        M4_prime = self.fog_h0(
            Kfc_prime + G7_prime.public_numbers().x.to_bytes((G7_prime.public_numbers().x.bit_length() + 7) // 8, 'big') +
            G5.public_numbers().x.to_bytes((G5.public_numbers().x.bit_length() + 7) // 8, 'big')
        )

        print(f"M4_prime: {M4_prime.hex()}")

        if not secrets.compare_digest(M4_prime, message_from_cloud["M4"]):
            raise ValueError("M4 verification failed")

        return Kfc_prime


if __name__ == "__main__":
    print("Starting key exchange process...")
    key_exchange = SecureKeyExchange()

    # Device initiates key exchange with Fog
    print("\n--- Device to Fog Key Exchange ---")
    message_to_fog, r1, G1, G1_bytes = key_exchange.device_to_fog()

    # Fog processes the message from Device and responds
    print("\n--- Fog to Device Response ---")
    message_from_fog, G4 = key_exchange.fog_to_device(message_to_fog, r1, G1_bytes)

    # Device processes the response from Fog and completes the exchange
    print("\n--- Device Final Response ---")
    Ksf = key_exchange.device_response(message_from_fog, r1, G1, G1_bytes)
    print("Key exchange between Smart Device and Fog Node successful, Ksf =", Ksf.hex())

    # Fog Node initiates key exchange with Cloud Server
    print("\n--- Fog to Cloud Key Exchange ---")
    message_to_cloud, r3, G5, G6 = key_exchange.fog_to_cloud()

    # Cloud processes the message from Fog Node and responds
    print("\n--- Cloud to Fog Response ---")
    message_from_cloud, nf = key_exchange.cloud_response(message_to_cloud, r3, G5, G6)

    # Fog Node processes the response from Cloud and completes the exchange
    print("\n--- Fog Final Response ---")
    Kfc = key_exchange.fog_response(message_from_cloud, r3, G5, nf)
    print("Key exchange between Fog Node and Cloud Server successful, Kfc =", Kfc.hex())
