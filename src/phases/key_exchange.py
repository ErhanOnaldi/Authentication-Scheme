import hashlib
from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1, derive_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# Hash fonksiyonu
def h0(data):
    return hashlib.sha3_512(data).digest()

# XOR işlemi
def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

# Zaman damgası (timestamp) oluşturma
import time
def generate_timestamp():
    return int(time.time())

# Anahtar değişimi işlemleri
class KeyExchange:
    def __init__(self, TA):
        self.TA = TA

    def key_exchange_smart_device_fog_node(self, smart_device, fog_node):
        # Smart Device adımları
        r1 = derive_private_key(int.from_bytes(hashlib.sha256(b"random_r1").digest(), "big"), SECP384R1())
        TS1 = generate_timestamp()
        G1 = r1.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        G2 = r1.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        Cs = xor_bytes(h0(smart_device.CID + smart_device.ns), G1)
        RIDs = xor_bytes(h0(G1 + TS1.to_bytes(8, "big")), smart_device.ns)
        M1 = h0(RIDs + smart_device.ns + G1 + TS1.to_bytes(8, "big"))

        # Smart device fog node'a mesaj gönderir
        message = (smart_device.CID, RIDs, TS1, M1)

        # Fog Node adımları
        received_CID, received_RIDs, received_TS1, received_M1 = message
        TS_star1 = generate_timestamp()

        # Zaman damgası doğrulama
        if abs(received_TS1 - TS_star1) > 1:
            raise ValueError("Timestamp not valid")

        nf = fog_node.n
        G_prime1 = r1.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)  # G2 * nf
        C_prime_s = xor_bytes(h0(smart_device.CID + smart_device.ns + G1), G1)
        ns_prime = xor_bytes(received_RIDs, h0(G1 + received_TS1.to_bytes(8, "big")))
        M_prime1 = h0(received_RIDs + ns_prime + G1 + received_TS1.to_bytes(8, "big"))

        if M_prime1 != received_M1:
            raise ValueError("M1 does not match, session terminated")

        # r2, TS2 oluştur
        r2 = derive_private_key(int.from_bytes(hashlib.sha256(b"random_r2").digest(), "big"), SECP384R1())
        TS2 = generate_timestamp()
        G3 = r2.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        G4 = r2.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        FID = xor_bytes(r2.private_numbers().private_value.to_bytes(48, "big"), h0(G3 + G1 + TS2.to_bytes(8, "big")))
        Kfs = h0(G3 + G1 + r2.private_numbers().private_value.to_bytes(48, "big"))
        M2 = h0(Kfs + G3 + G1)

        # Fog node smart device'a mesaj gönderir
        fog_message = (M2, fog_node.CID, FID, G4, TS2)

        # Smart device adımları (mesajı alır)
        received_M2, received_CIDf, received_FID, received_G4, received_TS2 = fog_message
        TS_star2 = generate_timestamp()

        # Zaman damgası doğrulama
        if abs(received_TS2 - TS_star2) > 1:
            raise ValueError("Timestamp not valid")

        G_prime3 = r1.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)  # G4 * ns
        r_prime2 = xor_bytes(received_FID, h0(G_prime3 + G1 + received_TS2.to_bytes(8, "big")))
        Ksf = h0(G_prime3 + G1 + r_prime2)
        M_prime2 = h0(Ksf + G_prime3 + G1)

        if M_prime2 != received_M2:
            raise ValueError("M2 does not match, session terminated")

        # Anahtarları sakla
        smart_device.Ksf = Ksf
        fog_node.Kfs = Kfs

    # Fog Node ile Cloud Server arasındaki anahtar değişimi fonksiyonu
    def key_exchange_fog_node_cloud_server(self, fog_node, cloud_server):
        # Fog Node adımları
        r3 = derive_private_key(int.from_bytes(hashlib.sha256(b"random_r3").digest(), "big"), SECP384R1())
        TS3 = generate_timestamp()
        G5 = r3.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        G6 = r3.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        Cf = xor_bytes(h0(fog_node.CID + fog_node.nf), G5)
        RIDf = xor_bytes(h0(G5 + TS3.to_bytes(8, "big")), fog_node.nf)
        M3 = h0(RIDf + fog_node.nf + G5 + TS3.to_bytes(8, "big"))

        # Fog node cloud server'a mesaj gönderir
        message_to_cloud = (fog_node.CID, RIDf, TS3, M3)

        # Cloud Server adımları
        received_CIDf, received_RIDf, received_TS3, received_M3 = message_to_cloud
        TS_star3 = generate_timestamp()

        # Zaman damgası doğrulama
        if abs(received_TS3 - TS_star3) > 1:
            raise ValueError("Timestamp not valid")

        G_prime5 = r3.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)  # G6 * nc
        nf_prime = xor_bytes(received_RIDf, h0(G_prime5 + received_TS3.to_bytes(8, "big")))
        C_prime_f = xor_bytes(h0(fog_node.CID + nf_prime), G_prime5)
        M_prime3 = h0(received_RIDf + nf_prime + G_prime5 + received_TS3.to_bytes(8, "big"))

        if M_prime3 != received_M3:
            raise ValueError("M3 does not match, session terminated")

        # r4, TS4 oluştur
        r4 = derive_private_key(int.from_bytes(hashlib.sha256(b"random_r4").digest(), "big"), SECP384R1())
        TS4 = generate_timestamp()
        G7 = r4.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        G8 = r4.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        CSIDi = xor_bytes(r4.private_numbers().private_value.to_bytes(48, "big"), h0(G7 + G_prime5 + TS4.to_bytes(8, "big")))
        Kcf = h0(G7 + G_prime5 + r4.private_numbers().private_value.to_bytes(48, "big"))
        M4 = h0(Kcf + G7 + G_prime5)

        # Cloud server fog node'a mesaj gönderir
        cloud_message = (M4, cloud_server.CID, CSIDi, G8, TS4)

        # Fog node adımları (mesajı alır)
        received_M4, received_CIDc, received_CSIDi, received_G8, received_TS4 = cloud_message
        TS_star4 = generate_timestamp()

        # Zaman damgası doğrulama
        if abs(received_TS4 - TS_star4) > 1:
            raise ValueError("Timestamp not valid")

        G_prime7 = r3.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)  # G8 * nf
        r_prime4 = xor_bytes(received_CSIDi, h0(G_prime7 + G5 + received_TS4.to_bytes(8, "big")))
        Kfc = h0(G_prime7 + G5 + r_prime4)
        M_prime4 = h0(Kfc + G_prime7 + G5)

        if M_prime4 != received_M4:
            raise ValueError("M4 does not match, session terminated")

        # Anahtarları sakla
        fog_node.Kfc = Kfc
        cloud_server.Kcf = Kcf
