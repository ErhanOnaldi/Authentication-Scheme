
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
import core.utils as utils
import core.fuzzyextractor as fuzzyextractor
from core.takebiodata import collect_biometric_data

def hi(data, output_length=32):
        #Hash function for h0 and h1.
        digest = hashes.Hash(hashes.SHA3_512(), backend=default_backend())
        digest.update(data)
        return digest.finalize()[:output_length]


class Entity:
    def __init__(self, p, f, g, order, h0, h1, h2, G, cloud_public_key, fog_public_key, device_public_key):
        self.p = p
        self.f = f
        self.g = g
        self.order = order
        self.h0 = h0
        self.h1 = h1
        self.h2 = h2
        self.G = G
        self.cloud_public_key = cloud_public_key
        self.fog_public_key = fog_public_key
        self.device_public_key = device_public_key
        self.hi = hi
        self.DELTA_T = 1

    def generate_r_and_ts(self):
        r = secrets.randbelow(self.G.curve.key_size)
        ts = int(time.time())
        return r, ts

    def point_multiply(self, public_key, scalar):
        curve = public_key.curve
        result = utils.scalar_mult(scalar, public_key, curve)
        return result

    def convert_to_ff_element(self, data):
        return sympy.FF(self.p)(int.from_bytes(data, 'big'))


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
        self.hi = hi
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
        #Hash function for h0 and h1.
        digest = hashes.Hash(hashes.SHA3_512(), backend=self.backend)
        digest.update(data)
        return digest.finalize()[:output_length]

    def _hash_function_z_star(self, data, output_length=32):
        #Hash function for h2 that ensures output is in Z*.
        while True:
            result = self._hash_function(data, output_length)
            if int.from_bytes(result, 'big') != 0:
                return result

    def point_multiply(self, public_key, scalar):
        curve = public_key.curve
        result = utils.scalar_mult(scalar, public_key, curve)
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
        #derived_key = self._derive_key(shared_key)

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
    
    def register_user(self, UIDi):
        e = secrets.token_bytes(16)  # Generate a random nonce e
        RTi = self._generate_rt()  # Generate a registration timestamp RTi
        
        # Compute h1(x∥e)
        h1_x_e = self.h1(self.master_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ) + e)

        # Convert h1_x_e to an integer
        h1_x_e_int = int.from_bytes(h1_x_e, 'big')

        # Perform elliptic curve point multiplication mi = h1(x∥e) * G
        mi = self.point_multiply(self.G, h1_x_e_int)

        # Calculate Hn
        mi_bytes = mi.public_numbers().x.to_bytes((mi.public_numbers().x.bit_length() + 7) // 8, 'big')
        Hn = self.h1(UIDi + mi_bytes + RTi.to_bytes(48, 'big'))

        # Calculate Vi = h1(x∥e) ⊕ hi(UIDi)
        Vi = h1_x_e_int ^ int.from_bytes(self.hi(UIDi), 'big')

        return Vi, RTi




class SmartCard:
    def __init__(self):
        self.storage = {}

    def store(self, key, value):
        """Veriyi SmartCard'a kaydeder."""
        self.storage[key] = value

    def retrieve(self, key):
        """SmartCard'dan veri alır."""
        return self.storage.get(key)

    def execute_gen(self, BIOi):
        """SmartCard'da saklanan Gen fonksiyonunu çalıştırır."""
        return self.storage['Gen'](BIOi)

    def execute_rep(self, BIOi, σi):
        """SmartCard'da saklanan Rep fonksiyonunu çalıştırır."""
        return self.storage['Rep'](BIOi, σi)

    def clear(self):
        """SmartCard'daki tüm verileri sıfırlar."""
        self.storage.clear()

FIXED_BIO_DATA = b'\x00' * 16
class SmartDevice(Entity):
    
    def __init__(self, device_data, p, f, g, order, h0, h1, h2, G, cloud_public_key, fog_public_key, device_public_key):
        super().__init__(p, f, g, order, h0, h1, h2, G, cloud_public_key, fog_public_key, device_public_key)
        self.device_h0 = device_data["h0"]
        self.device_n = device_data["n"]
        self.device_CID = device_data["CID"]
        self.Ksf = None
        self.user_information = {}
        self.smart_card = SmartCard()
        self.extractor = fuzzyextractor.FuzzyExtractor(16, 8)
        self.mi_prime = None
        self.RV1 = None
        self.user_session_key = None


    def identify_user(self):
        """Prompts the user for IDi and calculates UIDi."""
        IDi = input("Enter your ID: ")
        bi = secrets.token_bytes(32)
        UIDi = self.h1(IDi.encode() + bi)

        # Store IDi and bi in user_information for future use
        self.user_information['IDi'] = IDi
        self.user_information['bi'] = bi
        self.user_information['UIDi'] = UIDi
        
        return UIDi

    
    def store_new_user(self, Vi, RTi):
        PWi = input("Enter your password: ")
        BIOi = FIXED_BIO_DATA
        
        # Ensure BIOi is of consistent length (e.g., 16 bytes)
        BIOi = BIOi.ljust(16, b'\0')[:16]

        # Gen(BIOi) = (σi, τi)
        σi, τi = self.Gen(BIOi)

        # h(x∥e)' = Vi ⊕ h(UIDi)
        h_x_e_prime = Vi ^ int.from_bytes(self.hi(self.user_information['UIDi']), 'big')

        # m'i = h1(x∥e)' * G
        m_prime_i = self.point_multiply(self.G, h_x_e_prime)

        # Hn' = h1(UIDi ∥ m'i ∥ RTi)
        Hn_prime = self.h1(self.user_information['UIDi'] + m_prime_i.public_numbers().x.to_bytes((m_prime_i.public_numbers().x.bit_length() + 7) // 8, 'big') + RTi.to_bytes(8, 'big'))
        

        # RPW = h1(PWi∥σi∥m'i)
        RPW = self.h1(PWi.encode('utf-8') + σi + m_prime_i.public_numbers().x.to_bytes((m_prime_i.public_numbers().x.bit_length() + 7) // 8, 'big'))

        # Bi = h1(Hn' ∥ RPW ∥ bi)
        Bi = self.h1(Hn_prime + RPW + self.user_information['bi'])

        # Ri hesaplama işlemi
        bi_bytes = self.user_information['bi']
        h1_result = self.h1(self.user_information['IDi'].encode('utf-8') + PWi.encode('utf-8') + σi)
        bi_int = int.from_bytes(bi_bytes, 'big')
        h1_int = int.from_bytes(h1_result, 'big')
        max_bit_length = max(bi_int.bit_length(), h1_int.bit_length())
        bi_int_padded = bi_int.to_bytes((max_bit_length + 7) // 8, 'big')
        h1_int_padded = h1_int.to_bytes((max_bit_length + 7) // 8, 'big')
        if len(bi_int_padded) < len(h1_int_padded):
            bi_int_padded = bi_int_padded.rjust(len(h1_int_padded), b'\x00')
        Ri = int.from_bytes(bi_int_padded, 'big') ^ int.from_bytes(h1_int_padded, 'big')

        # Store the values
        self.user_information['Bi'] = Bi
        self.user_information['Ri'] = Ri
        self.user_information['σi'] = σi
        self.user_information['τi'] = τi
        self.user_information['Vi'] = Vi
        self.user_information['RTi'] = RTi
        print("Stored user information successfully.")


        # SmartCard'a verileri kaydet
        self.smart_card.store('Bi', Bi)
        self.smart_card.store('Ri', Ri)
        self.smart_card.store('τi', τi)
        self.smart_card.store('Vi', Vi)
        self.smart_card.store('RTi', RTi)
        self.smart_card.store('Gen', self.Gen)
        self.smart_card.store('Rep', self.Rep)
        self.smart_card.store('h1', self.h1)
        self.smart_card.store('h2', self.h2)

        return True



    def login(self):
        IDi = input("Enter your ID: ")
        PWi = input("Enter your password: ")
        BIOi = FIXED_BIO_DATA
        #BIOi = collect_biometric_data()
        BIOi = BIOi.ljust(16, b'\0')[:16]

        if not self.user_information:
            print("No user information found. Please register first.")
            return False

        Vi = self.user_information['Vi']
        Ri = self.user_information['Ri']
        helper = self.user_information['τi']
        # Rep function to calculate σi'
        is_valid, σi_prime = self.Rep(BIOi, helper)
        if not is_valid:
            print("Invalid biometric data.")
            return False

        # Calculate b'i
        h1_result = self.h1(IDi.encode('utf-8') + PWi.encode('utf-8') + σi_prime)

        h1_int = int.from_bytes(h1_result, 'big')
        h1_padded = h1_int.to_bytes((h1_int.bit_length() + 7) // 8, 'big')

        # b_prime_i hesapla
        b_prime_i = Ri ^ int.from_bytes(h1_padded, 'big')
        # Calculate UID'i
        UID_prime_i = self.h1(IDi.encode() + b_prime_i.to_bytes((b_prime_i.bit_length() + 7) // 8, 'big'))

        # Calculate h(x∥e)'
        h_x_e_prime = Vi ^ int.from_bytes(self.hi(UID_prime_i), 'big')

        # Calculate m'i
        m_prime_i = self.point_multiply(self.G, h_x_e_prime)
        self.mi_prime = m_prime_i

        # Calculate H'n
        H_prime_n = self.h1(UID_prime_i + m_prime_i.public_numbers().x.to_bytes((m_prime_i.public_numbers().x.bit_length() + 7) // 8, 'big') + self.user_information['RTi'].to_bytes(8, 'big'))

        # Calculate RPW'
        RPW_prime = self.h1(PWi.encode() + σi_prime + m_prime_i.public_numbers().x.to_bytes((m_prime_i.public_numbers().x.bit_length() + 7) // 8, 'big'))

        # Calculate B'i and verify
        Bi_prime = self.h1(H_prime_n + RPW_prime + b_prime_i.to_bytes((b_prime_i.bit_length() + 7) // 8, 'big'))

        if Bi_prime == self.user_information['Bi']:
            print("Login successful!")
            
        else:
            raise ValueError("Bi and Bi_prime is not equal")
            

        # Adım 10: T1 ve w1 üretimi
        T1 = int(time.time())
        w1 = secrets.randbelow(self.G.curve.key_size)

        # Adım 11: RV1 ve RV2 hesapla
        RV1 = self.point_multiply(self.fog_public_key, w1)
        self.RV1 = RV1
        RV2 = self.point_multiply(self.G, w1)

        # Adım 12: Csm hesapla
        Csm = self.h2(self.device_CID + T1.to_bytes(8, 'big') + RV1.public_numbers().x.to_bytes((RV1.public_numbers().x.bit_length() + 7) // 8, 'big'))
        Csm = int.from_bytes(Csm, 'big') ^ h_x_e_prime
        Csm = Csm.to_bytes((Csm.bit_length() + 7) // 8, 'big')

        # Adım 13: DUIDi hesapla ve mesajı oluştur
        DUIDi = self.h2(self.device_CID + RV1.public_numbers().x.to_bytes((RV1.public_numbers().x.bit_length() + 7) // 8, 'big') + T1.to_bytes(8, 'big') + m_prime_i.public_numbers().x.to_bytes((m_prime_i.public_numbers().x.bit_length() + 7) // 8, 'big'))

        message_to_fog = {
            "CIDs": self.device_CID,
            "RV2": RV2,
            "Csm": Csm,
            "T1": T1
        }
        print(f"CIDs bit size: {int.from_bytes(self.device_CID, 'big').bit_length()}")
        print(f"RV2 bit size: {RV2.public_numbers().x.bit_length()}")
        print(f"Csm bit size: {int.from_bytes(Csm, 'big').bit_length()}")

        print("Login phase completed. Message to Fog Server prepared.")
        return message_to_fog

    def smartdevice_process_message(self, message_from_fog):
        # Mesajdan verileri ayıkla
        Fsm = message_from_fog['Fsm']
        Fsn = message_from_fog['Fsn']
        T4 = message_from_fog['T4']
        FCSUIDi = message_from_fog['FCSUIDi']
        T3 = message_from_fog['T3']
        CV2 = message_from_fog['CV2']

        # Adım 1: Zaman kontrolü
        T4_star = int(time.time())
        if T4_star - T4 > self.DELTA_T:
            raise ValueError("Time difference exceeds allowed limit.")

        # Adım 2: FV1' hesapla
        FV1_prime = int.from_bytes(Fsn, 'big') ^ int.from_bytes(self.h2(self.mi_prime.public_numbers().x.to_bytes((self.mi_prime.public_numbers().x.bit_length() + 7) // 8, 'big') + 
                                            T4.to_bytes(8, 'big')), 'big')
        CV1_prime = int.from_bytes(Fsm, 'big') ^ int.from_bytes(self.h2(Fsn + 
                                                                        self.mi_prime.public_numbers().x.to_bytes((self.mi_prime.public_numbers().x.bit_length() + 7) // 8, 'big') + 
                                                                        T4.to_bytes(8, 'big')), 'big')

        # Adım 4: SKsfc hesapla
        SKsfc = self.h2(self.mi_prime.public_numbers().x.to_bytes((self.mi_prime.public_numbers().x.bit_length() + 7) // 8, 'big') + 
                        self.RV1.public_numbers().x.to_bytes((self.RV1.public_numbers().x.bit_length() + 7) // 8, 'big') + 
                        FV1_prime.to_bytes((FV1_prime.bit_length() + 7) // 8, 'big') + 
                        CV1_prime.to_bytes((CV1_prime.bit_length() + 7) // 8, 'big'))
        self.user_session_key = SKsfc

        # Adım 5: CSUIDi' hesapla
        CSUIDi_prime = self.h2(SKsfc + self.mi_prime.public_numbers().x.to_bytes((self.mi_prime.public_numbers().x.bit_length() + 7) // 8, 'big') + 
                            T3.to_bytes(8, 'big') + 
                            CV1_prime.to_bytes((CV1_prime.bit_length() + 7) // 8, 'big'))

        # Adım 6: FCSUIDi' hesapla
        FCSUIDi_prime = self.h2(CSUIDi_prime + T4.to_bytes(8, 'big') + 
                                self.mi_prime.public_numbers().x.to_bytes((self.mi_prime.public_numbers().x.bit_length() + 7) // 8, 'big') + 
                                CV1_prime.to_bytes((CV1_prime.bit_length() + 7) // 8, 'big'))


        # Adım 7: FCSUIDi' doğrula
        if FCSUIDi_prime != FCSUIDi:
            raise ValueError("FCSUIDi doğrulama hatası.")

        print(f"Sksfc bit size: {int.from_bytes(SKsfc, 'big').bit_length()}")
        print(f"Session key successfully created: {SKsfc.hex()}")
        
    def Gen(self, BIOi):
        """Gen fonksiyonu: Biometrik verilerden (σi, τi) değerlerini üretir."""
        key, helper = self.extractor.generate(BIOi)
        return key, helper


    def Rep(self, BIOi, helper):
        """Rep fonksiyonu: Biometrik veriyi ve helper değerini kullanarak σ'i üretir."""
        σi_prime = self.extractor.reproduce(BIOi, helper)
        is_valid = σi_prime is not None
        return is_valid, σi_prime
        
    def clear_user_data(self):
        """Simülasyon sonunda SmartCard'daki verileri sıfırlar."""
        self.smart_card.clear()
        print("All user data cleared from SmartCard.")
    

    def device_to_fog(self):
        r1, TS1 = self.generate_r_and_ts()
        G1 = self.point_multiply(self.fog_public_key, r1)
        G2 = self.point_multiply(self.G, r1)
        G1_bytes = G1.public_numbers().x.to_bytes((G1.public_numbers().x.bit_length() + 7) // 8, 'big')

        Cs = int.from_bytes(self.device_h0(self.device_CID + self.device_n.to_bytes((self.device_n.bit_length() + 7) // 8, 'big')), 'big') ^ G1.public_numbers().x
        RIDs = int.from_bytes(self.device_h0(G1_bytes + TS1.to_bytes(8, 'big')), 'big') ^ self.device_n
        M1 = self.device_h0(RIDs.to_bytes((RIDs.bit_length() + 7) // 8, 'big') + self.device_n.to_bytes((self.device_n.bit_length() + 7) // 8, 'big') + G1_bytes + TS1.to_bytes(8, 'big'))

        message_to_fog = {
            "CIDs": self.device_CID,
            "RIDs": RIDs,
            "TS1": TS1,
            "M1": M1,
            "G2": G2
        }
        print(f"CIDs bit size: {int.from_bytes(self.device_CID, 'big').bit_length()}")
        print(f"RIDs bit size: {RIDs.bit_length()}")
        print(f"M1 bit size: {int.from_bytes(M1, 'big').bit_length()}")
        print(f"G2 bit size: {G2.public_numbers().x.bit_length()}")

        return message_to_fog, r1, G1, G1_bytes

    def device_response(self, message_from_fog, r1, G1, G1_bytes):
        TS2 = message_from_fog["TS2"]
        current_ts = int(time.time())
        if abs(current_ts - TS2) > 1:
            raise ValueError("Message is outdated")

        CIDf = message_from_fog["CIDf"]
        G4 = message_from_fog["G4"]
        G3_prime = self.point_multiply(G4, self.device_n)

        device_CID_ff = self.convert_to_ff_element(self.device_CID)
        CIDf_ff = self.convert_to_ff_element(CIDf)

        g1 = self.g(CIDf_ff, device_CID_ff, 1) % self.p

        r2_prime = message_from_fog["FID"] ^ int.from_bytes(
            self.device_h0(
                int(g1).to_bytes((int(g1).bit_length() + 7) // 8, 'big') +
                G3_prime.public_numbers().x.to_bytes((G3_prime.public_numbers().x.bit_length() + 7) // 8, 'big') +
                G1_bytes + TS2.to_bytes(8, 'big')),'big')

        g2_prime = self.g(CIDf_ff, device_CID_ff, r2_prime) % self.p

        Ksf = self.device_h0(
            int(g2_prime).to_bytes((int(g2_prime).bit_length() + 7) // 8, 'big') +
            G3_prime.public_numbers().x.to_bytes((G3_prime.public_numbers().x.bit_length() + 7) // 8, 'big') +
            G1_bytes + r2_prime.to_bytes((r2_prime.bit_length() + 7) // 8, 'big')
        )
        self.Ksf = Ksf

        M2_prime = self.device_h0(
            Ksf + G3_prime.public_numbers().x.to_bytes((G3_prime.public_numbers().x.bit_length() + 7) // 8, 'big') +
            G1.public_numbers().x.to_bytes((G1.public_numbers().x.bit_length() + 7) // 8, 'big')
        )

        if not secrets.compare_digest(M2_prime, message_from_fog["M2"]):
            raise ValueError("M2 verification failed")
        print(f"Ksf bit size: {int.from_bytes(Ksf, 'big').bit_length()}")
        return Ksf


class FogServer(Entity):
    def __init__(self, fog_data, p, f, g, order, h0, h1, h2, G, cloud_public_key, fog_public_key, device_public_key):
        super().__init__(p, f, g, order, h0, h1, h2, G, cloud_public_key, fog_public_key, device_public_key)
        self.fog_h0 = fog_data["h0"]
        self.fog_n = fog_data["n"]
        self.fog_CID = fog_data["CID"]
        self.Kfc = None
        self.Ksf = None 
        self.mi_prime = None
        self.RV1_prime = None
        self.FV1= None
        self.fog_session_key= None

    def fog_process_message(self, message_from_device):
        # Verileri mesajdan ayıkla
        CIDs = message_from_device['CIDs']
        RV2 = message_from_device['RV2']
        Csm = message_from_device['Csm']
        T1 = message_from_device['T1']
        

        # Adım 1: Zaman kontrolü
        T1_star = int(time.time())  # Fog server'da mevcut zaman
        if T1_star - T1 > self.DELTA_T:
            raise ValueError("Time difference exceeds allowed limit.")

        # Adım 2: RV'1 hesapla
        RV1_prime = self.point_multiply(RV2, self.fog_n)  # nf, fog server'ın private key'idir
        self.RV1_prime = RV1_prime
        # Adım 3: h(x∥e)' hesapla
        h2_result = self.h2(CIDs + T1.to_bytes(8, 'big') + RV1_prime.public_numbers().x.to_bytes((RV1_prime.public_numbers().x.bit_length() + 7) // 8, 'big'))
        h2_int = int.from_bytes(h2_result, 'big')
        Csm_int = int.from_bytes(Csm, 'big')
        hx_e_prime = Csm_int ^ h2_int
        # Adım 4: m'i hesapla
        mi_prime = self.point_multiply(self.G, hx_e_prime)
        self.mi_prime = mi_prime

        # Adım 5: DUID'i hesapla
        DUIDi_prime = self.h2(CIDs + RV1_prime.public_numbers().x.to_bytes((RV1_prime.public_numbers().x.bit_length() + 7) // 8, 'big') + T1.to_bytes(8, 'big') + mi_prime.public_numbers().x.to_bytes((mi_prime.public_numbers().x.bit_length() + 7) // 8, 'big'))

        # Adım 6: T2 ve w2 üret
        T2 = int(time.time())
        w2 = secrets.randbelow(self.G.curve.key_size)

        # Adım 7: FV1 ve FV2 hesapla
        FV1 = self.point_multiply(self.cloud_public_key, w2)
        self.FV1 = FV1
        FV2 = self.point_multiply(self.G, w2)

        # Adım 8: Cf hesapla
        h2_result = self.h2(self.fog_CID + T2.to_bytes(8, 'big') + FV1.public_numbers().x.to_bytes((FV1.public_numbers().x.bit_length() + 7) // 8, 'big'))
        h2_int = int.from_bytes(h2_result, 'big')
        Cf = h2_int ^ hx_e_prime
        # Adım 9: Fc hesapla
        Cf_bytes = Cf.to_bytes((Cf.bit_length() + 7) // 8, 'big')

        # Adım 9: Fc hesapla
        Fc = int.from_bytes(self.h2(hx_e_prime.to_bytes((hx_e_prime.bit_length() + 7) // 8, 'big') + Cf_bytes + FV1.public_numbers().x.to_bytes((FV1.public_numbers().x.bit_length() + 7) // 8, 'big')), 'big') ^ int.from_bytes(RV1_prime.public_numbers().x.to_bytes((RV1_prime.public_numbers().x.bit_length() + 7) // 8, 'big'), 'big')

        # Adım 10: FUIDi hesapla
        FUIDi = self.h2(DUIDi_prime + mi_prime.public_numbers().x.to_bytes((mi_prime.public_numbers().x.bit_length() + 7) // 8, 'big') + FV1.public_numbers().x.to_bytes((FV1.public_numbers().x.bit_length() + 7) // 8, 'big') + RV1_prime.public_numbers().x.to_bytes((RV1_prime.public_numbers().x.bit_length() + 7) // 8, 'big') + T1.to_bytes(8, 'big') + T2.to_bytes(8, 'big'))
        print("fog successfully processed message")
        # Mesajı oluştur
        message_to_cloud = {
            "CIDs": CIDs,
            "CIDf": self.fog_CID,
            "Csm": Csm,
            "Cf": Cf,
            "Fc": Fc,
            "FUIDi": FUIDi,
            "RV2": RV2,
            "FV2": FV2,
            "T1": T1,
            "T2": T2
        }
        print(f"CIDs bit size:{int.from_bytes(CIDs,'big').bit_length()}")
        print(f"CIDf bit size:{int.from_bytes(self.fog_CID,'big').bit_length()}")
        print(f"Csm bit size:{int.from_bytes(Csm,'big').bit_length()}")
        print(f"Cf bit size:{Cf.bit_length()}")
        print(f"Fc bit size:{Fc.bit_length()}")
        print(f"FUIDi bit size:{int.from_bytes(FUIDi,'big').bit_length()}")
        print(f"RV2 bit size:{RV2.public_numbers().x.bit_length()}")
        print(f"FV2 bit size:{FV2.public_numbers().x.bit_length()}")
        
        return message_to_cloud
    
    def fog_process_message_from_cloud(self, message_from_cloud):
        # Mesajdan verileri ayıkla
        CV2 = message_from_cloud['CV2']
        T3 = message_from_cloud['T3']

        # Adım 1: Zaman kontrolü
        T3_star = int(time.time())
        if T3_star - T3 > self.DELTA_T:
            raise ValueError("Time difference exceeds allowed limit.")
        
        CV1 = self.point_multiply(CV2, self.fog_n)
        # Adım 3: SKfcs hesapla
        RV1_prime_x_bytes = self.RV1_prime.public_numbers().x.to_bytes(
            (self.RV1_prime.public_numbers().x.bit_length() + 7) // 8, 'big'
        )
        FV1_x_bytes = self.FV1.public_numbers().x.to_bytes(
            (self.FV1.public_numbers().x.bit_length() + 7) // 8, 'big'
        )
        CV1_x_bytes = CV1.public_numbers().x.to_bytes(
            (CV1.public_numbers().x.bit_length() + 7) // 8, 'big'
        )

        SKfcs = self.h2(
            self.mi_prime.public_numbers().x.to_bytes(
                (self.mi_prime.public_numbers().x.bit_length() + 7) // 8, 'big'
            ) + RV1_prime_x_bytes + FV1_x_bytes + CV1_x_bytes
        )
        self.fog_session_key = SKfcs
        # Adım 4: CSUID'i hesapla
        CSUIDi_prime = self.h2(SKfcs + self.mi_prime.public_numbers().x.to_bytes((self.mi_prime.public_numbers().x.bit_length() + 7) // 8, 'big') + 
                            T3.to_bytes(8, 'big') + CV1.public_numbers().x.to_bytes((CV1.public_numbers().x.bit_length() + 7) // 8, 'big'))

        # Adım 5: FCSUID'i hesapla
        T4 = int(time.time())
        FCSUIDi = self.h2(CSUIDi_prime + T4.to_bytes(8, 'big') + self.mi_prime.public_numbers().x.to_bytes((self.mi_prime.public_numbers().x.bit_length() + 7) // 8, 'big') + 
                        CV1.public_numbers().x.to_bytes((CV1.public_numbers().x.bit_length() + 7) // 8, 'big'))

        # Adım 6: Fsn hesapla
        Fsn = int.from_bytes(self.h2(self.mi_prime.public_numbers().x.to_bytes((self.mi_prime.public_numbers().x.bit_length() + 7) // 8, 'big') + 
                                    T4.to_bytes(8, 'big')), 'big') ^ int.from_bytes(self.FV1.public_numbers().x.to_bytes((self.FV1.public_numbers().x.bit_length() + 7) // 8, 'big'), 'big')

        # Adım 7: Fsm hesapla
        Fsm = int.from_bytes(self.h2(Fsn.to_bytes((Fsn.bit_length() + 7) // 8, 'big') + 
                                    self.mi_prime.public_numbers().x.to_bytes((self.mi_prime.public_numbers().x.bit_length() + 7) // 8, 'big') + 
                                    T4.to_bytes(8, 'big')), 'big') ^ int.from_bytes(CV1.public_numbers().x.to_bytes((CV1.public_numbers().x.bit_length() + 7) // 8, 'big'), 'big')

        # Mesajı oluştur
        message_to_device = {
            "Fsm": Fsm.to_bytes((Fsm.bit_length() + 7) // 8, 'big'),
            "Fsn": Fsn.to_bytes((Fsn.bit_length() + 7) // 8, 'big'),
            "T4": T4,
            "FCSUIDi": FCSUIDi,
            "T3": T3,
            "CV2": CV2
        }
        print(f"Fsm bit size: {Fsm.bit_length()}")
        print(f"Fsn bit size: {Fsn.bit_length()}")
        print(f"CV2 bit size: {CV2.public_numbers().x.bit_length()}")
        print(f"FCSUIDi bit size: {int.from_bytes(FCSUIDi, 'big').bit_length()}")

        print("Fog successfully processed message and send message to Device")
        return message_to_device


    def fog_to_device(self, message_from_device, r1, G1_bytes, G1):
        TS1 = message_from_device["TS1"]
        current_ts = int(time.time())
        if abs(current_ts - TS1) > 1:
            raise ValueError("Message is outdated")

        G2 = message_from_device["G2"]
        G_prime_1 = self.point_multiply(G2, self.fog_n)
        G_prime_1_bytes = G_prime_1.public_numbers().x.to_bytes((G_prime_1.public_numbers().x.bit_length() + 7) // 8, 'big')

        CIDs = message_from_device["CIDs"]
        Cs_prime = int.from_bytes(self.fog_h0(CIDs + self.fog_n.to_bytes((self.fog_n.bit_length() + 7) // 8, 'big') + G1_bytes), 'big') ^ G1.public_numbers().x
        ns = message_from_device["RIDs"] ^ int.from_bytes(self.fog_h0(G1_bytes + TS1.to_bytes(8, 'big')), 'big')

        M1_prime = self.fog_h0(
            message_from_device["RIDs"].to_bytes((message_from_device["RIDs"].bit_length() + 7) // 8, 'big') + 
            ns.to_bytes((ns.bit_length() + 7) // 8, 'big') + 
            G1_bytes + TS1.to_bytes(8, 'big')
        )
        if not secrets.compare_digest(M1_prime, message_from_device["M1"]):
            raise ValueError("M1 verification failed")

        r2, TS2 = self.generate_r_and_ts()
        G3 = self.point_multiply(self.device_public_key, r2)
        G4 = self.point_multiply(self.G, r2)

        fog_CID_ff = self.convert_to_ff_element(self.fog_CID)
        CIDs_ff = self.convert_to_ff_element(CIDs)

        g1 = self.g(fog_CID_ff, CIDs_ff, 1) % self.p
        g2 = self.g(fog_CID_ff, CIDs_ff, r2) % self.p

        FID = r2 ^ int.from_bytes(
            self.fog_h0(
                int(g1).to_bytes((int(g1).bit_length() + 7) // 8, 'big') +
                G3.public_numbers().x.to_bytes((G3.public_numbers().x.bit_length() + 7) // 8, 'big') +
                G1_bytes + TS2.to_bytes(8, 'big')
            ),
            'big'
        )

        Kfs = self.fog_h0(
            int(g2).to_bytes((int(g2).bit_length() + 7) // 8, 'big') +
            G3.public_numbers().x.to_bytes((G3.public_numbers().x.bit_length() + 7) // 8, 'big') +
            G1_bytes + r2.to_bytes((r2.bit_length() + 7) // 8, 'big')
        )
        self.Ksf = Kfs

        M2 = self.fog_h0(
            Kfs + G3.public_numbers().x.to_bytes((G3.public_numbers().x.bit_length() + 7) // 8, 'big') +
            G_prime_1_bytes
        )

        message_to_device = {
            "M2": M2,
            "CIDf": self.fog_CID,
            "FID": FID,
            "G4": G4,
            "TS2": TS2
        }

        print(f"M2 bit size: {int.from_bytes(M2, 'big').bit_length()}")
        print(f"CIDf bit size: {int.from_bytes(self.fog_CID, 'big').bit_length()}")
        print(f"FID bit size: {FID.bit_length()}")
        print(f"G4 bit size: {G4.public_numbers().x.bit_length()}")



        return message_to_device, G4

    def fog_to_cloud(self):
        r3, TS3 = self.generate_r_and_ts()
        G5 = self.point_multiply(self.cloud_public_key, r3)
        G6 = self.point_multiply(self.G, r3)
        G5_bytes = G5.public_numbers().x.to_bytes((G5.public_numbers().x.bit_length() + 7) // 8, 'big')

        Cf = int.from_bytes(self.fog_h0(self.fog_CID + self.fog_n.to_bytes((self.fog_n.bit_length() + 7) // 8, 'big')), 'big') ^ G5.public_numbers().x
        RIDf = int.from_bytes(self.fog_h0(G5_bytes + TS3.to_bytes(8, 'big')), 'big') ^ self.fog_n
        M3 = self.fog_h0(RIDf.to_bytes((RIDf.bit_length() + 7) // 8, 'big') + self.fog_n.to_bytes((self.fog_n.bit_length() + 7) // 8, 'big') + G5_bytes + TS3.to_bytes(8, 'big'))

        message_to_cloud = {
            "CIDf": self.fog_CID,
            "RIDf": RIDf,
            "TS3": TS3,
            "M3": M3
        }
        print(f"M3 bit size: {int.from_bytes(M3, 'big').bit_length()}")
        print(f"CIDf bit size: {int.from_bytes(self.fog_CID, 'big').bit_length()}")
        print(f"RIDf bit size: {RIDf.bit_length()}")
        return message_to_cloud, r3, G5, G6

    def fog_response(self, message_from_cloud, r3, G5, nf):
        TS4 = message_from_cloud["TS4"]
        current_ts = int(time.time())
        if abs(current_ts - TS4) > 1:
            raise ValueError("Message is outdated")

        G8 = message_from_cloud["G8"]
        G7_prime = self.point_multiply(G8, nf)

        fog_CID_ff = self.convert_to_ff_element(self.fog_CID)
        CIDc_ff = self.convert_to_ff_element(message_from_cloud["CIDc"])

        f1_prime = self.f(fog_CID_ff, CIDc_ff, 1) % self.p

        r4_prime = message_from_cloud["CSID"] ^ int.from_bytes(
            self.fog_h0(
                int(f1_prime).to_bytes((int(f1_prime).bit_length() + 7) // 8, 'big') +
                G7_prime.public_numbers().x.to_bytes((G7_prime.public_numbers().x.bit_length() + 7) // 8, 'big') +
                G5.public_numbers().x.to_bytes((G5.public_numbers().x.bit_length() + 7) // 8, 'big') +
                TS4.to_bytes(8, 'big')
            ),
            'big'
        )

        f2_prime = self.f(fog_CID_ff, CIDc_ff, r4_prime) % self.p

        Kfc_prime = self.fog_h0(
            int(f2_prime).to_bytes((int(f2_prime).bit_length() + 7) // 8, 'big') +
            G7_prime.public_numbers().x.to_bytes((G7_prime.public_numbers().x.bit_length() + 7) // 8, 'big') +
            G5.public_numbers().x.to_bytes((G5.public_numbers().x.bit_length() + 7) // 8, 'big') +
            r4_prime.to_bytes((r4_prime.bit_length() + 7) // 8, 'big')
        )
        self.Kfc = Kfc_prime

        M4_prime = self.fog_h0(
            Kfc_prime + G7_prime.public_numbers().x.to_bytes((G7_prime.public_numbers().x.bit_length() + 7) // 8, 'big') +
            G5.public_numbers().x.to_bytes((G5.public_numbers().x.bit_length() + 7) // 8, 'big')
        )

        if not secrets.compare_digest(M4_prime, message_from_cloud["M4"]):
            raise ValueError("M4 verification failed")

        print(f"Kfc bit size: {int.from_bytes(Kfc_prime, 'big').bit_length()}")
        return Kfc_prime


class CloudServer(Entity):
    def __init__(self, cloud_data, p, f, g, order, h0, h1, h2, G, cloud_public_key, fog_public_key, device_public_key):
        super().__init__(p, f, g, order, h0, h1, h2, G, cloud_public_key, fog_public_key, device_public_key)
        self.cloud_h0 = cloud_data["h0"]
        self.cloud_n = cloud_data["n"]
        self.cloud_CID = cloud_data["CID"]
        self.Kcf = None
        self.cloud_session_key=None

    def cloud_process_message(self, message_from_fog):
        # Mesajdan verileri ayıkla
        CIDs = message_from_fog['CIDs']
        CIDf = message_from_fog['CIDf']
        Csm = message_from_fog['Csm']
        Cf = message_from_fog['Cf']
        Fc = message_from_fog['Fc']
        FUIDi = message_from_fog['FUIDi']
        RV2 = message_from_fog['RV2']
        FV2 = message_from_fog['FV2']
        T1 = message_from_fog['T1']
        T2 = message_from_fog['T2']

        # Adım 1: Zaman kontrolü
        T2_star = int(time.time())
        if T2_star - T2 > self.DELTA_T:
            raise ValueError("Time difference exceeds allowed limit.")
        
        # Adım 2: FV1 hesapla
        FV1 = self.point_multiply(FV2, self.cloud_n)  # nc, cloud server'ın n değeri

        # Adım 3: h(x∥e)' hesapla
        h2_result = self.h2(CIDf + T2.to_bytes(8, 'big') + FV1.public_numbers().x.to_bytes((FV1.public_numbers().x.bit_length() + 7) // 8, 'big'))
        h2_int = int.from_bytes(h2_result, 'big')
        hx_e_prime = Cf ^ h2_int  # Cf bir int olduğundan doğrudan kullanıyoruz

        # Adım 4: m'i hesapla
        mi_prime = self.point_multiply(self.G, hx_e_prime)

        # Adım 5: RV'1 hesapla
        h2_result = self.h2(hx_e_prime.to_bytes((hx_e_prime.bit_length() + 7) // 8, 'big') + Cf.to_bytes((Cf.bit_length() + 7) // 8, 'big') + FV1.public_numbers().x.to_bytes((FV1.public_numbers().x.bit_length() + 7) // 8, 'big'))
        RV1_prime = Fc ^ int.from_bytes(h2_result, 'big')  # Fc de bir int olduğundan doğrudan kullanıyoruz

        # Adım 6: DUID'i hesapla
        DUIDi_prime = self.h2(CIDs + RV1_prime.to_bytes((RV1_prime.bit_length() + 7) // 8, 'big') + T1.to_bytes(8, 'big') + mi_prime.public_numbers().x.to_bytes((mi_prime.public_numbers().x.bit_length() + 7) // 8, 'big'))

        # Adım 7: FUID'i hesapla
        FUIDi_prime = self.h2(DUIDi_prime + mi_prime.public_numbers().x.to_bytes((mi_prime.public_numbers().x.bit_length() + 7) // 8, 'big') + FV1.public_numbers().x.to_bytes((FV1.public_numbers().x.bit_length() + 7) // 8, 'big') + RV1_prime.to_bytes((RV1_prime.bit_length() + 7) // 8, 'big') + T1.to_bytes(8, 'big') + T2.to_bytes(8, 'big'))

        # Adım 8: FUID'i doğrula
        if FUIDi_prime != FUIDi:
            raise ValueError("FUIDi doğrulama hatası.")

        # Adım 9: T3 ve w3 üret
        T3 = int(time.time())
        w3 = secrets.randbelow(self.G.curve.key_size)

        # Adım 10: CV1 ve CV2 hesapla
        CV1 = self.point_multiply(self.fog_public_key, w3)
        CV2 = self.point_multiply(self.G, w3)
        # Adım 11: SKCfs hesapla
        SKCfs = self.h2(mi_prime.public_numbers().x.to_bytes((mi_prime.public_numbers().x.bit_length() + 7) // 8, 'big') + RV1_prime.to_bytes((RV1_prime.bit_length() + 7) // 8, 'big') + FV1.public_numbers().x.to_bytes((FV1.public_numbers().x.bit_length() + 7) // 8, 'big') + CV1.public_numbers().x.to_bytes((CV1.public_numbers().x.bit_length() + 7) // 8, 'big'))
        self.cloud_session_key = SKCfs
        # Adım 12: CSUIDi hesapla
        CSUIDi = self.h2(SKCfs + mi_prime.public_numbers().x.to_bytes((mi_prime.public_numbers().x.bit_length() + 7) // 8, 'big') + T3.to_bytes(8, 'big') + CV1.public_numbers().x.to_bytes((CV1.public_numbers().x.bit_length() + 7) // 8, 'big'))
        # Mesajı oluştur
        message_to_fog = {
            "CV2": CV2,
            "T3": T3
        }
        print(f"CV2 bit size: {CV2.public_numbers().x.bit_length()}")
        print("Cloud successfully processed message from fog.")
        return message_to_fog


    def cloud_response(self, message_from_fog, r3, G5, G6):
        TS3 = message_from_fog["TS3"]
        current_ts = int(time.time())
        if abs(current_ts - TS3) > 1:
            raise ValueError("Message is outdated")
        
        G_prime_5 = self.point_multiply(G6, self.cloud_n)
        G_prime_5_bytes = G_prime_5.public_numbers().x.to_bytes((G_prime_5.public_numbers().x.bit_length() + 7) // 8, 'big')
        G5_bytes = G5.public_numbers().x.to_bytes((G5.public_numbers().x.bit_length() + 7) // 8, 'big')

        nf = message_from_fog["RIDf"] ^ int.from_bytes(self.cloud_h0(G5_bytes + TS3.to_bytes(8, 'big')), 'big')

        Cf_prime = int.from_bytes(self.cloud_h0(
        message_from_fog["CIDf"] + 
        nf.to_bytes((nf.bit_length() + 7) // 8, 'big')), 'big') ^ G_prime_5.public_numbers().x

        M3_prime = self.cloud_h0(message_from_fog["RIDf"].to_bytes((message_from_fog["RIDf"].bit_length() + 7) // 8, 'big') +
        nf.to_bytes((nf.bit_length() + 7) // 8, 'big') +
        G_prime_5_bytes +
        TS3.to_bytes(8, 'big'))

        if not secrets.compare_digest(M3_prime, message_from_fog["M3"]):
            raise ValueError("M3 verification failed")
        
        r4, TS4 = self.generate_r_and_ts()
        G7 = self.point_multiply(self.fog_public_key, r4)
        G8 = self.point_multiply(self.G, r4)

        cloud_CID_ff = self.convert_to_ff_element(self.cloud_CID)
        CIDf_ff = self.convert_to_ff_element(message_from_fog["CIDf"])

        f1 = self.f(cloud_CID_ff, CIDf_ff, 1) % self.p
        f2 = self.f(cloud_CID_ff, CIDf_ff, r4) % self.p

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
        self.Kcf = Kcf

        M4 = self.cloud_h0(
            Kcf + G7.public_numbers().x.to_bytes((G7.public_numbers().x.bit_length() + 7) // 8, 'big') +
            G_prime_5_bytes
        )

        message_to_fog = {
            "M4": M4,
            "CIDc": self.cloud_CID,
            "CSID": CSID,
            "G8": G8,
            "TS4": TS4
        }
        print(f"M4 bit size: {int.from_bytes(M4,'big').bit_length()}")
        print(f"CSID bit size: {CSID.bit_length()}")
        print(f"G8 bit size: {G8.public_numbers().x.bit_length()}")
        print(f"CSID bit size: {int.from_bytes(self.cloud_CID,'big').bit_length()}")
        return message_to_fog, nf