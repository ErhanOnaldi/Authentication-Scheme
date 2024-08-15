# src/utils/crypto.py

import hashlib
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Hash fonksiyonları
def h0(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def h1(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()

def h2(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=32).digest()

# ECC anahtar çifti oluşturma
def generate_ecc_key_pair():
    """
    Eliptik Eğri Kriptografisi (ECC) anahtar çifti oluşturur.
    
    :return: (private_key, public_key) tuple
    """
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# ECC ortak anahtar üretimi
def generate_shared_key(private_key, public_key):
    """
    İki taraf arasında paylaşılan bir anahtar üretir.
    
    :param private_key: Birinci tarafın özel anahtarı
    :param public_key: İkinci tarafın genel anahtarı
    :return: 32 byte uzunluğunda paylaşılan anahtar
    """
    shared_key = private_key.exchange(ec.ECDH(), public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
    return derived_key

# Nokta çarpımı (EC Point multiplication)
def point_multiplication(scalar: int, point: ec.EllipticCurvePublicKey):
    """
    Bir skalerin eliptik eğri noktası ile çarpımını hesaplar.
    
    :param scalar: Çarpılacak skaler değer
    :param point: Eliptik eğri noktası
    :return: Çarpım sonucu oluşan yeni nokta
    """
    return scalar * point

# XOR işlemi
def xor_bytes(a: bytes, b: bytes) -> bytes:
    """İki byte dizisini XOR'lar."""
    return bytes(x ^ y for x, y in zip(a, b))

# Rastgele nonce üretimi
def generate_nonce(size: int = 32) -> bytes:
    """
    Belirtilen boyutta rastgele bir nonce üretir.
    
    :param size: Nonce boyutu (byte cinsinden)
    :return: Rastgele nonce
    """
    return os.urandom(size)