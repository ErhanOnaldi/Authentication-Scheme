
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
import core.entities as entities

if __name__ == "__main__":
    
    ta = entities.TrustedAuthority()
    cloud_data, cloud_public_key = ta.register_cloud_server()
    fog_data, fog_public_key = ta.register_fog_node()
    device_data, device_public_key = ta.register_smart_device()

    # Dönüştürme işlemleri burada yapılacak
    print("Cloud Server Public Key (PEM):", cloud_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8'))
    print("Fog Node Public Key (PEM):", fog_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8'))
    print("Smart Device Public Key (PEM):", device_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8'))

    print("Cloud Server Data:")
    for key, value in cloud_data.items():
        if isinstance(value, bytes):
            value = value.hex()  
        elif hasattr(value, 'public_bytes'):
            value = value.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')  # Public key'leri PEM formatına dönüştür
        print(f"  {key}: {value}")

    print("Fog Node Data:")
    for key, value in fog_data.items():
        if isinstance(value, bytes):
            value = value.hex() 
        elif hasattr(value, 'public_bytes'):
            value = value.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')
        print(f"  {key}: {value}")

    print("Smart Device Data:")
    for key, value in device_data.items():
        if isinstance(value, bytes):
            value = value.hex()
        elif hasattr(value, 'public_bytes'):
            value = value.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')
        print(f"  {key}: {value}")
