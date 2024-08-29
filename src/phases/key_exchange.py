
import os
import time
import secrets
import pre_deployment
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import sympy
import utils
import entities
class SecureKeyExchange:
    def __init__(self):
        print("Initializing SecureKeyExchange...")
        # Pre-deployment phase - Load the TA data for cloud, fog, and device
        self.ta = entities.TrustedAuthority()
        self.cloud_data, self.cloud_public_key = self.ta.register_cloud_server()
        self.fog_data, self.fog_public_key = self.ta.register_fog_node()
        self.device_data, self.device_public_key = self.ta.register_smart_device()

        # Initialize entities
        self.device = entities.SmartDevice(self.device_data, self.ta.p, self.ta.f, self.ta.g, self.ta.order, 
                                           self.ta.h0, self.ta.h1, self.ta.h2, self.ta.G, 
                                           self.cloud_public_key, self.fog_public_key, self.device_public_key)
        self.fog = entities.FogServer(self.fog_data, self.ta.p, self.ta.f, self.ta.g, self.ta.order, 
                                      self.ta.h0, self.ta.h1, self.ta.h2, self.ta.G, 
                                      self.cloud_public_key, self.fog_public_key, self.device_public_key)
        self.cloud = entities.CloudServer(self.cloud_data, self.ta.p, self.ta.f, self.ta.g, self.ta.order, 
                                          self.ta.h0, self.ta.h1, self.ta.h2, self.ta.G, 
                                          self.cloud_public_key, self.fog_public_key, self.device_public_key)

    def perform_key_exchange(self):
        print("Starting key exchange process...")

        # Device initiates key exchange with Fog
        print("\n--- Device to Fog Key Exchange ---")
        message_to_fog, r1, G1, G1_bytes = self.device.device_to_fog()

        # Fog processes the message from Device and responds
        print("\n--- Fog to Device Response ---")
        message_from_fog, G4 = self.fog.fog_to_device(message_to_fog, r1, G1_bytes, G1=G1)

        # Device processes the response from Fog and completes the exchange
        print("\n--- Device Final Response ---")
        Ksf = self.device.device_response(message_from_fog, r1, G1, G1_bytes)
        print("Key exchange between Smart Device and Fog Node successful, Ksf =", Ksf.hex())

        # Fog Node initiates key exchange with Cloud Server
        print("\n--- Fog to Cloud Key Exchange ---")
        message_to_cloud, r3, G5, G6 = self.fog.fog_to_cloud()

        # Cloud processes the message from Fog Node and responds
        print("\n--- Cloud to Fog Response ---")
        message_from_cloud, nf = self.cloud.cloud_response(message_to_cloud, r3, G5, G6)

        # Fog Node processes the response from Cloud and completes the exchange
        print("\n--- Fog Final Response ---")
        Kfc = self.fog.fog_response(message_from_cloud, r3, G5, nf)
        print("Key exchange between Fog Node and Cloud Server successful, Kfc =", Kfc.hex())

if __name__ == "__main__":
    key_exchange = SecureKeyExchange()
    key_exchange.perform_key_exchange()
