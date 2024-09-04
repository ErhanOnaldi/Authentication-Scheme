import core.entities as entities

#Pre depoloyment phase
print("Pre deployment phase")
ta = entities.TrustedAuthority()
cloud_data, cloud_public_key = ta.register_cloud_server()
fog_data, fog_public_key = ta.register_fog_node()
device_data, device_public_key = ta.register_smart_device()
    

device = entities.SmartDevice(device_data, ta.p, ta.f, ta.g, ta.order, 
                                           ta.h0, ta.h1, ta.h2, ta.G, 
                                           cloud_public_key, fog_public_key, device_public_key)
fog = entities.FogServer(fog_data, ta.p, ta.f, ta.g, ta.order, 
                                      ta.h0, ta.h1, ta.h2, ta.G, 
                                      cloud_public_key, fog_public_key, device_public_key)
cloud = entities.CloudServer(cloud_data, ta.p, ta.f, ta.g, ta.order, 
                                          ta.h0, ta.h1, ta.h2, ta.G, 
                                          cloud_public_key, fog_public_key, device_public_key)

#Key exchange phase
print("Starting key exchange process...")

        # Device initiates key exchange with Fog
print("\n--- Device to Fog Key Exchange ---")
message_to_fog, r1, G1, G1_bytes = device.device_to_fog()

        # Fog processes the message from Device and responds
print("\n--- Fog to Device Response ---")
message_from_fog, G4 = fog.fog_to_device(message_to_fog, r1, G1_bytes, G1=G1)

        # Device processes the response from Fog and completes the exchange
print("\n--- Device Final Response ---")
Ksf = device.device_response(message_from_fog, r1, G1, G1_bytes)
print("Key exchange between Smart Device and Fog Node successful, Ksf =", Ksf.hex())

        # Fog Node initiates key exchange with Cloud Server
print("\n--- Fog to Cloud Key Exchange ---")
message_to_cloud, r3, G5, G6 = fog.fog_to_cloud()

        # Cloud processes the message from Fog Node and responds
print("\n--- Cloud to Fog Response ---")
message_from_cloud, nf = cloud.cloud_response(message_to_cloud, r3, G5, G6)

        # Fog Node processes the response from Cloud and completes the exchange
print("\n--- Fog Final Response ---")
Kfc = fog.fog_response(message_from_cloud, r3, G5, nf)
print("Key exchange between Fog Node and Cloud Server successful, Kfc =", Kfc.hex())



#User Registiration Phase
print("Registiration phase")
UIDi = device.identify_user()

    # Trusted Authority üzerinden Vi ve RTi değerlerini al
Vi, RTi = ta.register_user(UIDi)

    # Yeni kullanıcı bilgilerini sakla
device.store_new_user(Vi, RTi)

#Login Authentication Phase
print("login phase")
message_from_device_to_fog = device.login()
message_from_fog_to_cloud =fog.fog_process_message(message_from_device_to_fog)
message_from_cloud_to_fog = cloud.cloud_process_message(message_from_fog_to_cloud)
message_from_fog_to_device = fog.fog_process_message_from_cloud(message_from_cloud_to_fog)
device.smartdevice_process_message(message_from_fog_to_device)