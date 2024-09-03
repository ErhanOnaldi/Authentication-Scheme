import entities

def main():
    # Trusted Authority'yi başlat
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
    # Kullanıcı kimliğini belirle
    UIDi = device.identify_user()

    # Trusted Authority üzerinden Vi ve RTi değerlerini al
    Vi, RTi = ta.register_user(UIDi)

    # Yeni kullanıcı bilgilerini sakla
    device.store_new_user(Vi, RTi)

    # Kullanıcı girişini dene
    message_from_device_to_fog = device.login()
    message_from_fog_to_cloud =fog.fog_process_message(message_from_device_to_fog)
    message_from_cloud_to_fog = cloud.cloud_process_message(message_from_fog_to_cloud)
    message_from_fog_to_device = fog.fog_process_message_from_cloud(message_from_cloud_to_fog)
    device.smartdevice_process_message(message_from_fog_to_device)

if __name__ == "__main__":
    main()
