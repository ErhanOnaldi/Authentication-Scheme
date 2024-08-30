import entities

def main():
    # Trusted Authority'yi başlat
    ta = entities.TrustedAuthority()
    cloud_data, cloud_public_key = ta.register_cloud_server()
    fog_data, fog_public_key = ta.register_fog_node()
    device_data, device_public_key = ta.register_smart_device()
    

    device = entities.SmartDevice(device_data=device_data, p=ta.p, f=ta.f, g=ta.g, order=ta.order,
                                  h0=ta.h0, h1=ta.h1, h2=ta.h2, G=ta.G, 
                                  cloud_public_key=cloud_public_key, fog_public_key=fog_public_key, device_public_key=device_public_key)
    # Kullanıcı kimliğini belirle
    UIDi = device.identify_user()

    # Trusted Authority üzerinden Vi ve RTi değerlerini al
    Vi, RTi = ta.register_user(UIDi)

    # Yeni kullanıcı bilgilerini sakla
    device.store_new_user(Vi, RTi)

    # Kullanıcı girişini dene
    _test_login_data_from_device = device.login()

    print(_test_login_data_from_device)


if __name__ == "__main__":
    main()
