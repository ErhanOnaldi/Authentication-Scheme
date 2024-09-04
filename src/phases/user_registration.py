
import core.entities as entities

def main():
    # device_data burada tanımlanmalı
    ta = entities.TrustedAuthority()
    cloud_data, cloud_public_key = ta.register_cloud_server()
    fog_data, fog_public_key = ta.register_fog_node()
    device_data, device_public_key = ta.register_smart_device()
    

    device = entities.SmartDevice(device_data=device_data, p=ta.p, f=ta.f, g=ta.g, order=ta.order,
                                  h0=ta.h0, h1=ta.h1, h2=ta.h2, G=ta.G, 
                                  cloud_public_key=cloud_public_key, fog_public_key=fog_public_key, device_public_key=device_public_key)

    UIDi = device.identify_user()
    Vi, RTi = ta.register_user(UIDi)
    device.store_new_user(Vi, RTi)

if __name__ == "__main__":
    main()
