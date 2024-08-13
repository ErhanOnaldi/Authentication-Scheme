from ..utils.crypto import h1, h2
from ..entities.trusted_authority import TrustedAuthority
from ..entities.user import User

def register_user(user: User, ta: TrustedAuthority):
    # 1. Kullanıcı kimliği seçer ve UIDi hesaplar
    bi = user.generate_nonce()
    UIDi = h1(user.identity + str(bi))

    # TA'ya kayıt talebi gönderilir
    registration_request = {"UIDi": UIDi}
    print(f"User {user.identity} is registering with UIDi: {UIDi}")

    # 2. TA kayıt talebini işler
    registration_response = ta.process_registration(registration_request)
    Vi = registration_response['Vi']
    RTi = registration_response['RTi']
    
    # 3. Kullanıcı gelen değerleri işler ve akıllı karta kaydeder
    user.store_in_smart_card(Vi, RTi)
    print(f"User {user.identity} has registered and stored values in smart card.")
