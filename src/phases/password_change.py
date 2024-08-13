# password_change.py

from src.utils.crypto import hash_function, point_multiplication
from src.utils.helpers import generate_nonce
from src.entities.smart_device import SmartDevice

def secure_password_change(user_device: SmartDevice, user_id: str, old_password: str, new_password: str, bio_input: str):
    # Step 1: Compute σ‘i = Rep(BIO′i, τi)
    sigma_prime_i = Rep(bio_input, user_device.tau_i)
    
    # Step 2: Compute b′i = Ri ⊕ h1(IDi∥PWi∥σ′i)
    b_prime_i = user_device.Ri ^ hash_function(user_id + old_password + sigma_prime_i)
    
    # Step 3: Compute UID′i = h1(IDi∥b′i)
    uid_prime_i = hash_function(user_id + b_prime_i)
    
    # Step 4: Compute h(x∥e)′ = Vi ⊕ h1(UID′i)
    h_x_e_prime = user_device.Vi ^ hash_function(uid_prime_i)
    
    # Step 5: Compute m′i = h1(x∥e)′.G
    m_prime_i = point_multiplication(hash_function(h_x_e_prime), user_device.G)
    
    # Step 6: Compute H′n = h1(UIDi∥m′i∥RTi)
    h_prime_n = hash_function(uid_prime_i + str(m_prime_i) + str(user_device.RTi))
    
    # Step 7: Compute RPW′ = h1(PWi∥σ′i∥m′i)
    rpw_prime = hash_function(old_password + sigma_prime_i + str(m_prime_i))
    
    # Step 8: Compute B′i = h1(H′n∥RPW′∥b′i)
    b_prime_new_i = hash_function(h_prime_n + rpw_prime + b_prime_i)
    
    # Step 9: Verify whether B′i = Bi
    if b_prime_new_i != user_device.Bi:
        raise ValueError("Password and BIO verification failed.")
    
    # Step 10: Compute new password RPWnew = h1(PWnew∥σ′i∥m′i)
    rpw_new = hash_function(new_password + sigma_prime_i + str(m_prime_i))
    
    # Step 11: Compute Bnew_i = h1(H′n∥RPWnew∥b′i)
    b_new_i = hash_function(h_prime_n + rpw_new + b_prime_i)
    
    # Step 12: Compute Rnew_i = b′i ⊕ h1(IDi∥PWnew∥σi)
    r_new_i = b_prime_i ^ hash_function(user_id + new_password + sigma_prime_i)
    
    # Step 13: Replace {Bnew_i, Rnew_i} with old {Bi, Ri} in the smart card
    user_device.Bi = b_new_i
    user_device.Ri = r_new_i
    
    # Update the smart card data
    user_device.update_smart_card()
    
    return True
