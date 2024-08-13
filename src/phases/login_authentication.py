# login_authentication.py

from src.utils.crypto import hash_function, generate_nonce, point_multiplication
from src.utils.helpers import check_timestamp_validity
from src.entities.smart_device import SmartDevice
from src.entities.fog_node import FogNode

def user_login(device: SmartDevice, user_id: str, password: str, biometric: str):
    # Step 1.1: User Inputs ID, PWi, BIOi
    user_id = user_id
    password = password
    biometric = biometric
    
    # Step 1.2: Compute σ‘i = Rep(BIO′i, τi)
    sigma_prime = device.reproduce_biometric(biometric)
    
    # Step 1.3: Compute b′i = Ri ⊕ h1(IDi∥PWi∥σ′i)
    b_prime = device.Ri ^ hash_function(user_id + password + sigma_prime)
    
    # Step 1.4: Compute UID′i = h1(IDi∥b′i)
    uid_prime = hash_function(user_id + str(b_prime))
    
    # Step 1.5: Compute h(x∥e)′ = Vi ⊕ hi(UID′i)
    h_x_e_prime = device.Vi ^ hash_function(uid_prime)
    
    # Step 1.6: Compute m′i = h1(x∥e)′.G
    m_prime = point_multiplication(hash_function(h_x_e_prime), device.G)
    
    # Step 1.7: Compute H′n = h1(UIDi∥m′i∥RTi)
    h_prime_n = hash_function(uid_prime + str(m_prime) + str(device.RTi))
    
    # Step 1.8: Compute RPW′ = h1(PWi∥σ′i∥m′i)
    rpw_prime = hash_function(password + sigma_prime + str(m_prime))
    
    # Step 1.9: Compute B′i = h1(H′n∥RPW∥b′i)
    b_prime_i = hash_function(h_prime_n + rpw_prime + str(b_prime))
    
    # Step 1.10: Verify B′i = Bi
    if b_prime_i != device.Bi:
        raise ValueError("Authentication Failed. Incorrect password or biometric data.")
    
    # Step 1.11: Compute T1 and nonce w1
    t1 = generate_timestamp()
    w1 = generate_nonce()
    
    # Step 1.12: Compute RV1 = w1.Fpub, RV2 = w1.G
    rv1 = point_multiplication(w1, device.Fpub)
    rv2 = point_multiplication(w1, device.G)
    
    # Step 1.13: Compute Csm = h2(CIDs∥T1∥RV1) ⊕ h(x∥e)′
    csm = hash_function(device.CIDs + str(t1) + str(rv1)) ^ h_x_e_prime
    
    # Step 1.14: Compute DUIDi = h2(CIDs∥RV1∥T1∥mi)
    duid_i = hash_function(device.CIDs + str(rv1) + str(t1) + str(m_prime))
    
    # Step 1.15: Send {CIDs, RV2, Csm, T1} to Fog Server
    return {
        "CIDs": device.CIDs,
        "RV2": rv2,
        "Csm": csm,
        "T1": t1
    }


from src.utils.crypto import hash_function, point_multiplication
from src.utils.helpers import check_timestamp_validity
from src.entities.cloud_server import CloudServer

def fog_node_authentication(fog_node: FogNode, message_from_user: dict):
    # Step 2.1: Receive {CIDs, RV2, Csm, T1} from Ui
    cids = message_from_user["CIDs"]
    rv2 = message_from_user["RV2"]
    csm = message_from_user["Csm"]
    t1 = message_from_user["T1"]
    
    # Step 2.2: Check the message's validity (timestamp check)
    if not check_timestamp_validity(t1):
        raise ValueError("Message rejected due to invalid timestamp.")
    
    # Step 2.3: Compute RV′1 = RV2.nf
    rv_prime_1 = point_multiplication(fog_node.nf, rv2)
    
    # Step 2.4: Compute h(x∥e)′ = Csm ⊕ h2(CIDs∥T1∥RV′1)
    h_x_e_prime = csm ^ hash_function(cids + str(t1) + str(rv_prime_1))
    
    # Step 2.5: Compute m′i = h1(x∥e)′.G
    m_prime_i = point_multiplication(hash_function(h_x_e_prime), fog_node.G)
    
    # Step 2.6: Compute DUID′i = h2(CIDs∥RV′1∥T1∥m′i)
    duid_prime_i = hash_function(cids + str(rv_prime_1) + str(t1) + str(m_prime_i))
    
    # Step 2.7: Generate T2 and nonce w2
    t2 = generate_timestamp()
    w2 = generate_nonce()
    
    # Step 2.8: Compute FV1 = w2.Cpub, FV2 = w2.G
    fv1 = point_multiplication(w2, fog_node.Cpub)
    fv2 = point_multiplication(w2, fog_node.G)
    
    # Step 2.9: Compute cf = h2(CIDf∥T2∥FV1) ⊕ h(x∥e)′
    cf = hash_function(fog_node.CIDf + str(t2) + str(fv1)) ^ h_x_e_prime
    
    # Step 2.10: Compute Fc = h2(h(x∥e)′∥Cf∥FV1) ⊕ RV′1
    fc = hash_function(h_x_e_prime + fog_node.Cf + str(fv1)) ^ rv_prime_1
    
    # Step 2.11: Compute FUIDi = h2(DUID′i∥m′i∥FV1∥RV′1∥T1∥T2)
    fuid_i = hash_function(duid_prime_i + str(m_prime_i) + str(fv1) + str(rv_prime_1) + str(t1) + str(t2))
    
    # Step 2.12: Send {CIDs, CIDf, Csm, Cf, Fc, FUIDi, RV2, FV2, T1, T2} to Cloud Server
    return {
        "CIDs": cids,
        "CIDf": fog_node.CIDf,
        "Csm": csm,
        "Cf": cf,
        "Fc": fc,
        "FUIDi": fuid_i,
        "RV2": rv2,
        "FV2": fv2,
        "T1": t1,
        "T2": t2
    }

    # login_authentication.py

def cloud_server_authentication(cloud_server: CloudServer, message_from_fog_node: dict):
    # Step 3.1: Receive {CIDs, CIDf, Csm, Cf, Fc, FUIDi, RV2, FV2, T1, T2} from Fog Node
    cids = message_from_fog_node["CIDs"]
    cidf = message_from_fog_node["CIDf"]
    csm = message_from_fog_node["Csm"]
    cf = message_from_fog_node["Cf"]
    fc = message_from_fog_node["Fc"]
    fuid_i = message_from_fog_node["FUIDi"]
    rv2 = message_from_fog_node["RV2"]
    fv2 = message_from_fog_node["FV2"]
    t1 = message_from_fog_node["T1"]
    t2 = message_from_fog_node["T2"]
    
    # Step 3.2: Check the message's validity (timestamp check)
    if not check_timestamp_validity(t2):
        raise ValueError("Message rejected due to invalid timestamp.")
    
    # Step 3.3: Compute FV1 = FV2.nc
    fv1 = point_multiplication(cloud_server.nc, fv2)
    
    # Step 3.4: Compute h(x∥e)′ = cf ⊕ h2(CIDf∥T2∥FV1)
    h_x_e_prime = cf ^ hash_function(cidf + str(t2) + str(fv1))
    
    # Step 3.5: Compute m′i = h1(x∥e)′.G
    m_prime_i = point_multiplication(hash_function(h_x_e_prime), cloud_server.G)
    
    # Step 3.6: Compute RV′1 = Fc ⊕ h2(h(x∥e)′∥Cf∥FV1)
    rv_prime_1 = fc ^ hash_function(h_x_e_prime + cloud_server.Cf + str(fv1))
    
    # Step 3.7: Compute DUIDi = h2(CIDs∥RV′1∥T1∥m′i)
    duid_i = hash_function(cids + str(rv_prime_1) + str(t1) + str(m_prime_i))
    
    # Step 3.8: Compute FUID′i = h2(DUIDi∥m′i∥FV1∥RV′1∥T1∥T2)
    fuid_prime_i = hash_function(duid_i + str(m_prime_i) + str(fv1) + str(rv_prime_1) + str(t1) + str(t2))
    
    # Step 3.9: Verify whether FUID′i = FUIDi
    if fuid_prime_i != fuid_i:
        raise ValueError("Authentication Failed. FUID mismatch.")
    
    # Step 3.10: Mutual Authentication Process Starts
    # Step 3.11: Generate T3 and nonce w3
    t3 = generate_timestamp()
    w3 = generate_nonce()
    
    # Step 3.12: Compute CV1 = w3.Fpub, CV2 = w3.G
    cv1 = point_multiplication(w3, cloud_server.Fpub)
    cv2 = point_multiplication(w3, cloud_server.G)
    
    # Step 3.13: Compute SKcfs = h2(m′i∥RV′1∥FV′1∥CV1)
    skcfs = hash_function(str(m_prime_i) + str(rv_prime_1) + str(fv1) + str(cv1))
    
    # Step 3.14: Compute CSUIDi = h2(Skcfs∥m′i∥T3∥CV1)
    csuid_i = hash_function(skcfs + str(m_prime_i) + str(t3) + str(cv1))
    
    # Step 3.15: Send {CV2, T3} to Fog Node for mutual authentication
    return {
        "CV2": cv2,
        "T3": t3
    }

    # login_authentication.py

def mutual_authentication(fog_node: FogNode, message_from_cloud_server: dict, user_device: SmartDevice):
    # Step 4.1: Receive {CV2, T3} from Cloud Server
    cv2 = message_from_cloud_server["CV2"]
    t3 = message_from_cloud_server["T3"]
    
    # Step 4.2: Verify the timestamp T3
    if not check_timestamp_validity(t3):
        raise ValueError("Message rejected due to invalid timestamp.")
    
    # Step 4.3: Compute CV1 = CV2.nf
    cv1 = point_multiplication(fog_node.nf, cv2)
    
    # Step 4.4: Compute SKfcs = h2(m′i∥RV′1∥FV′1∥CV1)
    skfcs = hash_function(str(fog_node.m_prime_i) + str(fog_node.rv_prime_1) + str(fog_node.fv1) + str(cv1))
    
    # Step 4.5: Compute CSUID′i = h2(Skfcs∥m′i∥T3∥CV1)
    csuid_prime_i = hash_function(skfcs + str(fog_node.m_prime_i) + str(t3) + str(cv1))
    
    # Step 4.6: Verify whether CSUID′i = CSUIDi
    if csuid_prime_i != fog_node.csuid_i:
        raise ValueError("Mutual Authentication Failed. CSUID mismatch.")
    
    # Step 4.7: Compute Session Key SK = h2(Skfcs∥T3∥RV′1)
    session_key = hash_function(skfcs + str(t3) + str(fog_node.rv_prime_1))
    
    # Step 4.8: Mutual Authentication is successful, store the session key in the user device
    user_device.store_session_key(session_key)
    
    return session_key

