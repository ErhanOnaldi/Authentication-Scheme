# device_addition.py

from src.utils.crypto import hash_function, point_multiplication
from src.utils.helpers import generate_nonce
from src.entities.trusted_authority import TrustedAuthority

def add_device(trusted_authority: TrustedAuthority, device):
    # Step 1: Generate new device ID, timestamp, and nonce
    IDnew_s = device.id
    RTnew_s = generate_nonce()
    nnew_s = generate_nonce()
    
    # Step 2: Compute TIDnew_s and CIDnew_s
    TIDnew_s = hash_function(IDnew_s + trusted_authority.x + nnew_s)
    CIDnew_s = hash_function(TIDnew_s + RTnew_s + nnew_s)
    
    # Step 3: Compute device public key
    Snew_pub = point_multiplication(nnew_s, trusted_authority.G)
    
    # Step 4: Send computed values to the device
    device.receive_device_info({
        'TIDnew_s': TIDnew_s,
        'CIDnew_s': CIDnew_s,
        'RTnew_s': RTnew_s,
        'nnew_s': nnew_s,
        'g(x, y, z)': trusted_authority.g_xyz,
        'G': trusted_authority.G,
        'h0': trusted_authority.h0,
        'h1': trusted_authority.h1,
        'h2': trusted_authority.h2,
        'Gpub': Snew_pub
    })
    
    # Step 5: Publicize the new device's public key
    trusted_authority.publicize_device_key(Snew_pub)
    
    return Snew_pub
