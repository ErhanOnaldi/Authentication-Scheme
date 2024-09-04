import core.utils as utils
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

def test_scalar_mult_large_positive_scalar():
    k = 5
    point = ec.EllipticCurvePublicNumbers(
        x=0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
        y=0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f,
        curve=ec.SECP384R1()
    ).public_key(default_backend())

    result = utils.scalar_mult(k, point, ec.SECP384R1())
    
    print(f"Resulting point: {result.public_numbers()}")



def _test_scalar_mult_large_positive_scalar():
    k = 5
    point = (0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
        0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f)
        

    result = utils._scalar_mult(k, point)
    
    print(f"Resulting point: {result}")

test_scalar_mult_large_positive_scalar()
_test_scalar_mult_large_positive_scalar()

