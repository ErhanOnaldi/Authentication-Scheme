
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

def inverse_mod(k, p):
    """Returns the inverse of k modulo p."""
    if k == 0:
        raise ZeroDivisionError('division by zero')

    if k < 0:
        return p - inverse_mod(-k, p)

    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    gcd, x, y = old_r, old_s, old_t

    assert gcd == 1
    assert (k * x) % p == 1

    return x % p

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

def get_curve_params(curve):
    """Returns the curve parameters a, b, p, g, n, and h for a given curve."""
    if isinstance(curve, ec.SECP384R1):
        a = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc
        b = 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef
        p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff
        g = (
            0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
            0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
        )
        n = 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973
        h = 0x1
    else:
        raise ValueError("Unsupported curve type")
    
    return a, b, p, g, n, h

def is_on_curve(point, curve):
    """Returns True if the given point lies on the elliptic curve."""
    if point is None:
        return True

    numbers = point.public_numbers()
    x, y = numbers.x, numbers.y
    a, b, p, _, _, _ = get_curve_params(curve)

    return (y * y - x * x * x - a * x - b) % p == 0

def point_neg(point, curve):
    """Returns -point."""
    assert is_on_curve(point, curve)

    if point is None:
        return None

    numbers = point.public_numbers()
    x, y = numbers.x, numbers.y
    _, _, p, _, _, _ = get_curve_params(curve)
    return ec.EllipticCurvePublicNumbers(x, -y % p, curve).public_key(default_backend())

def point_add(point1, point2, curve):
    """Returns the result of point1 + point2 according to the group law."""
    assert is_on_curve(point1, curve)
    assert is_on_curve(point2, curve)

    if point1 is None:
        return point2
    if point2 is None:
        return point1

    numbers1 = point1.public_numbers()
    x1, y1 = numbers1.x, numbers1.y
    numbers2 = point2.public_numbers()
    x2, y2 = numbers2.x, numbers2.y

    a, _, p, _, _, _ = get_curve_params(curve)

    if x1 == x2 and y1 != y2:
        return None

    if x1 == x2:
        m = (3 * x1 * x1 + a) * inverse_mod(2 * y1, p)
    else:
        m = (y1 - y2) * inverse_mod(x1 - x2, p)

    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p

    return ec.EllipticCurvePublicNumbers(x3, y3, curve).public_key(default_backend())

def scalar_mult(k, point, curve):
    """Returns k * point using the double-and-add algorithm."""
    assert is_on_curve(point, curve)

    _, _, _, _, n, _ = get_curve_params(curve)

    if k % n == 0 or point is None:
        return None

    if k < 0:
        return scalar_mult(-k, point_neg(point, curve), curve)

    result = None
    addend = point

    while k:
        if k & 1:
            if result is None:
                result = addend
            else:
                result = point_add(result, addend, curve)
        addend = point_add(addend, addend, curve)
        k >>= 1

    return result
