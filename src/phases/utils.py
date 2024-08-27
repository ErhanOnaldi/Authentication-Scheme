
import collections
import random
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import sympy
import pre_deployment


EllipticCurve = collections.namedtuple('EllipticCurve', 'name p a b g n h')

curve = EllipticCurve(
    'secp384r1',
    # Field characteristic.
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
    # Curve coefficients.
    a=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc,
    b=0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
    # Base point.
    g=(0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
       0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
    # Subgroup order.
    n=0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973,
    # Subgroup cofactor.
    h=0x1,
)


# Modular arithmetic ##########################################################

def _inverse_mod(k, p):
    #Returns the inverse of k modulo p.

    #This function returns the only integer x such that (x * k) % p == 1.

    #k must be non-zero and p must be a prime.
    
    if k == 0:
        raise ZeroDivisionError('division by zero')

    if k < 0:
        # k ** -1 = p - (-k) ** -1  (mod p)
        return p - _inverse_mod(-k, p)

    # Extended Euclidean algorithm.
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


# Functions that work on curve points #########################################

def _is_on_curve(point):
    #Returns True if the given point lies on the elliptic curve.
    if point is None:
        # None represents the point at infinity.
        return True

    x, y = point

    return (y * y - x * x * x - curve.a * x - curve.b) % curve.p == 0


def _point_neg(point):
    #Returns -point.
    assert _is_on_curve(point)

    if point is None:
        # -0 = 0
        return None

    x, y = point
    result = (x, -y % curve.p)

    assert _is_on_curve(result)

    return result


def _point_add(point1, point2):
    #Returns the result of point1 + point2 according to the group law.
    assert _is_on_curve(point1)
    assert _is_on_curve(point2)

    if point1 is None:
        # 0 + point2 = point2
        return point2
    if point2 is None:
        # point1 + 0 = point1
        return point1

    x1, y1 = point1
    x2, y2 = point2

    if x1 == x2 and y1 != y2:
        # point1 + (-point1) = 0
        return None

    if x1 == x2:
        # This is the case point1 == point2.
        m = (3 * x1 * x1 + curve.a) * _inverse_mod(2 * y1, curve.p)
    else:
        # This is the case point1 != point2.
        m = (y1 - y2) * _inverse_mod(x1 - x2, curve.p)

    x3 = m * m - x1 - x2
    y3 = y1 + m * (x3 - x1)
    result = (x3 % curve.p,
              -y3 % curve.p)

    assert _is_on_curve(result)

    return result


def _scalar_mult(k, point):
    #Returns k * point computed using the double and point_add algorithm.
    assert _is_on_curve(point)

    if k % curve.n == 0 or point is None:
        return None

    if k < 0:
        # k * point = -k * (-point)
        return _scalar_mult(-k, _point_neg(point))

    result = None
    addend = point

    while k:
        if k & 1:
            # Add.
            result = _point_add(result, addend)

        # Double.
        addend = _point_add(addend, addend)

        k >>= 1

    assert _is_on_curve(result)

    return result


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
