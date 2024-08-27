from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import sympy
import pre_deployment
class EllipticCurveOperations:
    def __init__(self):
        self.ta = pre_deployment.TrustedAuthority() 
        self.curve = self.ta.curve # Elliptic Curve
        self.backend = self.ta.backend 
        self.p = int("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 16)  # Field prime p
        self.a = int("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc", 16)  # Curve parameter a
        self.b = int("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16)  # Curve parameter b
        print(f"Prime p: {self.p}")

    def point_add(self, P, Q):
        P_numbers = P.public_numbers()
        Q_numbers = Q.public_numbers()
        #print(f"Adding points P: {P_numbers}, Q: {Q_numbers}")
        
        x_p, y_p = P_numbers.x, P_numbers.y
        x_q, y_q = Q_numbers.x, Q_numbers.y
        
        if (x_p == x_q) and (y_p == y_q):
            return self.point_double(P)
        
        m = (y_q - y_p) * pow(x_q - x_p, -1, self.p) % self.p
        x_r = (m**2 - x_p - x_q) % self.p
        y_r = (m * (x_p - x_r) - y_p) % self.p
        R = ec.EllipticCurvePublicNumbers(x_r, y_r, self.curve)
        #print(f"Result of addition R: {R}")
        return R.public_key(self.backend)

    def point_double(self, P):
        P_numbers = P.public_numbers()
        print(f"Doubling point P: {P_numbers}")
        
        x_p, y_p = P_numbers.x, P_numbers.y
        m = (3 * x_p**2 + self.a) * pow(2 * y_p, -1, self.p) % self.p
        x_r = (m**2 - 2 * x_p) % self.p
        y_r = (m * (x_p - x_r) - y_p) % self.p
        R = ec.EllipticCurvePublicNumbers(x_r, y_r, self.curve)
        #print(f"Result of doubling R: {R}")
        return R.public_key(self.backend)

    def double_and_add(self, scalar, P):
        print(f"Starting double and add with scalar: {scalar} and point P: {P.public_numbers()}")
        result = None
        addend = P

        for bit in bin(scalar)[2:]:
            print(f"Current bit: {bit}")
            if result is None:
                result = addend
            else:
                result = self.point_double(result)

            if bit == '1':
                result = self.point_add(result, addend)

        print(f"Final result after double and add: {result.public_numbers()}")
        return result

# Test case
elliptic_curve = EllipticCurveOperations()
P = ec.EllipticCurvePublicNumbers(
    26247035095799689268623156744566981891852923491109213387815615900925518854738050089022388053975719786650872476732087,
    8325710961489029985546751289520108179287853048861315594709205902480503199884419224438643760392947333078086511627871,
    elliptic_curve.curve
).public_key(elliptic_curve.backend)
#scalar = 3678220481994384177625064431949350700258516693543656625513251350300321030904644808162657805788781748018319829337897
scalar = 2
result = elliptic_curve.double_and_add(scalar, P)
print(f"fog_n * G2 = ({result.public_numbers().x}, {result.public_numbers().y})")
