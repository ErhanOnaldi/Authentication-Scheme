import secrets
import sympy

def generate_symmetric_trivariate_polynomial(degree, p):
    x, y, z = sympy.symbols('x y z')
    terms = set()  # Set kullanarak tekrarlı terimleri engelliyoruz

    for i in range(degree + 1):
        for j in range(i, degree + 1):
            for k in range(j, degree + 1):
                coeff = secrets.randbelow(p)  # Rastgele katsayı seçimi
                if coeff != 0:
                    # Tüm permütasyonları ekleyin
                    terms.add(coeff * x**i * y**j * z**k)
                    terms.add(coeff * x**i * z**j * y**k)
                    terms.add(coeff * y**i * x**j * z**k)
                    terms.add(coeff * y**i * z**j * x**k)
                    terms.add(coeff * z**i * x**j * y**k)
                    terms.add(coeff * z**i * y**j * x**k)

    # Simetrik polinom
    poly = sum(terms)
    return sympy.poly(poly, x, y, z, domain=sympy.FF(p))

# Örnek kullanım:
p = sympy.randprime(2**383, 2**384)  # Büyük bir asal sayı seçimi
degree = 3  # Polinomun derecesi
poly = generate_symmetric_trivariate_polynomial(degree, p)
print(poly)
