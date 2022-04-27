
from sympy import isprime


c = 2022
e = 27893
n = 124711

for i in range(2, int(n**0.5)):
    if not isprime(i):
        continue
    # if n % i != 0 or not isprime(n/i):
    #     continue
    if n % i != 0:
        continue
    p, q = i, n/i
    print(p, q)
