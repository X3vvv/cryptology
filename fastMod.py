def fastMod(x: int, p: int, m: int):
    '''Return x^p mod m.'''
    binP = format(p, 'b')
    pList = []
    for k in range(len(binP)):
        c = binP[len(binP) - 1 - k]
        if c == '1':
            pList.append(2**k)

    tmp = x
    xList = [tmp]  # [x^1 % m, x^2 % m, x^4 % m, ...]
    for i in range(len(binP)-1):
        tmp = (tmp*tmp) % m
        xList.append(tmp)

    x = 1
    for i in range(len(binP)):
        if binP[::-1][i] == '1':
            x *= xList[i]

    return x % m


# fastMod(5, 117, 19)

def EEA(b, m):
    '''
    Return the inverse of b from b (mod m), using Extended 
    Euclidean Algorithm (EEA) algorithm.

    b and m fulfill: (b * b^-1) mod m = 1
    '''
    a1, a2, a3 = 1, 0, m
    b1, b2, b3 = 0, 1, b
    while (True):
        if b3 == 0:
            return None  # gcd(m, b) = a3
        if b3 == 1:
            while(b2 < 0):
                b2 += m
            return b2  # gcd(m, b) = b3
        q = int(a3 / b3)  # quotient
        a1, a2, a3, b1, b2, b3 = b1, b2, b3, a1-q*b1, a2-q*b2, a3-q*b3


if __name__ == '__main__':
    e = 8051
    phi_n = 152744712
    print(EEA(e, phi_n))