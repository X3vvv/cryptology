from sympy import isprime
import random


def BBSgenerator(nbits=8):
    '''
    BBS also called CSPRG (source: https://blog.csdn.net/android_jiangjun/article/details/80648184).
    Blum Blum Shub (B.B.S.) is a pseudorandom number generator proposed in 1986 by 
    Lenore Blum, Manuel Blum and Michael Shub[1] that is derived from Michael O. 
    Rabin's one-way function. (source: https://en.wikipedia.org/wiki/Blum_Blum_Shub)
    @param nbits: number of bits of the number. e.g., 8-bits: 0~255
    '''

    def generatePQ(start=None):
        '''
        Get the big prime number p and q.
        In BBS algorithm, p ≡ q ≡ 3(mod 4)
        @param start: start of finding big prime, 
                    default 1,000,000 (1 million)
        '''
        x = 1000000 if start is None else start
        p = q = None
        while (True):
            if isprime(x) and (x % 4) == 3:
                if p is None:
                    p = x
                elif q is None:
                    q = x
                else:
                    break
            x += 1
        return p, q

    # initialize p and q
    p, q = generatePQ()
    n = p * q
    s = p
    while (s % p) == 0 or (s % q) == 0:
        s = random.SystemRandom().randint(p+q, p+p+q+q)
    x = (s * s) % n
    num = 0
    for i in range(nbits):
        x = (x*x) % n
        num = num * 2 + (x % 2)
    return num


if __name__ == "__main__":
    print("Testing BBS generator...")
    # test: generate 10 random integers
    for i in range(10):
        print(BBSgenerator(16))
