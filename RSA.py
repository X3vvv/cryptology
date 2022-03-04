# reference:
#   https://www.youtube.com/watch?v=rVQpK6NcYIE
#   https://www.youtube.com/watch?v=wXB-V_Keiu8


import math
import secrets
import threading
import multiprocessing
from time import time
from timeit import timeit

from tqdm import tqdm


def rsaGenKey(primeStart: int = None):
    '''
    @param primeStart: start point of prime numbers (p, q >= primeStart). default 12345
    @return pubKey(e, n), privKey(d, n), (p, q)
    '''

    def getPQ(start: int = None):
        '''
        Get the 2 primes, p and q, which form phi_n, for RSA algorithm.
        p and q are large and roughly equal-length, e.g., |p|=|q|=512-bits.
        @param start: start point of the primes, default 12345.
        '''

        def gen_primes(start: int = None):
            """
            (Fast prime generator)
            Generate an infinite sequence of prime numbers.
            @param start: the start point of prime searching process, default 2.

            Sieve of Eratosthenes
            Code by David Eppstein, UC Irvine, 28 Feb 2002
            http://code.activestate.com/recipes/117119/
            """
            # Maps composites to primes witnessing their compositeness.
            # This is memory efficient, as the sieve is not "run forward"
            # indefinitely, but only as long as required by the current
            # number being tested.
            #
            D = {}

            # The running integer that's checked for primeness
            q = 2

            while True:
                if q not in D:
                    # q is a new prime.
                    # Yield it and mark its first multiple that isn't
                    # already marked in previous iterations
                    #
                    if q > start:
                        yield q
                    D[q * q] = [q]
                else:
                    # q is composite. D[q] is the list of primes that
                    # divide it. Since we've reached q, we no longer
                    # need it in the map, but we'll mark the next
                    # multiples of its witnesses to prepare for larger
                    # numbers
                    #
                    for p in D[q]:
                        # if D.has_key(p+q):
                        #     D[p+q].append(p)
                        # else:
                        #     D[p+q] = [p]
                        D.setdefault(p + q, []).append(p)
                    del D[q]

                q += 1

        start = start or 12345

        cnt = 0
        for i in gen_primes(start):
            if cnt == 0:
                p = i
            elif cnt == 1:
                q = i
            else:
                break
            cnt += 1
        return p, q

    def getE(phi_n):
        '''
        Generate e of the public key of RSA (PK=(e, n)).
        1 < e < phi(n), n % e != 0
        '''

        def gcd(a, b):
            ''' Return gcd of a and b'''
            if a == 0 and b == 0:
                raise ValueError("a and b cannot be both 0")
            if a < b:
                a, b = b, a
            # print("In gcd, a={}, b={}".format(a, b))
            if b == 0:
                return a
            while True:
                tmp = a % b
                if tmp == 0:
                    return b
                a, b = b, tmp

        i = secrets.randbelow(int(math.sqrt(phi_n)))
        while i < phi_n:
            # i must be co-prime to phi and
            # smaller than phi.
            if gcd(i, phi_n) == 1:
                return i
            i += 1

    def getD(e, phi_n):
        '''Get d of the private key of RSA.'''
        def slowMethod():
            '''Simple way, extremely slow.'''
            print(
                f"Trying to get d (e={e}, phi_n={phi_n}), this may take some time...", end='')
            timer = time()
            d = 1
            while (d * e) % phi_n != 1:
                d += 1
            print("finished in {:.3}s".format(time.time()-timer))
            return d

        def fastMethod():
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

            d = EEA(e, phi_n)
            assert d > 0, f"d should be positive (e={e}, phi_n={phi_n})"
            return d

        res = fastMethod()
        return res

    # Public key
    p, q = getPQ(primeStart)
    n = p * q  # public modulus
    phi_n = (p-1) * (q-1)
    e = getE(phi_n)
    pubKey = (e, n)

    # Private key
    d = getD(e, phi_n)
    privKey = (d, n)

    return pubKey, privKey, (p, q)


def fastMod(x: int, p: int, m: int):
    '''Fast modular square operation. Return x^p mod m.'''
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


def rsaEncrypt(data: int, pk: tuple) -> int:
    '''Encrypt data using RSA public key. Return encrypted data.'''
    e, n = pk
    # How to simplify the calculation:
    #    if x = a * b, then
    #    x mod n = [(a mod n) * (b mod n)] mod n
    # e.g., 16 mod 3 = (4 mod 3)(4 mod 3) mod 3 = 1*1 mod 3 = 1
    # for more: https://chenyangwang.gitbook.io/mathematical-base-for-information-safety/tong-yu-shi/fu-za-qu-mo-yun-suan-jian-hua
    # return (data**e) % n
    return fastMod(data, e, n)


def rsaDecrypt(encrypted: int, sk: int) -> int:
    '''Decrypt data using RSA private key. Return decrypted data.'''
    d, n = sk
    # return (encrypted**d) % n
    return fastMod(encrypted, d, n)


corruptTime = 0


def rsaDemo(info: bool = False, data: int = None):
    pk, sk, (p, q) = rsaGenKey()
    if info:
        print("Primes     : (p={}, q={})".format(p, q))
        print("Public key : (e={}, n={})".format(pk[0], pk[1]))
        print("Private key: (d={}, n={})".format(sk[0], sk[1]))

    data = data or 123456
    enc = rsaEncrypt(data, pk)
    dec = rsaDecrypt(enc, sk)
    if info:
        print("Data     :", data)
        print("Encrypted:", enc)
        print("Decrypted:", dec)

    global corruptTime
    if data != dec:
        corruptTime += 1


def rsaDemoTimeit():
    runTime = 200
    t = timeit(rsaDemo, number=runTime)
    print("Finished in {:.3}s ({:.3}s/round)".format(t, t/runTime))
    print("{}% success ({} failed)".format(
        int((runTime-corruptTime)/runTime*100), corruptTime))


def hackDemo():
    '''
    Bob's old d is leaked, but he didn't change p and q, and
    directly generate new e2, n2, and d2. How to hack d2.
    '''
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

    # Unknown
    p = 12347
    q = 12373
    phi_n = (p-1)*(q-1)
    # Known
    e = 9833
    n = 152769431
    d = 55455977
    e2 = 2
    # Target
    d2 = EEA(e2, phi_n)

    # Try to guess d2
    # phi_n=(e*d-1)/k (k<min(e,d))
    print("Start hacking...")
    timer = time()
    guessed = []
    k_limit = min(e, d)
    for k in tqdm(range(1, k_limit)):
        # for k in range(1, k_limit):
        gphi_n = (e*d-1)/k
        gp_limit = min(n, gphi_n)
        for gp in tqdm(range(1, gp_limit)):
            # for gp in range(1, gp_limit):
            if n % gp == 0:
                gq = n/gp
                if gp*gq == n and (gp-1)*(gq-1) == gphi_n:
                    gd = EEA(e2, gphi_n)
                    print("Guessed d: {}. {}".format(
                        gd, 'Correct' if gd == d2 else 'Wrong'))
                    guessed.append(gphi_n)
    # for gphi_n in guessed:
    #     gd = EEA(e2, gphi_n)
    #     print("Guessed d: {}. {}".format(
    #         gd, 'Correct' if gd == d2 else 'Wrong'))
    print("Finished in {:.3}s.".format(time()-timer))


def threadHackDemo():
    '''
    Threading accelated hacking process:
    Bob's old d is leaked, but he didn't change p and q, and
    directly generate new e2, n2, and d2. How to hack d2.
    '''

    # Unknown
    p, q = 12347, 12373
    phi_n = (p-1)*(q-1)
    # Known
    e, n, d, e2 = 9833, 152769431, 55455977, 2
    # Target
    d2 = EEA(e2, phi_n)

    def hack(k_start, k_end, childID):
        # Try to guess d2
        print("Start hacking...")
        timer = time()
        guessed = []
        for k in tqdm(range(k_start, k_end), desc=f"Child {childID} (k:[{k_start}~{k_end}])"):
            if (e*d-1) % k != 0:
                continue
            gphi_n = int((e*d-1)/k)
            gp_limit = min(n, gphi_n)
            for gp in tqdm(range(1, gp_limit), desc=f"Child {childID} (gp:[1~{gp_limit}])"):
                if n % gp == 0:
                    gq = n/gp
                    if gp*gq == n and (gp-1)*(gq-1) == gphi_n:
                        gd = EEA(e2, gphi_n)
                        if gd == None:
                            tqdm.write(
                                "Find the good p,q, but dont have an inversion e.")
                            continue
                        tqdm.write("Guessed d: {}. {}".format(
                            gd, 'Correct' if gd == d2 else 'Wrong'))
                        guessed.append([gp, gq])
        print("All guessed results (in form of [p, q]):", guessed)
        print("Finished in {:.3}s.".format(time()-timer))

    k_limit = min(e, d)
    cpuCnt = multiprocessing.cpu_count() - 2  # prevent killing computer
    step = math.ceil(k_limit/cpuCnt)
    for i in range(cpuCnt):
        k_start, k_end = step*i, step*(i+1)
        if k_start == 0:
            k_start = 1
        if k_end > k_limit:
            k_end = k_limit
        t = threading.Thread(target=hack, args=(k_start, k_end, i+1))
        t.start()


if __name__ == '__main__':
    rsaDemo(True, 114514)
    # threadHackDemo()
