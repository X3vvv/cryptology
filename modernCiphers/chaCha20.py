from random import randint


def chaCha20(data):
    return data


def genBitStr(len):
    s = ''
    for i in range(len):
        s += str(randint(0, 1))
    return s


def quarter_round(a, b, c, d):
    '''a,b,c,d are 4 32-bit string.'''

    def add(a, b):
        return bin((int(a, 2) + int(b, 2)) % (2 ** 32))[2:].zfill(32)

    def xor(a, b):
        return bin(int(a, 2) ^ int(b, 2))[2:].zfill(32)

    def lshift(n, d):
        return bin((int(n, 2) << d | int(n, 2) >> (32 - d)) % (2**32))[2:].zfill(32)

    a = add(a, b)
    d = xor(d, a)
    d = lshift(d, 16)

    c = add(c, d)
    b = xor(b, c)
    b = lshift(b, 12)

    a = add(a, b)
    d = xor(d, a)
    d = lshift(d, 8)

    c = add(c, d)
    b = xor(b, c)
    b = lshift(b, 7)

    return a, b, c, d



def test(input: str) -> None:
    '''input:128bit bin string'''
    a, b, c, d = input[0:32], input[32:64], input[64:96], input[96:128]

    print("Input:")
    print("\t", a)
    print("\t", b)
    print("\t", c)
    print("\t", d)

    a, b, c, d = quarter_round(a, b, c, d)

    print("Output:")
    print("\t", a)
    print("\t", b)
    print("\t", c)
    print("\t", d)
    print()

def mytest():
    test1 = '01111010011010000110000101101110011001110111100001101001011000010110111001111001011010010111001101101000011010010110010001100001'
    test2 = '11011010011010000110000101111110011001110111100001101001011110010110111001111001011010010111001101101000011010010110010001100001'
    test3 = '00110010011010000110000101100110011001110111100101101001011000010110111001111001011010010111001101101000011010010110010001100001'
    test4 = '00000010011010100110000101101110011001110010000011101001011001110110111001111001011010010111001101101000011010010110010001100001'
    test5 = '11111111111110010110000101101110011001110111100101101001011000010110011001111001011010010111001101101000011010010110010001100001'

    test(test1)
    test(test2)
    test(test3)
    test(test4)
    test(test5)


if __name__ == "__main__":
    def testChaCha20():
        print("Testing ChaCha20...")
        data = '1110100101100111'  # 1110 1001 0110 0111
        encrypted = chaCha20(data)
        decrypted = chaCha20(encrypted)
        print("Orignal data:", data)
        print("Encrypted   :", encrypted)
        print("Decrypted   :", decrypted)
    testChaCha20()
