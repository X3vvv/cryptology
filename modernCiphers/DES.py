'''
DES, Data Encryption Standard, is one example of fiestel cipher.
Symmetric encryption: but the decryption shuold use the sub-keys that used in
                    encryption reversely.
It's a block cipher, 64-bits / block
Key: 64-bits, the 8k-th bit is the parity bit (utilize for error detection in 
    key generation, distribution, and storage), thus 56-bits effective key
Round: 16 rounds, can have 16 different sub-keys

E.g., 
X = (3 5 0 7 7 F 1 0 A B 1 2 F C 6 5)hex
K = (k1 … k7 k8 … k15 k16 k17 … k24 … k32 … k40 … k48 … k56 … k64)
    (where k8, k16, k24, k32, k40, k48, k56, k64 are parity bits for each byte, 
    help ensure that each byte is of odd parity)
'''
import secrets


def myCipher(data: str, key):
    return data.reverse()


def bitStreamStrXor(streamX: str, streamY: str):
    '''Do xor on streamX[k] and streamY[k]'''

    def bitStrXor(x: str, y: str) -> str:
        '''00 or 11 -> 0, 01 or 10 -> 1'''
        if (x == '1' and y == '1') or (x == '0' and y == '0'):
            return '0'
        elif (x == '1' and y == '0') or (x == '0' and y == '1'):
            return '1'
        else:
            raise RuntimeError("only allow '0' or '1'")

    if len(streamX) != len(streamY):
        raise RuntimeError("Two streams should have save length")
    processed = ''
    for i in range(len(streamX)):
        processed += bitStrXor(streamX[i], streamY[i])
    return processed


def eBox(longRight: str):
    MAXLEN = 32
    return longRight[:MAXLEN]


def DES(data: str, cipher, subkeys: list):
    '''
    @param data: bit stream string, should have length of 64
    @param cipher: any cipher algorithm
    @param subkeys: subkeys to be used in each round, 
                    should have length of 16
    Algorithm:
        L_i = R_(i-1)
        R_i = L_(i-1) XOR F(R_(i-1), K_i)

    The function F takes 32-bit R and 48-bit subkey, and
    - expands R to 48 bits using perm E
    - adds to subkey
    - passes through 8 S-boxes to get a 32-bit result
    - finally permutes this using 32-bit perm P

    (here, as a primitive demo, a hash is used as cipher)
    reference: https://www.youtube.com/watch?v=r6ZYb_3-Yh4
    '''
    BLOCK_LEN = 64
    ROUND_NUM = 16
    assert len(data) == BLOCK_LEN
    assert len(subkeys) == ROUND_NUM
    left, right = data[:int(BLOCK_LEN/2)], data[int(BLOCK_LEN/2):]
    for i in range(ROUND_NUM):
        # generate new left and right
        key = subkeys[i]
        left2 = right
        encryptedRight = cipher(right, key)

        # shrink the new 'right' (right2) to 32bit if its too long
        # after being applied to cipher
        if len(encryptedRight) > BLOCK_LEN/2:
            encryptedRight = eBox(encryptedRight)

        right2 = bitStreamStrXor(left, encryptedRight)

        # switch left and right
        left, right = left2, right2
        return left+right  # merge left and right


def testDES(data: str, cipher, subkeys: list):
    print("Testing DES...")
    encrypted = DES(data, cipher, subkeys)
    decrypted = DES(encrypted, cipher, subkeys.reverse())
    print("Original data:", data)
    print("Encrypted    :", encrypted)
    print("Decrypted    :", decrypted)


data = ''.join([str(secrets.randbelow(2)) for _ in range(64)])  # 64 bit string
testDES(data, myCipher, ['' for _ in range(16)])
