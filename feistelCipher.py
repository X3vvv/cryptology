'''
Feistel Cipher Design Principles
› Block size
– increasing size improves security, but slows cipher
› Key size
– increasing size improves security, makes exhaustive key searching harder, but
may slow cipher
› Number of rounds
– increasing number improves security, but slows cipher
› Subkey generation
– greater complexity can make analysis harder, but slows cipher
› Round function
– greater complexity can make analysis harder, but slows cipher
› Fast software en/decryption & ease of analysis
– are more recent concerns for practical use and testing
(reference: PolyU COMP3334 Lecture 3, Spring)
'''

# reference: https://www.youtube.com/watch?v=FGhj3CGxl8I

import secrets


def partition(data: str):
    '''
    Seperate data into two parts. 
    Here, to make it simple, we evenly seperate them.
    '''
    mid = int(len(data)/2)  # floor(length / 2)
    return data[:mid], data[mid:]


def streamCipher(data: str):
    '''
    Stream Cipher algorithm. The key is generated once using 'secrets' random lib.
    When used in feistel cipher, can use different keys in different rounds (need
    to be used reversly during decryption).
    '''
    global streamCipherKey
    try:
        streamCipherKey
    except NameError:
        streamCipherKey = ''
        for i in range(len(data)):
            streamCipherKey += str(secrets.randbelow(2))
    processed = ''
    for i in range(len(data)):
        processed += bitStrXor(data[i], streamCipherKey[i])
    return processed


def my_hash(data: str):
    num = 0
    for bit in data:
        num = num * 2 + int(bit)
    num = (num % 7) ^ 2
    processed = ''
    while num > 0:
        processed += str(num % 2)
        num = int(num / 2)
    processed = ''.join(
        ['0' for _ in range(len(data) - len(processed))]) + processed
    return processed


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


def feistelCipher(data: str = None, encryptionFunc=None, roundNum: int = None):
    '''
    Do feistel cipher (symmetric encryption algorithm, devised by Horst Feistel, IBM) to the 
    bit stream to encrypt/decrypt.
    @param data: string of bits
    @param func: encryption function, can be any encryption algorithm (can use different keys 
                in different rounds), even hash.
    @param roundNum: number of round of feistelCipher, default 3
    (reference: https://www.youtube.com/watch?v=FGhj3CGxl8I)
    '''

    # initialized parameters
    data = '10001111' if data is None else data
    encryptionFunc = streamCipher if encryptionFunc is None else encryptionFunc
    roundNum = 3 if roundNum is None else roundNum

    # algorithm start
    left, right = partition(data)
    for i in range(roundNum):
        right2 = encryptionFunc(right)
        left2 = bitStreamStrXor(right2, left)
        left, right = right, left2
    left, right = right, left
    return left+right


def testFeistelCipher(data: str, encryptionFunc, roundNum):
    '''
    Test feistel cipher.
    @param data: string of bits
    @param func: encryption function
    @param roundNum: number of round of feistelCipher
    '''
    print("Testing Feistel Cipher...")
    encrypted = feistelCipher(data, encryptionFunc, roundNum)
    decrypted = feistelCipher(encrypted, encryptionFunc, roundNum)
    print("Doing {} rounds feistel cipher...".format(roundNum))
    print('Original data:', data)
    print("Encrypted:    ", encrypted)
    print("Decrypted:    ", decrypted)


if __name__ == "__main__":
    # testFeistelCipher(data='10001111', encryptionFunc=streamCipher, roundNum=3)
    testFeistelCipher(data='10001111', encryptionFunc=my_hash, roundNum=3)
