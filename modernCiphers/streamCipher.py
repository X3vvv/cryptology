import random


def bitStrXor(x: str, y: str) -> str:
    '''00 or 11 -> 0, 01 or 10 -> 1'''
    if (x == '1' and y == '1') or (x == '0' and y == '0'):
        return '0'
    elif (x == '1' and y == '0') or (x == '0' and y == '1'):
        return '1'
    else:
        raise RuntimeError("only allow '0' or '1'")


def streamCipher(data: str, key: str) -> str:
    '''
    About stream cipher.
    Desc: symmetric ciphers.
    target: arbitrary long bit stream
    key: as long as the data
    algorithm: xor operator (00 or 11 -> 0, 01 or 10 -> 1).
    advantage: xor cannot be reverse, extremely fast, pretty simple,
                allow partial decryption.
    disadvantage: the key is the same length as data, could be too 
                long, not pratical; cannot protect the integrety of 
                original data; easy to break (only need to know the 
                encrypted data and original data at the same time, and
                do a simple xor operation to get the key)
    '''
    if len(data) != len(key):
        raise RuntimeError("Data and key should have the same length")
    processed = ''
    for i in range(len(data)):
        d, k = data[i], key[i]
        processed += bitStrXor(d, k)  # xor: 00 or 11 -> 0, 01 or 10 -> 1
    return processed


def advancedStreamCipher(data: str, shortKey: str) -> str:
    '''
    The difference between this version and the original version is
    that the key ('shortkey') dont have to be the same length as the
    data. We will use a number generator generate the whole key using
    the key ('shortkey') as the seed.

    shortkey: fixed length (e.g., 128k), shorter key
    Advantage: more pratical, extremely fast
    Disadvantage: shorter key, easier to be hacked. Have risk of using
                the wrong number generator (e.g., build-in random
                generators that have fixed pattern).
    '''
    random.seed(shortKey)
    processed = ''
    for bit in data:
        currBitOfKey = str(int(random.random()) % 2)
        processed += bitStrXor(bit, currBitOfKey)
    return processed


def testStreamCipher(data, key):
    encrypted = streamCipher(data, key)
    decrypted = streamCipher(encrypted, key)

    print("Original data: ", data)
    print("Key:           ", key)
    print("Encrypted data:", encrypted)
    print("Decrypted data:", decrypted)


def testAdvancedStreamCipher(data, key):
    print("Testing Stream Cipher...")
    encrypted = advancedStreamCipher(data, key)
    decrypted = advancedStreamCipher(encrypted, key)

    print("Original data: ", data)
    print("Key:           ", key)
    print("Encrypted data:", encrypted)
    print("Decrypted data:", decrypted)


if __name__ == "__main__":
    data = '0010110111'  # 10 bit example
    key = '1001100001'  # same length as data

    testStreamCipher(data, key)
    print("=====")
    testAdvancedStreamCipher(data, key)
