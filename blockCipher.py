from unicodedata import decimal
from sympy import blockcut
from feistelCipher import feistelCipher


def blockCipher(data: str, blockSize: int, cipherAlgorithm):
    '''
    Seperate data into blocks and apply cipher algorithms on each block.
    @param data: bit stream string (here to make it simple, must be 
                divisible by 'blocksize')
    @param blockSize: size of each block, default 8 (bits)
    @param cipherAlgorithm: cipher algorithm function
    '''

    processed = ''
    while len(data) > 0:
        currblock = data[:blockSize]
        processedBlock = cipherAlgorithm(currblock)
        processed += processedBlock
        data = data[blockSize:]
    return processed


def testBlockCipher():
    print("Testing Block Cipher...")
    data = '1010111101110000'  # 1010 1111 0101 0000
    encrypted = blockCipher(data, 8, feistelCipher)
    decrepted = blockCipher(encrypted, 8, feistelCipher)
    print("Original data:", data)
    print("Encrypted:    ", encrypted)
    print("Decrepted:    ", decrepted)


if __name__ == "__main__":
    testBlockCipher()
