'''
Classic Ciphers
Author: PAN Zewen Xavier
'''


def caesar(m: str, k: int = None) -> str:
    '''
    # Caesar cipher
    @param `k`: how many bits each letter will be right-shift in alphabet.
    - Encrypt: caesar(msg, k)
    - Decrypt: caesar(encrpyted, -k)
    '''

    LEN_OF_ALPHABET = 26
    k = k or 3
    crypted = ''
    for c in m:
        if c.isupper():
            crypted += chr(((ord(c) - ord('A') + k) %
                           LEN_OF_ALPHABET) + ord('A'))
        elif c.islower():
            crypted += chr(((ord(c) - ord('a') + k) %
                           LEN_OF_ALPHABET) + ord('a'))
        else:  # keep non-alphabet letters
            crypted += c
    return crypted


def monoalpha(m: str, mapfrom: str, mapto: str) -> str:
    '''
    # Monoalphabetic Substitution Ciphers
    @param `mapfrom`: 'abc...ABC...123...'
    @param `mapto`: 'ekl...EKL...!@#...'

    - Encrypt: monoalpha(msg, 'abc...ABC...123...', 'ekl...EKL...!@#...')
    - Decrypt: monoalpha(encrypted, 'ekl...EKL...!@#...',  'abc...ABC...123...', 'ekl...EKL...!@#...')
    '''

    charMap = dict(zip(mapfrom, mapto))
    return ''.join([charMap[c] if c in mapfrom else c for c in m])


def vigenere(m: str, key: str, encrypt: bool = True) -> str:
    '''# Vigenere Cipher'''

    # Generate vigenere cipher table
    textSpace = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    table = []
    for i in range(len(textSpace)):
        table.append(textSpace.copy())
        textSpace.append(textSpace.pop(0))

    # Extend key to have same length as msg
    m = m.upper()
    key = key.upper()
    while len(key) < len(m):
        key += key
    key = key[:len(m)]

    res = ''
    if encrypt:
        for i in range(len(m)):
            k, c = key[i], m[i]  # current letter in key, current letter in msg
            rw = ord(k)-ord('A')
            col = ord(c)-ord('A')
            res += table[rw][col]
    else:
        for i in range(len(m)):
            k, c = key[i], m[i]  # current letter in key, current letter in msg
            rw = ord(k)-ord('A')
            for i in range(len(table[rw])):
                if table[rw][i] == c:
                    res += table[0][i]

    return res


def otp(m: str, key: str) -> str:
    '''
    # One-Time Pad
    Use caecar cipher to implement one-time pad.
    Note that all letters will become upper case within this funtion.
    '''
    def getKey(l1: str, l2: str) -> str:
        assert l1[0].isupper()
        assert l2[0].isupper()
        return chr((ord(l1)-ord('A')+ord(l2)-ord('A')) % 26+ord('A'))

    m, key = m.upper(), key.upper()

    assert len(m) <= len(
        key), "Key must be no shorter than msg."
    res = ''
    for i in range(len(m)):
        res += getKey(m[i], key[i])
    return res


def bitOtp(m: str, key: str) -> str:
    '''
    # Bit One-Time Pad
    Use **XOR** to encrypt and decrypt.
    @param `m`: bit stream
    @param `key`: bit stream, which should be no shorter 
                    than `m`, only the first `len(m)` bits 
                    will be used.
    '''
    def xor(a: str, b: str) -> str:
        return '0' if (a == '1' and b == '1') or (a == '0' and b == '0') else '1'

    assert len(key) >= len(m), 'Key should be no shorter than msg.'
    res = ''
    for i in range(len(m)):
        res += xor(m[i], key[i])
    return res


def playfair(m: str, key: str) -> str:
    # TODO: 1) implement decryption, 2) optimize code, 3) deal with key has I/J, 4) fix bugs
    '''Playfair Ciphers'''
    assert len(key) <= 25, "Not support longer key for now."
    assert 'I' in key or 'i' in key or 'J' in key or 'j' in key, "Not support key with 'i' or 'j' for new."

    # Build table
    key = key.upper()
    table = list(key)

    for i in range(ord('A'), ord('Z')+1):
        c = chr(i)

        # Deal with 'I/J'
        if c == 'I' or c == 'J':
            # if key has I or J
            if 'I' in key or 'J' in key:
                continue
            # if key has neither I nor J
            elif c == 'J':  # if curr char is J
                continue
            else:  # if curr char is I
                pass

        if c not in key:
            table.append(c)

    # Main
    filler = 'X'
    res = ''
    for i in range(0, len(m), 2):
        pair = m[i:i+2]
        if pair[0] == pair[1]:
            pair[1] = filler

        i1, i2 = table.index(pair[0]), table.index(pair[1])
        # If pair in the same row

        def sameRow(a: int, b: int) -> bool:
            return int(a / 5) == int(b / 5)
        if sameRow(i1, i2):
            newI1, newI2 = i1+1, i2+1
            if not sameRow(i1, newI1):
                newI1 -= 5
            if not sameRow(i2, newI2):
                newI2 -= 5
            pair[0] = table[newI1]
            pair[1] = table[newI2]

        # If pair in the same column
        elif i1 % 5 == i2 % 5:
            pair[0] = table[(i1+5) % 25]
            pair[1] = table[(i2+5) % 25]

        # Otherwise
        else:
            # row(newI1) = row(i1), col(newI1) = col(i2). Same to newI2
            rw = int(i1 / 5)
            for i in range(5*rw, 5*rw+5):
                if i % 5 == i2 % 5:
                    pair[0] = table[i]

            rw = int(i2 / 5)
            for i in range(5*rw, 5*rw+5):
                if i % 5 == i1 % 5:
                    pair[1] = table[i]

        res += pair

    return res


def freqAttack(ciphertext: str, specialMap: dict) -> str:
    # TODO: allow hardcoded special map
    '''Try Statistical cryptanalysis to crack the ciphertext.'''
    letterFreq = dict(zip(
        'abcdefghijklmnopqrstuvwxyz',
        [
            8.2, 1.5, 2.8, 4.3, 12.7,
            2.2, 2.0, 6.1, 7.0, 0.2,
            0.8, 4.0, 2.4, 6.7, 7.5,
            1.9, 0.1, 6.0, 6.3, 9.1,
            2.8, 1.0, 2.4, 0.2, 2.0,
            0.1
        ]
    ))

    # e t a o i n s h r d l c u m w f g y p b v k j x q z
    orderLetterFreq = [c for c, _ in sorted(
        letterFreq.items(), key=lambda item: item[1], reverse=True)]
    # print('English freq:', ' '.join(orderLetterFreq))
    print('English freq: ', end='')
    for e in orderLetterFreq:
        print('{} '.format(e), end='')
    print()

    textFreq = {}
    for c in ciphertext:
        if not c.isalnum():
            continue
        if c in textFreq.keys():
            textFreq[c] += 1
        else:
            textFreq[c] = 1
    orderedTextFreq = dict(sorted(
        textFreq.items(), key=lambda item: item[1], reverse=True))
    # print('Text freq   :', ' '.join(orderedTextFreq.keys()))
    print('Text freq   : ', end='')
    for e in orderedTextFreq.keys():
        print('{} '.format(e), end='')
    print()
    # print('Appear count:', ' '.join([str(v) for v in orderedTextFreq.values()]))
    print('Appear count: ', end='')
    for e in orderedTextFreq.values():
        print('{:2>} '.format(e), end='')
    print()

    orderedTextFreq = list(orderedTextFreq.keys())
    crackMap = dict(zip(orderedTextFreq, orderLetterFreq))
    symbols = ' !@#$%^&*(),./;\'[]\\<>?:"{}|`~'
    # return ''.join([crackMap[c] if c not in symbols else c for c in ciphertext])

    res = ''
    for c in ciphertext:
        if c in symbols:
            res += c
        else:
            res += crackMap[c]

    return res


if __name__ == '__main__':
    plaintext = 'I love eating 114514 apples.'

    def pRes(cipherName, encrypted, decrypted, plaintext=plaintext):
        print(f"===== {cipherName} =====")
        print("Plaintext:", plaintext)
        print("Encrypted:", encrypted)
        print("Decrypted:", decrypted)
        print("Success :)" if decrypted == plaintext else "Failed ;(")
        print()

    def testCaesar():
        enc = caesar(plaintext, 3)
        dec = caesar(enc, -3)
        pRes('Caesar Cipher', enc, dec)
    # testCaesar()/

    def testMonoalpha():
        mapfrom = 'abcdefghijklmnopqrstuvwxyz1234567890' + \
            'abcdefghijklmnopqrstuvwxyz1234567890'.upper()
        mapto = 'DKVQFIBJWPESCXHTMYAUOLRGZN!@#$%^&*()'.lower() + \
            'DKVQFIBJWPESCXHTMYAUOLRGZN!@#$%^&*()'
        enc = monoalpha(plaintext, mapfrom, mapto)
        dec = monoalpha(enc, mapto, mapfrom)
        pRes('Monoalphabetic Substitution Cipher', enc, dec)
    # testMonoalpha()

    # TODO: finish this
    def testVigenere():
        text = 'attackatdawn'
        key = 'lemon'
        enc = vigenere(text, key, True)
        dec = vigenere(enc, key, False)
        pRes('Vigenere Cipher', enc, dec, text.upper())
    # testVigenere()

    def testFreqAttack():
        ciphertext = 'BQWE UQPY LOKATNEP Q LVFPTWQX \
MQOOTEO JK BXHTNP QZN XQORE LQOJTWXE NOKLXEJP PHORTWQX \
UQPY TP Q JFLE KB BQWE UQPY WKUUKZXF HPEN SVEZ HPEN \
LOKLEOXF PHORTWQX UQPYP WQZ LOEAEZJ TZBEWJTKZP \
JOQZPUTJJEN MF OEPLTOQJKOF NOKLXEJP'
        # print(freqAttack(ciphertext, {}))
        freqAttack(ciphertext, {})
    # testFreqAttack()

    # print(playfair('balloon', 'monarchy'))
