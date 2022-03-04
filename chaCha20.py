def chaCha20(data):
    return data


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
