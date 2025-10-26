def generate_keystream(key, length):
        key_len = len(key)
        ks = []
        for i in range(length):
            val = (ord(key[i % key_len]) * (i**2 + 11*i + 7)) % 256
            symbol = chr(((ord(key[(i*3) % key_len]) + i * 5) % 93) + 33)
            ks.append((val, symbol))
        return ks


def encrypt(plaintext, key):
        ks = generate_keystream(key, len(plaintext))
        cipher = []
        for i, (p, (val, sym)) in enumerate(zip(plaintext, ks)):
            shift = ord(sym) % (6 if i % 2 == 0 else 4)
            if i % 2 == 0:
                shifted = (ord(p) + shift) % 256
            else:
                shifted = (ord(p) - shift) % 256
            cipher_val = shifted ^ val
            cipher.append(cipher_val)
        return bytes(cipher)


def decrypt(ciphertext, key):
        ks = generate_keystream(key, len(ciphertext))
        plain = []
        for i, (c, (val, sym)) in enumerate(zip(ciphertext, ks)):
            temp = c ^ val
            shift = ord(sym) % (6 if i % 2 == 0 else 4)
            if i % 2 == 0:
                orig = (temp - shift) % 256
            else:
                orig = (temp + shift) % 256
            plain.append(chr(orig))
        return ''.join(plain)

if __name__ == "__main__":
    key = input("Enter encryption key: ")
    text = input("Enter plaintext: ")

    print("\n--- Encryption ---")
    encrypted = encrypt(text, key)
    print("Encrypted (bytes):", encrypted)

    choice = input("\nDo you want to decrypt it? (y/n): ")
    if choice.lower() == 'y':
        decrypted = decrypt(encrypted, key)
        print("Decrypted text:", decrypted)
