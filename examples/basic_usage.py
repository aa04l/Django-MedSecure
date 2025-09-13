from medcrypto import quick_encrypt, quick_decrypt, is_encrypted


def main():
    secret = "Patient heart rate: 78 bpm"
    enc = quick_encrypt(secret, user_id=42)
    print("Encrypted:", enc)
    print("Is encrypted?", is_encrypted(enc))
    dec = quick_decrypt(enc, user_id=42)
    print("Decrypted:", dec)


if __name__ == "__main__":
    main()
