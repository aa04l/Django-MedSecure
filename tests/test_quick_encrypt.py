from medcrypto import quick_encrypt, quick_decrypt, is_encrypted


def test_quick_encrypt_decrypt_roundtrip():
    msg = "hello-medcrypto"
    enc = quick_encrypt(msg, user_id=7)
    assert is_encrypted(enc)
    dec = quick_decrypt(enc, user_id=7)
    assert dec == msg
