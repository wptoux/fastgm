from fastgm import SM2, SM3, SM4
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def zero_pad(data):
    buf_len = len(data)
    
    if buf_len % 16 == 0:
        return data
    else:
        new_len = (buf_len // 16 + 1) * 16
        return data + b'\0' * (new_len - buf_len)

def test_sm4_ecb():
    sm4 = SM4(b'1' * 16)
    assert sm4.decrypt_ecb(sm4.encrypt_ecb(b'helloworld')) == b'helloworld'

def test_sm4_ecb_with_crypto():
    key = b'1' * 16
    value = b'1' * 16
    
    cipher = Cipher(algorithms.SM4(key), mode=modes.ECB())
    encryptor = cipher.encryptor()
    enc_crypto = encryptor.update(zero_pad(value)) + encryptor.finalize()

    sm4 = SM4(key)

    assert enc_crypto == sm4.encrypt_ecb(value)

def test_sm4_generate_key():
    key = SM4.generate_key()
    sm4 = SM4(key)
    assert sm4.decrypt_ecb(sm4.encrypt_ecb(b'helloworld')) == b'helloworld'

def test_sm3():
    from gmssl.sm3 import sm3_hash

    assert SM3().hash(b'helloworld' * 1024) == sm3_hash(list(b'helloworld' * 1024))

def test_sm2():
    sk = '00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'
    pk = 'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'

    data = b'helloworld' * 1024

    sm2 = SM2()

    enc = sm2.encrypt(pk, data)
    dec = sm2.decrypt(sk, enc)

    assert dec == data

def test_sm2_generate_key():
    sm2 = SM2()

    sk, pk = SM2.generate_key()

    data = b'helloworld' * 1024

    enc = sm2.encrypt(pk, data)
    dec = sm2.decrypt(sk, enc)

    assert dec == data