from fastgm import SM4
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

