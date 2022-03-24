# coding=utf-8
from fastgm import SM2, SM3, SM4
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT

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


def test_sm4_cbc():
    key = b"1" * 16
    iv = b"2" * 16
    plain_text = b'/#N4:=EFtd|2"}Wg0'
    sm4 = SM4(key, "pkcs7")

    assert sm4.decrypt_cbc(iv, sm4.encrypt_cbc(iv, plain_text)) == plain_text

    crypt_sm4 = CryptSM4()
    crypt_sm4.set_key(key, SM4_ENCRYPT)
    encrypt_value = crypt_sm4.crypt_cbc(iv, plain_text)
    crypt_sm4.set_key(key, SM4_DECRYPT)
    decrypt_value = crypt_sm4.crypt_cbc(iv, encrypt_value)
    assert plain_text == decrypt_value

    assert crypt_sm4.crypt_cbc(iv, sm4.encrypt_cbc(iv, plain_text)) == plain_text
    crypt_sm4.set_key(key, SM4_ENCRYPT)
    assert sm4.decrypt_cbc(iv, crypt_sm4.crypt_cbc(iv, plain_text)) == plain_text


def test_sm4_ecb_with_crypto():
    key = b'1' * 16
    value = b'1' * 16
    
    cipher = Cipher(algorithms.SM4(key), mode=modes.ECB())
    encryptor = cipher.encryptor()
    enc_crypto = encryptor.update(zero_pad(value)) + encryptor.finalize()

    sm4 = SM4(key)

    assert enc_crypto == sm4.encrypt_ecb(value)

def test_sm4_ecb_pkcs7():
    sm4 = SM4(b'1' * 16, padding='pkcs7')
    assert sm4.decrypt_ecb(sm4.encrypt_ecb(b'helloworld')) == b'helloworld'

def test_sm4_ecb_with_gmssl():
    from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT

    crypt_sm4 = CryptSM4()

    crypt_sm4.set_key(b'1' * 16, SM4_ENCRYPT)
    gmssl_enc = crypt_sm4.crypt_ecb(b'plain_text')

    from fastgm import SM4
    fastgm_enc = SM4(b'1'*16, padding='pkcs7').encrypt_ecb(b'plain_text')

    assert gmssl_enc == fastgm_enc

def test_sm4_generate_key():
    key = SM4.generate_key()
    sm4 = SM4(key)
    assert sm4.decrypt_ecb(sm4.encrypt_ecb(b'helloworld')) == b'helloworld'

def test_sm3():
    # python2下不能再用gmssl进行测试，因为版本不支持
    # gmssl项目官方源地址下未找到历史版本
    from gmssl.sm3 import sm3_hash
    
    # python2.7下测试用
    # a = SM3().hash(b'helloworld' * 1024)
    # print(a)
    # python2此处会中断，但fastgm.sm3.hash的结果已经打印在stdout上，可以和python3环境下的输出结果对比
    # b = sm3_hash(list(b'helloworld' * 1024)) 
    # print(b)
    # assert  a == b
    
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
