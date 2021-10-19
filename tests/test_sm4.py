from fastgm import SM4

def test_sm4_ecb():
    sm4 = SM4(b'1233213')
    assert sm4.decrypt_ecb(sm4.encrypt_ecb(b'helloworld')) == b'helloworld'