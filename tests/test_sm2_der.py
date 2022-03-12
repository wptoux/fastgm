from fastgm import SM2, SM3, SM4

def test_sm2():
    sk = '00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'
    pk = 'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'

    data = b'helloworld' * 1024

    sm2 = SM2()
    sm2._sk = sk
    sm2._pk = pk
    enc = sm2.encrypt(data)
    dec = sm2.decrypt(enc)

    assert dec == data

def test_sm2_generate_key():
    sm2 = SM2.generate_key()
    data = b'helloworld'
    print(sm2._sk)
    print(sm2._pk)

    enc = sm2.encrypt(data)
    dec = sm2.decrypt(enc)
    
    assert dec == data

def test_sm2_form_pem():
    '''
    使用openssl 生成SM2密钥
    openssl ecparam -genkey -name SM2 -out sk.pem
    openssl ec -in sk.pem -pubout -out pk.pem
    '''
    with open('sk.pem') as f:
        sk_buffer = f.read()

    with open('pk.pem') as f:
        pk_buffer = f.read()

    sm2 = SM2()
    sm2.pk_from_pem(pk_buffer)
    sm2.sk_from_pem(sk_buffer)
    data = b'helloworld'

    enc = sm2.encrypt(data)
    dec = sm2.decrypt(enc)

    assert dec == data
