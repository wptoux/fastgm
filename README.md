# fastgm
Fast GMSSL Library for Python  

基于Cython的快速国密算法Python实现，目前支持SM2, SM3, SM4（ECB）

#### 介绍
基于Cython的快速国密算法Python实现，目前支持SM2, SM3, SM4（ECB）


#### 安装教程
```
pip install fastgm
```

#### 使用说明

```
from fastgm import SM2, SM3, SM4

def test_sm4_ecb():
    sm4 = SM4(b'1' * 16)

    enc = sm4.encrypt_ecb(b'helloworld')
    dec = sm4.decrypt_ecb(enc)

def test_sm3():
    h = SM3().hash(b'helloworld' * 1024)

def test_sm2():
    sk = '00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'
    pk = 'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'

    data = b'helloworld' * 1024

    sm2 = SM2()

    enc = sm2.encrypt(pk, data)
    dec = sm2.decrypt(sk, enc)

```

#### benchmark
以SM4为例，加密1024个helloworld，共计10240个字符，只需约0.3ms。纯Python实现的gmssl-python需要约171ms。


|   |fastgm（本方法）|gmssl-python|crytography|
|-  |---------------|------------|-----------|
|sm2|**29.9 ms ± 1.39 ms**|1.12 s ± 22.3 ms|未提供|
|sm3|**802 µs ± 21.4 µs**|111 ms ± 10.4 ms|未提供|
|sm4|299 µs ± 6.61 µs|170 ms ± 1.22 ms| **283 µs ± 6.57 µs**|

测试环境，Intel 8265U，WSL2。

### 参考
[1] https://github.com/guanzhi/GmSSL  
[2] https://github.com/gongxian-ding/gmssl-python  
[3] https://github.com/pyca/cryptography