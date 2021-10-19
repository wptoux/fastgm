# pygm
Fast GMSSL Library for Python
基于Cython的快速国密算法Python实现，目前支持SM4（ECB）

#### 介绍
基于Cython的快速国密算法Python实现，目前支持SM4（ECB）


#### 安装教程
下载项目
```
cd pygm
pip install .
```

#### 使用说明

```
from pygm import SM4

def test_sm4_ecb():
    sm4 = SM4(b'1233213')
    assert sm4.decrypt_ecb(sm4.encrypt_ecb(b'helloworld')) == b'helloworld'

```

#### benchmark
加密1024个helloworld，共计10240个字符，只需约6ms。纯Python实现的gmssl-python需要约171ms。

本方法
```
%%timeit
sm4 = SM4(b'1233213')
sm4.decrypt_ecb(sm4.encrypt_ecb(b'helloworld' * 1024))

OUT:
6.61 ms ± 359 µs per loop (mean ± std. dev. of 7 runs, 100 loops each)

```

gmssl-python(https://github.com/gongxian-ding/gmssl-python)
```
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT

%%timeit
key = b'1233213'
key = key + (16 - len(key)) * b'\0'
value = b'helloworld' * 1024
crypt_sm4 = CryptSM4()


crypt_sm4.set_key(key, SM4_ENCRYPT)
encrypt_value = crypt_sm4.crypt_ecb(value) #  bytes类型
crypt_sm4.set_key(key, SM4_DECRYPT)
decrypt_value = crypt_sm4.crypt_ecb(encrypt_value) #  bytes类型

OUT:
171 ms ± 3.28 ms per loop (mean ± std. dev. of 7 runs, 10 loops each)
```

测试环境，Intel 8265U，WSL2。

### 参考
[1] https://github.com/guanzhi/GmSSL
[2] https://github.com/gongxian-ding/gmssl-python