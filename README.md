# pygm
Fast GMSSL Library for Python
基于Cython的快速国密算法Python实现，目前支持SM4（ECB）

#### 介绍
基于Cython的快速国密算法Python实现，目前支持SM4（ECB）

#### 软件架构
软件架构说明


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
加密1024个helloworld，共计10240个字符，只需约6ms
```
%%timeit
sm4 = SM4(b'1233213')
sm4.decrypt_ecb(sm4.encrypt_ecb(b'helloworld' * 1024))

OUT:
6.61 ms ± 359 µs per loop (mean ± std. dev. of 7 runs, 100 loops each)

```