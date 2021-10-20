# fastgm
Fast GMSSL Library for Python  

基于Cython的快速国密算法Python实现，目前支持SM4（ECB）

#### 介绍
基于Cython的快速国密算法Python实现，目前支持SM4（ECB）


#### 安装教程
下载项目
```
pip install fastgm
```

#### 使用说明

```
from fastgm import SM4

def test_sm4_ecb():
    sm4 = SM4(b'1233213')
    assert sm4.decrypt_ecb(sm4.encrypt_ecb(b'helloworld')) == b'helloworld'

```

#### benchmark
加密1024个helloworld，共计10240个字符，只需约0.3ms。纯Python实现的gmssl-python需要约171ms。


|   |fastgm（本方法）|gmssl-python|crytography|
|-  |---------------|------------|-----------|
|sm4|299 µs ± 6.61 µs|170 ms ± 1.22 ms| 283 µs ± 6.57 µs|

测试环境，Intel 8265U，WSL2。

### 参考
[1] https://github.com/guanzhi/GmSSL  
[2] https://github.com/gongxian-ding/gmssl-python  
[3] https://github.com/pyca/cryptography