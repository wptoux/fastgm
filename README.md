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

##### SM2
SM2是国家密码管理局发布的椭圆曲线公钥密码算法。对标RSA

使用方法：

+ 使用公钥加密

```
from fastgm import SM2

pk = 'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207' # 公钥，Hex格式

data = b'helloworld' # 待加密内容，格式为bytes数组

sm2 = SM2() # 初始化
enc = sm2.encrypt(pk, data) # 运行加密算法

```

+ 使用私钥解密
```
from fastgm import SM2

sk = '00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'  # 私钥

sm2 = SM2() # 初始化

dec = sm2.decrypt(sk, enc) # 运行解密算法，enc为加密内容

```

#### SM3
SM3密码杂凑算法是中国国家密码管理局2010年公布的中国商用密码杂凑算法标准。对标MD5

使用方法：

```
from fastgm import SM3
data = b'helloworld'  # 待哈希bytes数组
h = SM3().hash(data)  # 哈希运算

```

#### SM4
SM4.0（原名SMS4.0）是中华人民共和国政府采用的一种分组密码标准。对标AES。

使用方法：

+ Zero Padding ECB加解密
```
from fastgm import SM4

key = b'1' * 16  # key为16位bytes数组
data = b'helloworld' # 待加密内容

sm4 = SM4(key)  # 初始化

enc = sm4.encrypt_ecb(data) # 加密
dec = sm4.decrypt_ecb(enc)  # 解密

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
[2] https://github.com/duanhongyi/gmssl  
[3] https://github.com/gongxian-ding/gmssl-python  
[4] https://github.com/pyca/cryptography