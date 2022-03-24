#### python2兼容性调整 1:

```python
k = os.urandom(32)
k = int(k.hex(), 16)
```

> 问题描述：
>
> python3中`os.urandom()`的返回值是bytes类型，该类型拥有`hex()`方法
>
> python2中没有bytes类型，bytes与str被视为同类型，`os.urandom()`输出str类型，该类型在python2中没有`hex()`方法，导致程序报错



> 该问题出现位置：
>
> in sm2.py
>
> ```python
> def encrypt(pk, k, data, mode='C1C3C2'):
>     ...
>     msg = data.hex()  # 消息转化为16进制字符串
>     k = int(k.hex(), 16)
>     pk = hex2point(pk)
> ```
>
> ```python
> def decrypt(sk, data, mode='C1C3C2'):
>     ...
>     # 解密函数，data密文（bytes）
>     data = data.hex()
>     len_2 = 128
> ```
>
> ```python
> def generate_key():
>     ...
>     k = os.urandom(32)
>     k = int(k.hex(), 16)
> ```



> solution：
>
> 使用`binascii.hexlify()`方法
>
> ```python
> k = os.urandom(32)
> k = int(k.hex(), 16)
> ```
>
> 改为：
>
> ```python
> import binascii
> 
> k = os.urandom(32)
> k = int(binascii.hexlify(k), 16)
> ```
>
> 在python2中，`binascii.hexlify(k)`与python3中的`k.hex()`效果相同，且返回类型都为str类型
>
> 在python3中，`binascii.hexlify()`的输出类型为bytes，但不影响后续的`int()`函数的运行和输出
>
> 
>
> 将上述位置的代码重构后build_ext，在python3.8环境下运行test_gm.py中的测试函数`test_sm2()`、`test_sm2_generate_key()`均通过，python命令行手动测试可以正常加解密。
>
> 在python2.7环境中有待检验（因为还有其他兼容性问题导致报错）



#### python2兼容性调整 2:

```python
zin = bytes.fromhex(z.decode('utf-8'))
```

> 问题描述：
>
> python2中没有bytes类型，bytes与str被视为同类型，`bytes.fromhex()`相当于`str.fromhex()`，而python2中的str类型没有`fromhex()`方法，导致程序报错：`type object 'str' has no attribute 'fromhex'`



> 该问题出现位置：
>
> in sm3.pyx
>
> ```python
> def kdf(z, klen): # z为16进制表示的比特串（str），klen为密钥长度（单位byte）
>     ...
>     zin = bytes.fromhex(z.decode('utf8'))
>     ...
>     msg = zin  + bytes.fromhex('%08x' % ct)
> ```
>
> in sm2.py
>
> ```python
> def encrypt(pk, k, data, mode='C1C3C2'):
>     ...
>     C3 = hash(bytes.fromhex('%s%s%s' % (x2, msg, y2)))
> 
>     if mode == 'C1C3C2':
>         return bytes.fromhex('%s%s%s' % (C1, C3, C2))
>     elif mode == 'C1C2C3':
>         return bytes.fromhex('%s%s%s' % (C1, C2, C3))
>     else:
>         return None    
> ```
>
> ```python
> def decrypt(sk, data, mode='C1C3C2'):
>     ...
>     u = hash(bytes.fromhex('%s%s%s' % (x2, M, y2)))
>         
>     if u == C3:
>         return bytes.fromhex(M)
>     else:
>         return None
> ```



> solution:
>
> 使用`binascii.unhexlify()`方法
>
> ```python
> zin = bytes.fromhex(z.decode('utf-8'))
> ```
>
> 改为：
>
> ```python
> import binascii
> 
> zin = binascii.unhexlify(z.decode('utf-8'))
> ```
>
> 在python2中，`binascii.unhexlify(s)`与python3中的`bytes.fromhex(s)`效果相同，前者（在python2中）返回类型为str（在相当于bytes），而在python3中，两者的返回类型都是bytes
>
> 
>
> 将上述位置的代码重构后build_ext，在python3.8环境下运行抛出`binascii.Error: Odd-length string`错误，详细分析转`《python2兼容性调整2-1》`
>
> 在python2.7环境中有待检验（因为还有其他兼容性问题导致报错）



#### python2兼容性调整2-1:

> 上接`《python2兼容性调整2/solution》`
>
> 问题分析：
>
> 抛出`binascii.Error: Odd-length string`错误，说明传递给`binascii.unhenlify()`方法的参数的长度是奇数（无论是`bytes.fromhex()`还是`binascii.unhexlify()`都只能接收偶数长度参数，详见python官方文档说明）
>
> 其原因是使用了`binascii.hexlify()`方法，使得在python3环境下的msg变量类型为bytes
>
> 导致后续的`binascii.unhexlify('%s%s%s' % (x2, msg, y2))`语句有问题，具体是在`%s%s%s' % (x2, msg, y2)`的字符串拼接上，拼接msg时，会先将msg转换成str类型再拼接，而`str(msg)`的结果为`"b'xxxxxxxxxx'"`
>
> 该字符串带上了bytes类型的标识：前缀b以及两个单引号，使得msg的长度增加了3，即`len(msg) + 3 = len(str(msg))`
>
> 
>
> 初步解决方法是使用先用`str()`函数将msg转换成str类型，再判断其长度，如果长度是偶数，则证明是在python2环境下；如果长度为奇数，则可以使用切片的方式去掉msg中多余的部分：`msg = msg[2:-1]`
>
> ```python
> msg = str(msg)
> if len(msg) % 2 == 1:
>  msg = msg[2:-1]
> ```
>
> 虽然在python3中，`str()`函数可以指定编码类型使得转换后的字符串不带有bytes类型的标识（自动去掉前缀b和两个单引号），但是这样使用在python2中又会出错，因为python2的`str()`函数不支持两个输入参数，所以这里选择了加一个逻辑判断来解决问题。但是总感觉这么做不够优雅......征求一下更好的处理办法



> 修改涉及的位置：
>
> 这些地方使用`binascii.hexlify()`进行处理后，返回值变量后续还需要参与某些运算和操作
>
> ```python
> def encrypt(pk, k, data, mode='C1C3C2'):
>     # 加密函数，data消息(bytes)
>     # msg = data.hex()  # 消息转化为16进制字符串
>     msg = binascii.hexlify(data)
>     k = int(k.hex(), 16)
>     pk = hex2point(pk)
> ```
>
> ```python
> def decrypt(sk, data, mode='C1C3C2'):
>     # 解密函数，data密文（bytes）
>     # data = data.hex()
>     data = binascii.hexlify(data)
>     len_2 = 128
>     len_3 = len_2 + 64
>     C1 = data[0:len_2]
> ```
>
> 
>
> 将上述位置的代码重构后build_ext，在python3.8环境下运行test_gm.py中的测试函数`test_sm2()`、`test_sm2_generate_key()`、`test_sm3()`均通过，python命令行手动测试可以正常加解密。



#### python2兼容性调整 3:

```python
rcnt = ceil(klen/32)

for i in range(rcnt):
```

> 问题描述：
>
> python2中`math.ceil()`方法返回的是浮点类型，python3中则是返回整型，而无论是python2还是python3的`range()`方法都只接受整型参数，从而导致程序抛出`TypeError`参数类型错误
>
> 相同的问题还有：使用了`round()`方法后使用`range()`



> 该问题出现位置：
>
> in sm3.pyx
>
> ```python
> def kdf(z, klen): # z为16进制表示的比特串（str），klen为密钥长度（单位byte）
>     ...
>     rcnt = ceil(klen/32)
>     ...
>     for i in range(rcnt):
> ```
>
> ```python
> def hash(msg):
>     ...
>     group_count = round(len(msg) / 64)
> 
>     B = []
>     for i in range(0, group_count):
>         B.append(array.array('I', msg[i*64:(i+1)*64]))
> ```



> solution:
>
> 在函数外面套一层`int()`方法
>
> ```python
> rcnt = ceil(klen/32)
> ```
>
> 改为：
>
> ```python
> rcnt = int(ceil(klen/32))
> ```
>
> 小问题，做个简单的类型转换就可以了
>
> 
>
> 将上述位置的代码重构后build_ext，在python3.8环境下运行test_gm.py中的测试函数`test_sm2()`、`test_sm2_generate_key()`、`test_sm3()`均通过，python命令行手动测试可以正常加解密。
>
> 在python2.7环境中有待检验（因为还有其他兼容性问题导致报错）



#### python2兼容性调整 4:

> 一上来就从sm2的兼容性入手真的太蠢了，sm2里使用了kdf，而kdf又关系到sm3，不如追根溯源先把sm3的兼容性搞定，反正sm3没有使用其他模块的东西，不用东改一点西改一点，所以现在开始改变工作方针。

```python
def hash(msg):
    """
    msg: bytes
    return: sm3 hash bytes
    """
    msg = list(msg)
    len1 = len(msg)
```

> 问题描述：
>
> 在python2.7环境下测试`test_sm3()`的时候抛出了类型错误，提示信息是`an integer is required`
>
> 浏览了一下源码，最后将问题定位在`hash()`方法第一行的`list()`上
>
> 从注释提示得知传入的msg应该是bytes型，但是在python2中bytes和str是一样的，当`list()`作用于msg上时，生成的是字符列表，而在python3中，由于str和bytes分家，`list()`作用于bytes类型上时，返回的是由每个字节的ascii码组成的列表，列表里面每一项都是一个整型数字，也就是说接下来在`hash()`函数里的所有对msg列表的操作，其实是对整数的操作。



> 解决方法：对列表化后的msg中的项进行类型判断，如果是字符型，则多加一步将其转换成整型（小心传入空字符串的情况，会造成下标溢出）
>
> ```python
> msg = list(msg)
> if msg != []:
>  if type(msg[0]) == str:
>      for i in range(len(msg)):
>          msg[i] = ord(msg[i])
> 
> len1 = len(msg)
> ```
>
> 
>
> 将上述代码重构后build_ext，在python3.8环境下运行test_gm.py中的测试函数`test_sm3()`通过，python3命令行手动测试可以正常对消息进行杂凑。
>
> 在python2.7环境下运行test_gm.py中的测试函数`test_sm3()`出错，原因是gmssl版本过高不支持python2.7，fastgm本身的hash运算是可以成功运行的。python2.7命令行手动测试可以正常对消息进行杂凑。
>
> 修改了一下`test_sm3()`把杂凑值打印到stdout，手动比较python2.7下打印出来的结果和在python3下打印出来的结果，测试通过，如果有更好的测试方法请提出。



#### python2兼容性调整 5:

> 运行SM2加密时报错，`kdf()`返回值为空，导致后续运行出错。
>
> 进一步调试发现`rcnt`变量值为0，`kdf()`中的for循环一次都没有进行，所以返回值为空。
>
> 进一步寻找问题所在，发现问题出在以下语句：
>
> ```python
> def kdf(z, klen): # z为16进制表示的比特串（str），klen为密钥长度（单位byte）
>     ...
>     rcnt = ceil(klen/32)
> ```
>
> 在python2中，如果除法两边的类型都为整型，结果将不会保留小数，而是向下取整，当变量`klen`小于32时，`klen/32`的结果就是0，之后`ceil()`的返回值也是0
>
> 而在python3中，整数除法结果为小数时都会返回浮点数



>solution:
>
>只要把语句改成：
>
>```python
>rcnt = ceil(klen/32.0)
>```
>
>即可。
>
>在python2中，只要除法两边有其中一个操作数为浮点数，结果就会保留小数点
>
>
>
>将上述代码重构后build_ext，在python3.8环境下运行test_gm.py中的测试函数`test_sm2()`，`test_sm2_generate_key()`通过。命令行手动测试可以正常加解密。
>
>在python2.7环境中运行test_gm.py中的测试函数`test_sm2()`，`test_sm2_generate_key()`通过。命令行手动测试可以正常加解密。



#### 至此，对于fastgm的python2.7兼容工作告一段落
