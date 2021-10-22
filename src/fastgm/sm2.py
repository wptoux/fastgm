import os

from .sm3 import hash, kdf

# 选择素域，设置椭圆曲线参数

N = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', base=16)
P = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF', base=16)
G = (
    int('32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7', base=16),
    int('bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0', base=16),
    1)

A = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC', base=16)
B = int('28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93', base=16)

ECC_A3 = (A + 3) % P

def point2hex(Point):
    x, y, z = Point
    
    if z != 1:
        return '%064x%064x%064x' % (x, y, z)
    else:
        return '%064x%064x' % (x, y)
    
def hex2point(s):
    if len(s) == 128:
        return (
            int(s[:64], base=16),
            int(s[64:], base=16),
            1
        )
    else:
        return (
            int(s[   :  64], base=16),
            int(s[64 : 128], base=16),
            int(s[128: 192], base=16)
        )

def kP(k, Point):  # kP运算
    mask = int('8' + '0' * 63, 16)
    Temp = Point
    flag = False
    for n in range(64 * 4):
        if flag:
            Temp = double_point(Temp)
        if (k & mask) != 0:
            if flag:
                Temp = add_point(Temp, Point)
            else:
                flag = True
                Temp = Point
        k = k << 1
    return convert_jacb_to_nor(Temp)


def double_point(Point):  # 倍点
    """
    Point: (x, y, z)
    
    return double_point
    """
    x1, y1, z1 = Point

    T6 = (z1 * z1) % P
    T2 = (y1 * y1) % P
    T3 = (x1 + T6) % P
    T4 = (x1 - T6) % P
    T1 = (T3 * T4) % P
    T3 = (y1 * z1) % P
    T4 = (T2 * 8) % P
    T5 = (x1 * T4) % P
    T1 = (T1 * 3) % P
    T6 = (T6 * T6) % P
    T6 = (ECC_A3 * T6) % P
    T1 = (T1 + T6) % P
    z3 = (T3 + T3) % P
    T3 = (T1 * T1) % P
    T2 = (T2 * T4) % P
    x3 = (T3 - T5) % P

    if (T5 % 2) == 1:
        T4 = (T5 + ((T5 + P) >> 1) - T3) % P
    else:
        T4 = (T5 + (T5 >> 1) - T3) % P

    T1 = (T1 * T4) % P
    y3 = (T1 - T2) % P

    return x3, y3, z3

def add_point(P1, P2):  # 点加函数，P2点为仿射坐标即z=1，P1为Jacobian加重射影坐标
    """
    P1: (x, y, z)
    P1: (x, y, z)
    
    return add_point
    """
    X1, Y1, Z1 = P1
    x2, y2, z2 = P2

    T1 = (Z1 * Z1) % P
    T2 = (y2 * Z1) % P
    T3 = (x2 * T1) % P
    T1 = (T1 * T2) % P
    T2 = (T3 - X1) % P
    T3 = (T3 + X1) % P
    T4 = (T2 * T2) % P
    T1 = (T1 - Y1) % P
    Z3 = (Z1 * T2) % P
    T2 = (T2 * T4) % P
    T3 = (T3 * T4) % P
    T5 = (T1 * T1) % P
    T4 = (X1 * T4) % P
    X3 = (T5 - T3) % P
    T2 = (Y1 * T2) % P
    T3 = (T4 - X3) % P
    T1 = (T1 * T3) % P
    Y3 = (T1 - T2) % P

    return X3, Y3, Z3

def convert_jacb_to_nor(Point):  # Jacobian加重射影坐标转换成仿射坐标
    """
    Point: (x, y, z)
    
    return double_point
    """
    x, y, z = Point
    z_inv = pow(z, P - 2, P)
    z_invSquar = (z_inv * z_inv) % P
    z_invQube = (z_invSquar * z_inv) % P
    x_new = (x * z_invSquar) % P
    y_new = (y * z_invQube) % P
    z_new = (z * z_inv) % P
    if z_new == 1:
        return x_new, y_new, z_new
    else:
        return None

def encrypt(pk, k, data, mode='C1C3C2'):
    # 加密函数，data消息(bytes)
    msg = data.hex()  # 消息转化为16进制字符串
    k = int(k.hex(), 16)
    pk = hex2point(pk)
    
    C1 = kP(k, G)
    xy = kP(k, pk)
    
    x2, y2, _ = xy
    x2 = '%064x' % x2
    y2 = '%064x' % y2
    
    ml = len(msg)
    t = kdf(point2hex(xy).encode('utf8'), ml/2)
    if int(t, 16) == 0:
        return None
    else:
        form = '%%0%dx' % ml
        
        C1 = point2hex(C1)
        C2 = form % (int(msg, 16) ^ int(t, 16))
        C3 = hash(bytes.fromhex('%s%s%s' % (x2, msg, y2)))
        
        if mode == 'C1C3C2':
            return bytes.fromhex('%s%s%s' % (C1, C3, C2))
        elif mode == 'C1C2C3':
            return bytes.fromhex('%s%s%s' % (C1, C2, C3))
        else:
            return None

def decrypt(sk, data, mode='C1C3C2'):
    # 解密函数，data密文（bytes）
    data = data.hex()
    len_2 = 128
    len_3 = len_2 + 64
    C1 = data[0:len_2]

    if mode == 'C1C3C2':
        C3 = data[len_2:len_3]
        C2 = data[len_3:]
    elif mode == 'C1C2C3':
        C2 = data[len_2:-64]
        C3 = data[-64:]
    else:
        return None
        
    sk = int(sk, 16)
    C1 = hex2point(C1)
    
    xy = kP(sk, C1)
    x2, y2, _ = xy
    x2 = '%064x' % x2
    y2 = '%064x' % y2

    cl = len(C2)
    t = kdf(point2hex(xy).encode('utf8'), cl/2)
    if int(t, 16) == 0:
        return None
    else:
        form = '%%0%dx' % cl
        M = form % (int(C2, 16) ^ int(t, 16))
        u = hash(bytes.fromhex('%s%s%s' % (x2, M, y2)))
        
        if u == C3:
            return bytes.fromhex(M)
        else:
            return None


def generate_key():
    """
    return: sk, pk
    """
    
    k = os.urandom(32)
    k = int(k.hex(), 16)

    pk = kP(k, G)
    
    return ('%064x'% k).upper(), point2hex(pk).upper()


class SM2:
    def __init__(self, mode='C1C3C2'):
        """
        mode: C1C3C2 或 C1C2C3
        """
        
        self._mode = mode

    @classmethod
    def generate_key(cls):
        """
        return: 私钥、公钥组成的tuple
        """
        return generate_key()

    def encrypt(self, pk, data):
        """
        pk: 公钥, hex编码
        data: bytes
        """
        k = os.urandom(32)

        return encrypt(pk, k, data, mode=self._mode)

    def decrypt(self, sk, data):
        """
        sk: 私钥, hex编码
        data: bytes
        """
        return decrypt(sk, data, self._mode)