# coding=utf-8
import binascii
from math import ceil
from cpython cimport array
import array

# rotl = lambda x, n:((x << n) & 0xffffffff) | ((x >> (32 - n)) & 0xffffffff)
bytes_to_list = lambda data: [i for i in data]


cdef unsigned int[:] IV = array.array('I', [
    1937774191, 1226093241, 388252375, 3666478592,
    2842636476, 372324522, 3817729613, 2969243214,
])

cdef unsigned int[:] T_j = array.array('I', [
    2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169,
    2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169,
    2043430169, 2043430169, 2043430169, 2043430169, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042
])

cdef unsigned int rotl(unsigned int x, unsigned int n):
    return ((x << n)) | ((x >> (32 - n)))

cdef unsigned int sm3_ff_j(unsigned int x, unsigned int y, 
                           unsigned int z, unsigned int j):
    if 0 <= j and j < 16:
        ret = x ^ y ^ z
    elif 16 <= j and j < 64:
        ret = (x & y) | (x & z) | (y & z)
    return ret

cdef unsigned int sm3_gg_j(unsigned int x, unsigned int y, 
                          unsigned int z, unsigned int j):
    if 0 <= j and j < 16:
        ret = x ^ y ^ z
    elif 16 <= j and j < 64:
        #ret = (X | Y) & ((2 ** 32 - 1 - X) | Z)
        ret = (x & y) | ((~ x) & z)
    return ret

cdef unsigned int sm3_p_0(unsigned int x):
    return x ^ (rotl(x, 9 % 32)) ^ (rotl(x, 17 % 32))

cdef unsigned int sm3_p_1(unsigned int x):
    return x ^ (rotl(x, 15 % 32)) ^ (rotl(x, 23 % 32))

cdef void sm3_cf(unsigned int[:] v_j, unsigned int[:] v_i, unsigned int[:] b_i):
    cdef unsigned int w[68]
    cdef int weight, data
    cdef unsigned long i, j
    
    for i in range(68):
        w[i] = 0
    
    for i in range(16):
        weight = 0x1000000
        data = 0
        for k in range(i*4,(i+1)*4):
            data = data + b_i[k]*weight
            weight = weight//0x100
        w[i] = data

    for j in range(16, 68):
        w[j] = sm3_p_1(w[j-16] ^ w[j-9] ^ (rotl(w[j-3], 15 % 32))) ^ (rotl(w[j-13], 7 % 32)) ^ w[j-6]
#         str1 = "%08x" % w[j]
    
    cdef unsigned int w_1[64]
    
    for i in range(64):
        w_1[i] = 0
    
    for j in range(0, 64):
        w_1[j] = w[j] ^ w[j+4]
#         str1 = "%08x" % w_1[j]

#     a, b, c, d, e, f, g, h = v_i
    cdef unsigned int a, b, c, d, e, f, g, h
    a = v_i[0]
    b = v_i[1]
    c = v_i[2]
    d = v_i[3]
    e = v_i[4]
    f = v_i[5]
    g = v_i[6]
    h = v_i[7]
    
    cdef unsigned int ss_1, ss_2, tt_1, tt_2

    for j in range(0, 64):
        ss_1 = rotl(
            ((rotl(a, 12 % 32)) +
            e +
            (rotl(T_j[j], j % 32))),# & 0xffffffff, 
            7 % 32
        )
        ss_2 = ss_1 ^ (rotl(a, 12 % 32))
        tt_1 = (sm3_ff_j(a, b, c, j) + d + ss_2 + w_1[j])# & 0xffffffff
        tt_2 = (sm3_gg_j(e, f, g, j) + h + ss_1 + w[j])# & 0xffffffff
        d = c
        c = rotl(b, 9 % 32)
        b = a
        a = tt_1
        h = g
        g = rotl(f, 19 % 32)
        f = e
        e = sm3_p_0(tt_2)

#         a, b, c, d, e, f, g, h = map(
#             lambda x:x & 0xFFFFFFFF ,[a, b, c, d, e, f, g, h])
#         a = a & 0xFFFFFFFF
#         b = b & 0xFFFFFFFF
#         c = c & 0xFFFFFFFF
#         d = d & 0xFFFFFFFF
#         e = e & 0xFFFFFFFF
#         f = f & 0xFFFFFFFF
#         g = g & 0xFFFFFFFF
#         h = h & 0xFFFFFFFF
    
    v_j[0] = a ^ v_i[0]
    v_j[1] = b ^ v_i[1]
    v_j[2] = c ^ v_i[2]
    v_j[3] = d ^ v_i[3]
    v_j[4] = e ^ v_i[4]
    v_j[5] = f ^ v_i[5]
    v_j[6] = g ^ v_i[6]
    v_j[7] = h ^ v_i[7]

def hash(msg):
    """
    msg: bytes
    return: sm3 hash bytes
    """
    msg = list(msg)
    if msg != []:
        if type(msg[0]) == str:
            for i in range(len(msg)):
                msg[i] = ord(msg[i])
                
    len1 = len(msg)
    reserve1 = len1 % 64
    msg.append(0x80)
    reserve1 = reserve1 + 1
    # 56-64, add 64 byte
    range_end = 56
    if reserve1 > range_end:
        range_end = range_end + 64

    for i in range(reserve1, range_end):
        msg.append(0x00)

    bit_length = (len1) * 8
    bit_length_str = [bit_length % 0x100]
    for i in range(7):
        bit_length = int(bit_length / 0x100)
        bit_length_str.append(bit_length % 0x100)
    for i in range(8):
        msg.append(bit_length_str[7-i])

    group_count = int(round(len(msg) / 64))

    B = []
    for i in range(0, group_count):
        B.append(array.array('I', msg[i*64:(i+1)*64]))

    V = []
    V.append(IV)
    
    for i in range(0, group_count):
#         print(V[i], B[i])
        buf = array.array('I', [0] * 8)
        sm3_cf(buf, V[i], B[i])
        V.append(buf)

    y = V[i+1]
    result = ""
    for i in y:
        result = '%s%08x' % (result, i)
    return result

def kdf(z, klen): # z为16进制表示的比特串（str），klen为密钥长度（单位byte）
    klen = int(klen)
    ct = 0x00000001
    rcnt = int(ceil(klen/32.0))
    zin = binascii.unhexlify(z.decode('utf8'))
    
    ha = ""
    for i in range(rcnt):
        msg = zin  + binascii.unhexlify('%08x' % ct)
        ha = ha + hash(msg)
        ct += 1
    return ha[0: klen * 2]

class SM3:
    def __init__(self):
        pass

    def hash(self, msg):
        """
        msg: bytes
        return: sm3 bytes
        """
        return hash(msg)
