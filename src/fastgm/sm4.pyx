import os

from cpython cimport array
import array
import cython


@cython.boundscheck(False) # turn off bounds-checking for entire function
@cython.wraparound(False)  # turn off negative index wrapping for entire function        
cdef int SM4_GETU32(const unsigned char[:] data, unsigned long offset):
    return ((data[offset] << 24)
            | (data[offset + 1] << 16)
            | (data[offset + 2] << 8)
            | data[offset + 3])

@cython.boundscheck(False) # turn off bounds-checking for entire function
@cython.wraparound(False)  # turn off negative index wrapping for entire function    
cdef void SM4_PUTU32(unsigned char[:] data, unsigned long offset, unsigned int value):
    data[offset + 3] = (value & 0xff)
    value >>= 8
    data[offset + 2] = (value & 0xff)
    value >>= 8
    data[offset + 1] = (value & 0xff)
    value >>= 8
    data[offset] = (value & 0xff)
    
cdef unsigned int SM4_KEY_LENGTH = 16
cdef unsigned int SM4_BLOCK_SIZE = 16
cdef unsigned int SM4_IV_LENGTH = SM4_BLOCK_SIZE
cdef unsigned int SM4_NUM_ROUNDS = 32

cdef unsigned int* SM4_S = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
    0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
    0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
    0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95,
    0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
    0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
    0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
    0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
    0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
    0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
    0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
    0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
    0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
    0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
    0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e,
    0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
    0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
]

cdef unsigned int* SM4_FK = [
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc,
]

cdef unsigned int* SM4_CK = [
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
]

cdef unsigned int SM4_ROL32(unsigned int x, unsigned int n):
    return ((x << n) | (x >> (32 - n)))

cdef unsigned int SM4_S32(unsigned int A):
    return (
        (SM4_S[A >> 24] << 24) ^
        (SM4_S[(A >> 16) & 0xff] << 16) ^
        (SM4_S[(A >> 8) & 0xff] << 8) ^
        (SM4_S[A & 0xff]))

cdef unsigned int SM4_L32(unsigned int x):
    return (
        x ^
        SM4_ROL32(x, 2) ^
        SM4_ROL32(x, 10) ^
        SM4_ROL32(x, 18) ^
        SM4_ROL32(x, 24))

cdef unsigned int SM4_L32_(unsigned int x):
    return (
        x ^
        SM4_ROL32(x, 13) ^
        SM4_ROL32(x, 23))

@cython.boundscheck(False) # turn off bounds-checking for entire function
@cython.wraparound(False)  # turn off negative index wrapping for entire function
cdef void sm4_set_encrypt_key(unsigned int[:] key, const unsigned char[:] user_key):
    cdef unsigned int x0, x1, x2, x3, x4
    x0 = SM4_GETU32(user_key,  0) ^ SM4_FK[0]
    x1 = SM4_GETU32(user_key,  4) ^ SM4_FK[1]
    x2 = SM4_GETU32(user_key,  8) ^ SM4_FK[2]
    x3 = SM4_GETU32(user_key, 12) ^ SM4_FK[3]
    key[ 0] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[ 0])))
    key[ 1] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[ 1])))
    key[ 2] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[ 2])))
    key[ 3] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[ 3])))
    key[ 4] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[ 4])))
    key[ 5] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[ 5])))
    key[ 6] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[ 6])))
    key[ 7] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[ 7])))
    key[ 8] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[ 8])))
    key[ 9] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[ 9])))
    key[10] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[10])))
    key[11] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[11])))
    key[12] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[12])))
    key[13] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[13])))
    key[14] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[14])))
    key[15] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[15])))
    key[16] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[16])))
    key[17] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[17])))
    key[18] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[18])))
    key[19] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[19])))
    key[20] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[20])))
    key[21] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[21])))
    key[22] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[22])))
    key[23] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[23])))
    key[24] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[24])))
    key[25] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[25])))
    key[26] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[26])))
    key[27] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[27])))
    key[28] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[28])))
    key[29] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[29])))
    key[30] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[30])))
    key[31] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[31])))
    x0 = x1 = x3 = x3 = x4 = 0

@cython.boundscheck(False) # turn off bounds-checking for entire function
@cython.wraparound(False)  # turn off negative index wrapping for entire function
cdef void sm4_set_decrypt_key(unsigned int[:] key, const unsigned char[:] user_key):
    cdef unsigned int x0, x1, x2, x3, x4
    x0 = SM4_GETU32(user_key,  0) ^ SM4_FK[0]
    x1 = SM4_GETU32(user_key,  4) ^ SM4_FK[1]
    x2 = SM4_GETU32(user_key,  8) ^ SM4_FK[2]
    x3 = SM4_GETU32(user_key, 12) ^ SM4_FK[3]
    key[31] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[ 0])))
    key[30] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[ 1])))
    key[29] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[ 2])))
    key[28] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[ 3])))
    key[27] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[ 4])))
    key[26] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[ 5])))
    key[25] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[ 6])))
    key[24] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[ 7])))
    key[23] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[ 8])))
    key[22] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[ 9])))
    key[21] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[10])))
    key[20] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[11])))
    key[19] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[12])))
    key[18] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[13])))
    key[17] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[14])))
    key[16] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[15])))
    key[15] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[16])))
    key[14] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[17])))
    key[13] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[18])))
    key[12] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[19])))
    key[11] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[20])))
    key[10] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[21])))
    key[ 9] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[22])))
    key[ 8] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[23])))
    key[ 7] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[24])))
    key[ 6] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[25])))
    key[ 5] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[26])))
    key[ 4] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[27])))
    key[ 3] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[28])))
    key[ 2] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[29])))
    key[ 1] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[30])))
    key[ 0] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[31])))
    x0 = x1 = x3 = x3 = x4 = 0

@cython.boundscheck(False) # turn off bounds-checking for entire function
@cython.wraparound(False)  # turn off negative index wrapping for entire function
cdef void sm4_encrypt(const unsigned char[:] inbuf, unsigned long in_offset, 
                unsigned char[:] outbuf, unsigned long out_offset, 
                unsigned int[:] key):
    cdef unsigned int x0, x1, x2, x3, x4
    x0 = SM4_GETU32(inbuf, in_offset)
    x1 = SM4_GETU32(inbuf, in_offset + 4)
    x2 = SM4_GETU32(inbuf, in_offset + 8)
    x3 = SM4_GETU32(inbuf, in_offset + 12)
    x4 = x0 ^ SM4_L32(SM4_S32(x1 ^ x2 ^ x3 ^ key[0]))
    x0 = x1 ^ SM4_L32(SM4_S32(x2 ^ x3 ^ x4 ^ key[1]))
    x1 = x2 ^ SM4_L32(SM4_S32(x3 ^ x4 ^ x0 ^ key[2]))
    x2 = x3 ^ SM4_L32(SM4_S32(x4 ^ x0 ^ x1 ^ key[3]))
    x3 = x4 ^ SM4_L32(SM4_S32(x0 ^ x1 ^ x2 ^ key[4]))
    x4 = x0 ^ SM4_L32(SM4_S32(x1 ^ x2 ^ x3 ^ key[5]))
    x0 = x1 ^ SM4_L32(SM4_S32(x2 ^ x3 ^ x4 ^ key[6]))
    x1 = x2 ^ SM4_L32(SM4_S32(x3 ^ x4 ^ x0 ^ key[7]))
    x2 = x3 ^ SM4_L32(SM4_S32(x4 ^ x0 ^ x1 ^ key[8]))
    x3 = x4 ^ SM4_L32(SM4_S32(x0 ^ x1 ^ x2 ^ key[9]))
    x4 = x0 ^ SM4_L32(SM4_S32(x1 ^ x2 ^ x3 ^ key[10]))
    x0 = x1 ^ SM4_L32(SM4_S32(x2 ^ x3 ^ x4 ^ key[11]))
    x1 = x2 ^ SM4_L32(SM4_S32(x3 ^ x4 ^ x0 ^ key[12]))
    x2 = x3 ^ SM4_L32(SM4_S32(x4 ^ x0 ^ x1 ^ key[13]))
    x3 = x4 ^ SM4_L32(SM4_S32(x0 ^ x1 ^ x2 ^ key[14]))
    x4 = x0 ^ SM4_L32(SM4_S32(x1 ^ x2 ^ x3 ^ key[15]))
    x0 = x1 ^ SM4_L32(SM4_S32(x2 ^ x3 ^ x4 ^ key[16]))
    x1 = x2 ^ SM4_L32(SM4_S32(x3 ^ x4 ^ x0 ^ key[17]))
    x2 = x3 ^ SM4_L32(SM4_S32(x4 ^ x0 ^ x1 ^ key[18]))
    x3 = x4 ^ SM4_L32(SM4_S32(x0 ^ x1 ^ x2 ^ key[19]))
    x4 = x0 ^ SM4_L32(SM4_S32(x1 ^ x2 ^ x3 ^ key[20]))
    x0 = x1 ^ SM4_L32(SM4_S32(x2 ^ x3 ^ x4 ^ key[21]))
    x1 = x2 ^ SM4_L32(SM4_S32(x3 ^ x4 ^ x0 ^ key[22]))
    x2 = x3 ^ SM4_L32(SM4_S32(x4 ^ x0 ^ x1 ^ key[23]))
    x3 = x4 ^ SM4_L32(SM4_S32(x0 ^ x1 ^ x2 ^ key[24]))
    x4 = x0 ^ SM4_L32(SM4_S32(x1 ^ x2 ^ x3 ^ key[25]))
    x0 = x1 ^ SM4_L32(SM4_S32(x2 ^ x3 ^ x4 ^ key[26]))
    x1 = x2 ^ SM4_L32(SM4_S32(x3 ^ x4 ^ x0 ^ key[27]))
    x2 = x3 ^ SM4_L32(SM4_S32(x4 ^ x0 ^ x1 ^ key[28]))
    x3 = x4 ^ SM4_L32(SM4_S32(x0 ^ x1 ^ x2 ^ key[29]))
    x4 = x0 ^ SM4_L32(SM4_S32(x1 ^ x2 ^ x3 ^ key[30]))
    x0 = x1 ^ SM4_L32(SM4_S32(x2 ^ x3 ^ x4 ^ key[31]))
    SM4_PUTU32(outbuf, out_offset, x0)
    SM4_PUTU32(outbuf, out_offset + 4, x4)
    SM4_PUTU32(outbuf, out_offset + 8, x3)
    SM4_PUTU32(outbuf, out_offset + 12, x2)

cdef void sm4_decrypt(const unsigned char[:] inbuf, unsigned long in_offset, 
                unsigned char[:] outbuf, unsigned long out_offset, 
                unsigned int[:] key):
    sm4_encrypt(inbuf, in_offset, outbuf, out_offset, key)

cdef void sm4_encrypt_ecb(const unsigned char[:] inbuf,
                    unsigned char[:] outbuf,
                    unsigned int[:] key):
    
    cdef unsigned long buf_len = len(inbuf)
    assert buf_len >= 16 and buf_len % 16 == 0 and buf_len == len(outbuf)
    
    for i in range(0, buf_len, 16):
        sm4_encrypt(inbuf, i, outbuf, i, key)
        
cdef void sm4_decrypt_ecb(const unsigned char[:] inbuf,
                    unsigned char[:] outbuf,
                    unsigned int[:] key):
    
    cdef unsigned long buf_len = len(inbuf)
    assert buf_len >= 16 and buf_len % 16 == 0 and buf_len == len(outbuf)
    
    for i in range(0, buf_len, 16):
        sm4_decrypt(inbuf, i, outbuf, i, key)
        
        
def sm4_key_new():
    return array.array('I', [0] * SM4_NUM_ROUNDS)


def zero_pad(data):
    buf_len = len(data)
    
    if buf_len % 16 == 0:
        return data
    else:
        new_len = (buf_len // 16 + 1) * 16
        return data + b'\0' * (new_len - buf_len)

class SM4:
    def __init__(self, key):
        assert len(key) == 16
        self._raw_key = key
        self._enc_key = None
        self._dec_key = None

    @classmethod
    def generate_key(cls):
        return os.urandom(16)
        
    def encrypt_ecb(self, message):
        if self._enc_key is None:
            self._enc_key = sm4_key_new()
            sm4_set_encrypt_key(self._enc_key, self._raw_key)
        
        message = zero_pad(message)
        buf = array.array('B', b'\0' * len(message))
        
        sm4_encrypt_ecb(message, buf, self._enc_key)
        
        return buf.tobytes().rstrip(b'\0')
    
    def decrypt_ecb(self, message):
        if self._dec_key is None:
            self._dec_key = sm4_key_new()
            sm4_set_decrypt_key(self._dec_key, self._raw_key)
        
        message = zero_pad(message)
        buf = array.array('B', b'\0' * len(message))
        
        sm4_decrypt_ecb(message, buf, self._dec_key)
        
        return buf.tobytes().rstrip(b'\0')