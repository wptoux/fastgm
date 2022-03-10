import base64
import warnings
import binascii
from itertools import chain
from six import int2byte, b, text_type, integer_types

_sentry = object()

class FastgmExpectedDer(Exception):
    pass

# sm2 256 curve information
sm256v1 = {
    'ver': 1,
    'cor': 1,
    'p': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF',
    'a': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',
    'b': '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93',
    'n': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',
    'gx':'32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7',
    'gy':'BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0',
    'sm2ecc_oid':[1, 2, 156, 10197, 1, 301],
    'ecpk_oid':[1, 2, 840, 10045, 2, 1],
}

def str_idx_as_int(string, index):
    """Take index'th byte from string, return as integer"""
    val = string[index]
    if isinstance(val, integer_types):
        return val
    return ord(val)

def normalise_bytes(buffer_object):
    """Cast the input into array of bytes."""
    return memoryview(buffer_object).cast("B")

def read_length(string):
    if not string:
        raise FastgmExpectedDer("Empty string can't encode valid length value")
    num = str_idx_as_int(string, 0)
    if not (num & 0x80):
        # short form
        return (num & 0x7F), 1
    # else long-form: b0&0x7f is number of additional base256 length bytes,
    # big-endian
    llen = num & 0x7F
    if not llen:
        raise FastgmExpectedDer("Invalid length encoding, length of length is 0")
    if llen > len(string) - 1:
        raise FastgmExpectedDer("Length of length longer than provided buffer")
    # verify that the encoding is minimal possible (DER requirement)
    msb = str_idx_as_int(string, 1)
    if not msb or llen == 1 and msb < 0x80:
        raise FastgmExpectedDer("Not minimal encoding of length")
    return int(binascii.hexlify(string[1 : 1 + llen]), 16), 1 + llen

def remove_sequence(string):
    if not string:
        raise FastgmExpectedDer("Empty string does not encode a sequence")
    if string[:1] != b"\x30":
        n = str_idx_as_int(string, 0)
        raise FastgmExpectedDer("wanted type 'sequence' (0x30), got 0x%02x" % n)
    length, lengthlength = read_length(string[1:])
    if length > len(string) - 1 - lengthlength:
        raise FastgmExpectedDer("Length longer than the provided buffer")
    endseq = 1 + lengthlength + length
    return string[1 + lengthlength : endseq], string[endseq:]

def remove_bitstring(string, expect_unused=_sentry):
    if not string:
        raise FastgmExpectedDer("Empty string does not encode a bitstring")
    if expect_unused is _sentry:
        warnings.warn(
            "Legacy call convention used, expect_unused= needs to be"
            " specified",
            DeprecationWarning,
        )
    num = str_idx_as_int(string, 0)
    if string[:1] != b"\x03":
        raise FastgmExpectedDer("wanted bitstring (0x03), got 0x%02x" % num)
    length, llen = read_length(string[1:])
    if not length:
        raise FastgmExpectedDer("Invalid length of bit string, can't be 0")
    body = string[1 + llen : 1 + llen + length]
    rest = string[1 + llen + length :]
    if expect_unused is not _sentry:
        unused = str_idx_as_int(body, 0)
        if not 0 <= unused <= 7:
            raise FastgmExpectedDer("Invalid encoding of unused bits")
        if expect_unused is not None and expect_unused != unused:
            raise FastgmExpectedDer("Unexpected number of unused bits")
        body = body[1:]
        if unused:
            if not body:
                raise FastgmExpectedDer("Invalid encoding of empty bit string")
            last = str_idx_as_int(body, -1)
            # verify that all the unused bits are set to zero (DER requirement)
            if last & (2 ** unused - 1):
                raise FastgmExpectedDer("Non zero padding bits in bit string")
        if expect_unused is None:
            body = (body, unused)
    return body, rest

def remove_integer(string):
    if not string:
        raise FastgmExpectedDer(
            "Empty string is an invalid encoding of an integer"
        )
    if string[:1] != b"\x02":
        n = str_idx_as_int(string, 0)
        raise FastgmExpectedDer("wanted type 'integer' (0x02), got 0x%02x" % n)
    length, llen = read_length(string[1:])
    if length > len(string) - 1 - llen:
        raise FastgmExpectedDer("Length longer than provided buffer")
    if length == 0:
        raise FastgmExpectedDer("0-byte long encoding of integer")
    numberbytes = string[1 + llen : 1 + llen + length]
    rest = string[1 + llen + length :]
    msb = str_idx_as_int(numberbytes, 0)
    if not msb < 0x80:
        raise FastgmExpectedDer("Negative integers are not supported")
    # check if the encoding is the minimal one (DER requirement)
    if length > 1 and not msb:
        # leading zero byte is allowed if the integer would have been
        # considered a negative number otherwise
        smsb = str_idx_as_int(numberbytes, 1)
        if smsb < 0x80:
            raise FastgmExpectedDer(
                "Invalid encoding of integer, unnecessary "
                "zero padding bytes"
            )
    return int(binascii.hexlify(numberbytes), 16), rest

def remove_octet_string(string):
    if string[:1] != b"\x04":
        n = str_idx_as_int(string, 0)
        raise FastgmExpectedDer("wanted type 'octetstring' (0x04), got 0x%02x" % n)
    length, llen = read_length(string[1:])
    body = string[1 + llen : 1 + llen + length]
    rest = string[1 + llen + length :]
    return body, rest

def remove_ctx_t61string(string):
    if not string:
        raise FastgmExpectedDer("Empty string can't encode valid length value")
    tag = str_idx_as_int(string, 0)
    if (tag & 0xF0) != 0xA0:
        raise FastgmExpectedDer("wanted type 'context-specify' (0xA0), got 0x%02x" % tag)
    length, llen = read_length(string[1:])
    if length > len(string) - 1 - llen:
        raise UnexpectedDER("Length longer than the provided buffer")
    endctx = 1 + llen + length
    return string[1 + llen : endctx], string[endctx:]

def encode_length(l):
    assert l >= 0
    if l < 0x80:
        return int2byte(l)
    s = ("%x" % l).encode()
    if len(s) % 2:
        s = b("0") + s
    s = binascii.unhexlify(s)
    llen = len(s)
    return int2byte(0x80 | llen) + s

def encode_number(n):
    b128_digits = []
    while n:
        b128_digits.insert(0, (n & 0x7F) | 0x80)
        n = n >> 7
    if not b128_digits:
        b128_digits.append(0)
    b128_digits[-1] &= 0x7F
    return b("").join([int2byte(d) for d in b128_digits])

def encode_integer(r):
    assert r >= 0  # can't support negative numbers yet
    h = ("%x" % r).encode()
    if len(h) % 2:
        h = b("0") + h
    s = binascii.unhexlify(h)
    num = str_idx_as_int(s, 0)
    if num <= 0x7F:
        return b("\x02") + encode_length(len(s)) + s
    else:
        # DER integers are two's complement, so if the first byte is
        # 0x80-0xff then we need an extra 0x00 byte to prevent it from
        # looking negative.
        return b("\x02") + encode_length(len(s) + 1) + b("\x00") + s

def encode_bitstring(s, unused=_sentry):
    encoded_unused = b""
    len_extra = 0
    if unused is _sentry:
        warnings.warn(
            "Legacy call convention used, unused= needs to be specified",
            DeprecationWarning,
        )
    elif unused is not None:
        if not 0 <= unused <= 7:
            raise ValueError("unused must be integer between 0 and 7")
        if unused:
            if not s:
                raise ValueError("unused is non-zero but s is empty")
            last = str_idx_as_int(s, -1)
            if last & (2 ** unused - 1):
                raise ValueError("unused bits must be zeros in DER")
        encoded_unused = int2byte(unused)
        len_extra = 1
    return b("\x03") + encode_length(len(s) + len_extra) + encoded_unused + s

def encode_octet_string(s):
    return b("\x04") + encode_length(len(s)) + s

def encode_sequence(*encoded_pieces):
    total_len = sum([len(p) for p in encoded_pieces])
    return b("\x30") + encode_length(total_len) + b("").join(encoded_pieces)

def encode_ctx_t61string(string, pos):
    tag = 0xA0 + pos
    return tag.to_bytes(1, 'big') + encode_length(len(string)) + string

def encode_oid(first, second, *pieces):
    assert 0 <= first < 2 and 0 <= second <= 39 or first == 2 and 0 <= second
    body = b"".join(
        chain(
            [encode_number(40 * first + second)],
            (encode_number(p) for p in pieces),
        )
    )
    return b"\x06" + encode_length(len(body)) + body

def unpem(pem):
    if isinstance(pem, text_type):  # pragma: no branch
        pem = pem.encode()

    d = b("").join(
        [
            l.strip()
            for l in pem.split(b("\n"))
            if l and not l.startswith(b("-----"))
        ]
    )
    second = d.find(b'MH', 0)
    if second != -1:
        return base64.b64decode(d[second:])

    return base64.b64decode(d)

def to_pem(der, name):
    b64 = base64.b64encode(der)
    lines = [("-----BEGIN %s-----\n" % name).encode()]
    lines.extend(
        [b64[start : start + 64] + b("\n") for start in range(0, len(b64), 64)]
    )
    lines.append(("-----END %s-----\n" % name).encode())
    return b("").join(lines)

def sm2_pk_from_pem(pem):
    unb64 = unpem(pem)
    string = normalise_bytes(unb64)
    total_seq, empty1 = remove_sequence(string)
    oid_sequence, rest1 = remove_sequence(total_seq)
    pk, rest2 = remove_bitstring(rest1, 0)
    return pk[1:]

def sm2_sk_from_pem(pem):
    unb64 = unpem(pem)
    string = normalise_bytes(unb64)
    total_seq, empty = remove_sequence(string)
    version, ver_rest = remove_integer(total_seq)
    sk, sk_rest = remove_octet_string(ver_rest)
    sm2_ecc_ctx, sm2ecc_rest = remove_ctx_t61string(sk_rest)
    pk_ctx, pk_ctx_rest = remove_ctx_t61string(sm2ecc_rest)
    pk, rest = remove_bitstring(pk_ctx, 0)

    return sk, pk[1:]

def sm2_cur_info_to_der():
    cor_integer = encode_integer(sm256v1['cor'])
    n_integer = encode_integer(int(sm256v1['n'], base=16))
    g_octet_string = encode_octet_string(bytearray.fromhex('04'+sm256v1['gx']+sm256v1['gy']))
    b_octet_string = encode_octet_string(bytearray.fromhex(sm256v1['b']))
    a_octet_string = encode_octet_string(bytearray.fromhex(sm256v1['a']))
    sequence_1 = encode_sequence(a_octet_string, b_octet_string)
    p_integer = encode_integer(int(sm256v1['p'], base=16))
    prime_object_id = encode_oid(sm256v1['prime-oid'][0], sm256v1['prime-oid'][1],\
                               sm256v1['prime-oid'][2], sm256v1['prime-oid'][3],\
                               sm256v1['prime-oid'][4], sm256v1['prime-oid'][5])
    sequence_2 = encode_sequence(prime_object_id, p_integer)
    version_integer = encode_integer(sm256v1['ver'])

    return encode_sequence(version_integer, sequence_2, sequence_1, g_octet_string, n_integer, cor_integer)


def sm2_pk_to_der(pk):
    pk_bitstring = encode_bitstring(b'\04' + pk, 0)
    sm2ecc = encode_oid(sm256v1['sm2ecc_oid'][0], sm256v1['sm2ecc_oid'][1],\
                        sm256v1['sm2ecc_oid'][2], sm256v1['sm2ecc_oid'][3],\
                        sm256v1['sm2ecc_oid'][4], sm256v1['sm2ecc_oid'][5])
    ecpk = encode_oid(sm256v1['ecpk_oid'][0], sm256v1['ecpk_oid'][1],\
                      sm256v1['ecpk_oid'][2], sm256v1['ecpk_oid'][3],\
                      sm256v1['ecpk_oid'][4], sm256v1['ecpk_oid'][5])
    sequence = encode_sequence(ecpk, sm2ecc)
    pk_der = encode_sequence(sequence, pk_bitstring)

    return to_pem(pk_der, 'PUBLIC KEY')

def sm2_sk_to_der(sk, pk):
    # first parameter
    sm2ecc = encode_oid(sm256v1['sm2ecc_oid'][0], sm256v1['sm2ecc_oid'][1],\
                        sm256v1['sm2ecc_oid'][2], sm256v1['sm2ecc_oid'][3],\
                        sm256v1['sm2ecc_oid'][4], sm256v1['sm2ecc_oid'][5])
    # second parameter
    pk_bitstring = encode_bitstring(b'\04' + pk, 0)
    ctx_spec_1 = encode_ctx_t61string(pk_bitstring, 1)
    ctx_spec_2 = encode_ctx_t61string(sm2ecc, 0)
    sk_octet_string = encode_octet_string(sk)
    version_integer = encode_integer(sm256v1['ver'])
    sk_der = encode_sequence(version_integer, sk_octet_string, ctx_spec_2, ctx_spec_1)

    cur_pem = to_pem(sm2ecc, 'EC PARAMETERS')
    sk_pem  = to_pem(sk_der, 'EC PRIVATE KEY')
    return cur_pem + sk_pem





