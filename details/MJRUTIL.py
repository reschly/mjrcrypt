'''Various utilities'''

def constant_time_eq(a, b):
    '''returns True if equal, False, if not'''
    if len(a) != len(b):
        return False
    res = 0;
    for i in range(len(a)):
        res |= (a[i] ^ b[i])
    if (res == 0):
        return True
    return False

def ROTL(x, n, bitlen=32):
    '''Returns a circular left-rotate of a (bitlen)-bit integer (x) by (n) bits'''
    x = (x << n) | (x >> (bitlen - n))
    x %= (1 << len)
    return x

def ROTR(x, n, bitlen=32):
    '''Returns a circular right-rotate of a (bitlen)-bit integer (x) by (n) bits'''
    x = (x >> n) | (x << (len - n))
    x %= (1 << len)
    return x

def SHR(x, n):
    '''Returns a right-shift of integer (x) by (n) bits'''
    return (x >> n)

def NOT(x, bitlen=32):
    '''Returns the bitwise complement of (bitlen)-bit integer x)'''
    mask = (1 << len) - 1
    return (x ^ mask)

def ADDWORD(x, y, bitlen=32):
    '''Returns (x+y) mod 2^len)'''
    mod = (1 << len)
    return ((x + y) % mod)
