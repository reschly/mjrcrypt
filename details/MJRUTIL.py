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
    x %= (1 << bitlen)
    return x

def ROTR(x, n, bitlen=32):
    '''Returns a circular right-rotate of a (bitlen)-bit integer (x) by (n) bits'''
    x = (x >> n) | (x << (len - n))
    x %= (1 << bitlen)
    return x

def SHR(x, n):
    '''Returns a right-shift of integer (x) by (n) bits'''
    return (x >> n)

def NOT(x, bitlen=32):
    '''Returns the bitwise complement of (bitlen)-bit integer x)'''
    mask = (1 << bitlen) - 1
    return (x ^ mask)

def CHOOSE(x, y, z, bitlen=32):
    '''FIPS 180-4, Section 4.1.2/4.1.3'''
    return (x & y) ^ (NOT(x, bitlen) & z)
    
def MAJORITY(x, y, z):
    '''FIPS 180-4, Section 4.1.2/4.1.3'''
    return (x & y) ^ (x & z) ^ (y & z)

def ADDWORD(x, y, bitlen=32):
    '''Returns (x+y) mod 2^len)'''
    mod = (1 << bitlen)
    return ((x + y) % mod)



def CHUNKS(arr, size):
    if size < 1:
        size = 1
    return [arr[i:i + size] for i in range(0, len(arr), size)]