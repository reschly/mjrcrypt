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