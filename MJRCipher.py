'''The Cipher interface for symmetric en/decryption'''
from details.MJRAES import AES
from details.MJRGCM import GCM

class Cipher(object):
    '''The interface for symmetric en/decryption'''
    
    def __init__(self, key, iv=None, cip=AES, mode=GCM):
        '''Constructor
        key = symmetric key
        iv = initial iv (optional, Default= all-0)
        cip = block cipher (Default: AES)
        mode = mode of operation (Default: GCM)
        '''
        self._ae = mode(cip(key))
        if iv is None:
            iv = Cipher.default_iv()
        self._iv = bytearray(iv)
    
    @staticmethod
    def default_iv():
        '''Returns the default iv'''
        return bytearray(b'\x00' * 12)
    
    def _increment_iv(self):
        '''Updates the iv to the next one to be used'''
        for i in range(len(self._iv) - 1, -1, -1):
            self._iv[i] = (self._iv[i] + 1) & 0xff
            if (self._iv[i] != 0):
                break
    
    def encrypt(self, data, aad=b''):
        cipher, tag = self._ae._auth_encrypt(self._iv, data, aad)
        self._increment_iv()
        return cipher + tag

    def decrypt(self, data, aad=b''):
        cipher = data[0:-16]
        tag = data[-16:]
        plain = self._ae._auth_decrypt(self._iv, cipher, aad, tag)
        self._increment_iv()
        return plain
    
    def set_iv(self, iv):
        self._iv = bytearray(iv)
