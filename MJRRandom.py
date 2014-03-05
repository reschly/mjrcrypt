'''The Random interface for random byte generators'''
from details.MJRCTRDRBG import CTRDRBG
from details.MJRAES import AES
from time import time
from os import urandom

class Random(object):
    '''The interface for random byte generator'''
    
    def __init__(self, seed=None, keysize=32, cipher=AES):
        '''Constructor
        seed = seed (will auto-generate if not specified)
        keysize = keysize of underlying block cipher (default = 32 bytes)
        cipher = Class for block cipher (default: AES)
        '''
        self.__drbg = CTRDRBG(cipher, keysize)
        if (seed is None) or (len(seed) == 0):
            seed = Random.__self_seed(1024)
        
        microseconds = round(time() * 1000000)
        nonce = int.to_bytes(12, microseconds, byteorder='big')
        personalization = b'MJR CTR-DRBG'
        self.drbg._CTRDRBG__Instantiate(seed, nonce, personalization)
    
    @staticmethod
    def __self_seed(numbytes):
        '''Generates a default seed
        Uses urandom because otherwise @tqbf will
        complain'''
        return urandom(numbytes)
    
    def get_bytes(self, numbytes):
        try:
            rand = self.drbg._CTRDRBG__Generate(numbytes, None)
        except AssertionError:
            # resseed required
            self._drbg._CTRDRBG__Reseed(self.__self_seed(1024), None)
            rand = self.drbg._CTRDRBG__Generate(numbytes, None)
        return rand