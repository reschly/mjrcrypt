'''The Random interface for random byte generators'''
from details.MJRCTRDRBG import CTRDRBG
from details.MJRAES import AES
from time import time
from os import urandom
from os import getpid, getppid

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
            seed = Random.__generate_seed(1024)
        
        microseconds = round(time() * 1000000)
        nonce = microseconds.to_bytes(12, byteorder='big')
        personalization = b'MJR CTR-DRBG'
        self.__drbg._Instantiate(seed, nonce, personalization)
        # To detect a later fork
        self.__pid = getpid()
    
    @staticmethod
    def __generate_seed(numbytes):
        '''Generates a default seed
        Uses urandom because otherwise @tqbf will
        complain'''
        return urandom(numbytes)
    
    def get_bytes(self, numbytes):
        if (self.__pid != getpid()):
            # fork() happened -- reseed
            self.__drbg._Reseed(self.__generate_seed(1024), None)
            self.__pid = getpid()
        try:
            rand = self.__drbg._Generate(numbytes, None)
        except AssertionError:
            # resseed required
            self.__drbg._Reseed(self.__generate_seed(1024), None)
            rand = self.__drbg._Generate(numbytes, None)
        return rand