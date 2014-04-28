'''My SHA (256, 384, 512) module.'''

from details.MJRUTIL import ROTR, ROTL, SHR, NOT, ADDWORD


class SHA(object):
    '''
    An implementation of SHA-256, 384, 512 from FIPS 180-4
    '''
    
    @staticmethod
    def ch(x, y, z, bitlen=32):
        '''FIPS 180-4, Section 4.1.2/4.1.3'''
        return (x & y) ^ (NOT(x, bitlen) & z)
    
    @staticmethod
    def maj(x, y, z):
        '''FIPS 180-4, Section 4.1.2/4.1.3'''
        return (x & y) ^ (x & z) ^ (y & z)
    
    @staticmethod
    def bigsigma0_256(x):
        '''FIPS 180-4, Section 4.1.2'''
        return ROTR(x, 2, bitlen=32) ^ ROTR(x, 13, bitlen=32) ^ ROTR(x, 22, bitlen=32)
    
    @staticmethod
    def bigsigma1_256(x):
        '''FIPS 180-4, Section 4.1.2'''
        return ROTR(x, 6, bitlen=32) ^ ROTR(x, 11, bitlen=32) ^ ROTR(x, 25, bitlen=32)
    
    @staticmethod
    def littlesigma0_256(x):
        '''FIPS 180-4, Section 4.1.2'''
        return ROTR(x, 7, bitlen=32) ^ ROTR(x, 18, bitlen=32) ^ SHR(x, 3, bitlen=32)
    
    @staticmethod
    def littlesigma1_256(x):
        '''FIPS 180-4, Section 4.1.2'''
        return ROTR(x, 17, bitlen=32) ^ ROTR(x, 19, bitlen=32) ^ SHR(x, 10, bitlen=32)
    
    @staticmethod
    def bigsigma0_512(x):
        '''FIPS 180-4, Section 4.1.2'''
        return ROTR(x, 28, bitlen=64) ^ ROTR(x, 34, bitlen=64) ^ ROTR(x, 39, bitlen=64)
    
    @staticmethod
    def bigsigma1_512(x):
        '''FIPS 180-4, Section 4.1.2'''
        return ROTR(x, 14, bitlen=64) ^ ROTR(x, 18, bitlen=64) ^ ROTR(x, 41, bitlen=64)
    
    @staticmethod
    def littlesigma0_512(x):
        '''FIPS 180-4, Section 4.1.2'''
        return ROTR(x, 1, bitlen=64) ^ ROTR(x, 8, bitlen=64) ^ SHR(x, 7)
    
    @staticmethod
    def littlesigma1_512(x):
        '''FIPS 180-4, Section 4.1.2'''
        return ROTR(x, 19, bitlen=64) ^ ROTR(x, 61, bitlen=64) ^ SHR(x, 6)    