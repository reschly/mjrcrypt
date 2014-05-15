'''Unit tests for Random'''

import sys
sys.path.append("..")
import unittest
from MJRRandom import Random
from MJRCipher import AES


class Random_test(unittest.TestCase):
    '''TestCase for Random'''
    
    def test_nocrash(self):
        '''Just make sure it doesn't crash or throw an exception
        CTRDRBG tests takes care of KATs'''
        
        drbg = Random()
        drbg.get_bytes(1)
        drbg.get_bytes(1024)
        drbg.get_bytes(4096)
        drbg = Random(bytes([i for i in range(128)]))
        drbg.get_bytes(1)
        drbg.get_bytes(1024)
        drbg.get_bytes(4096)
        drbg = Random(bytes([i for i in range(128)]), keysize=24)
        drbg.get_bytes(1)
        drbg.get_bytes(1024)
        drbg.get_bytes(4096)
        drbg = Random(keysize=16)
        drbg.get_bytes(1)
        drbg.get_bytes(1024)
        drbg.get_bytes(4096)
        drbg = Random(keysize=32, cipher=AES)
        drbg.get_bytes(1)
        drbg.get_bytes(1024)
        drbg.get_bytes(4096)
        
if __name__ == "__main__":
    unittest.main()