'''Unit tests for Random'''

import sys
import os
import copy
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
        
    def test_forkprotecction(self):
        '''Test fork() protection'''
        seed = os.urandom(128)
        drbg1 = Random(seed=seed, keysize=16, cipher=AES)
        drbg2 = copy.deepcopy(drbg1)
        
        # ensure drbg1 == drbg2
        self.assertEqual(drbg1.get_bytes(16), drbg2.get_bytes(16), "drbgs not identical")

        # "fork" (windows doen'st support os.fork()
        drbg2._Random__pid += 5
        
        # ensure drbg1 != drbg2 after fork
        self.assertNotEqual(drbg1.get_bytes(16), drbg2.get_bytes(16), "drbgs identical after fork")
        
if __name__ == "__main__":
    unittest.main()