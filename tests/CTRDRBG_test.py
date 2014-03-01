'''Unit tests for CTRDRBG'''

import sys
sys.path.append("..")
import unittest
from details.MJRCTRDRBG import CTRDRBG
from details.MJRAES import AES


class CTRDRBG_test(unittest.TestCase):
    '''TestCase for Cipher'''
    
    def test_array_increment(self):
        '''Unit test for _array_increment'''
        ar0 = bytearray(b'\x01\x02\x03\xff\xfe')
        ar1 = b'\x01\x02\x03\xff\xff'
        ar2 = b'\x01\x02\x04\x00\x00'
        ar3 = b'\x01\x02\x04\x00\x01'
        CTRDRBG._array_increment(ar0)
        self.assertEqual(ar0, ar1)
        CTRDRBG._array_increment(ar0)
        self.assertEqual(ar0, ar2)
        CTRDRBG._array_increment(ar0)
        self.assertEqual(ar0, ar3)
        ar0 = bytearray(b'\xff\xff\xff\xfe')
        ar1 = b'\xff\xff\xff\xff'
        ar2 = b'\x00\x00\x00\x00'
        ar3 = b'\x00\x00\x00\x01'
        CTRDRBG._array_increment(ar0)
        self.assertEqual(ar0, ar1)
        CTRDRBG._array_increment(ar0)
        self.assertEqual(ar0, ar2)
        CTRDRBG._array_increment(ar0)
        self.assertEqual(ar0, ar3)
        
    def test_aes128_df(self):
        drbg = CTRDRBG(AES, 16)
        entropy_input = b'\x0f\x65\xda\x13\xdc\xa4\x07\x99\x9d\x47\x73\xc2\xb4\xa1\x1d\x85'
        nonce = b'\x52\x09\xe5\xb4\xed\x82\xa2\x34'
        personalization_string = b''
        
        drbg._CTRDRBG__Instantiate(entropy_input, nonce, personalization_string)
        self.assertEqual(b'\x0c\x42\xea\x68\x04\x30\x39\x54\xde\xb1\x97\xa0\x7e\x6d\xbd\xd2', drbg._CTRDRBG__key)
        self.assertEqual(b'\x80\x94\x16\x80\x71\x3d\xf7\x15\x05\x6f\xb2\xa3\xd2\xe9\x98\xb2', drbg._CTRDRBG__V)
        



if __name__ == "__main__":
    unittest.main()