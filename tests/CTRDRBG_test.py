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
        '''Test aes128-ctr-drbg with derivation function'''
        drbg = CTRDRBG(AES, 16)
        entropy_input = b'\x0f\x65\xda\x13\xdc\xa4\x07\x99\x9d\x47\x73\xc2\xb4\xa1\x1d\x85'
        nonce = b'\x52\x09\xe5\xb4\xed\x82\xa2\x34'
        personalization_string = b''
        additional_input = b''
        
        drbg._CTRDRBG__Instantiate(entropy_input, nonce, personalization_string)
        self.assertEqual(b'\x0c\x42\xea\x68\x04\x30\x39\x54\xde\xb1\x97\xa0\x7e\x6d\xbd\xd2', drbg._CTRDRBG__key)
        self.assertEqual(b'\x80\x94\x16\x80\x71\x3d\xf7\x15\x05\x6f\xb2\xa3\xd2\xe9\x98\xb2', drbg._CTRDRBG__V)
        
        entropy_input = b'\x1d\xea\x0a\x12\xc5\x2b\xf6\x43\x39\xdd\x29\x1c\x80\xd8\xca\x89'
        
        drbg._CTRDRBG__Reseed(entropy_input, additional_input)
        self.assertEqual(b'\x32\xfb\xfd\x01\x09\xf3\x64\xed\x21\xef\x21\xa6\xe5\xc7\x63\xe7', drbg._CTRDRBG__key)
        self.assertEqual(b'\xf2\xba\xcb\xb2\x33\x25\x2f\xba\x35\xfb\x05\x82\xf9\x28\x61\x79', drbg._CTRDRBG__V)
        
        drbg._CTRDRBG__Generate(64, additional_input)
        self.assertEqual(b'\x75\x7c\x8e\xb7\x66\xf9\xaa\xa4\x65\x0d\x65\x00\xb5\x86\x24\xa3', drbg._CTRDRBG__key)
        self.assertEqual(b'\x99\x00\x3d\x63\x0b\xba\x50\x0f\xe1\x7c\x37\xf8\xc7\x33\x1b\xf6', drbg._CTRDRBG__V)
        
        returned_bits = drbg._CTRDRBG__Generate(64, additional_input)
        expected = (b'\x28\x59\xcc\x46\x8a\x76\xb0\x86\x61\xff\xd2\x3b\x28\x54\x7f\xfd\x09\x97\xad\x52\x6a\x0f' +
                    b'\x51\x26\x1b\x99\xed\x3a\x37\xbd\x40\x7b\xf4\x18\xdb\xe6\xc6\xc3\xe2\x6e\xd0\xdd\xef\xcb' +
                    b'\x74\x74\xd8\x99\xbd\x99\xf3\x65\x54\x27\x51\x9f\xc5\xb4\x05\x7b\xca\xf3\x06\xd4')
        self.assertEqual(returned_bits, expected)
        self.assertEqual(b'\xe4\x21\xff\x24\x45\xe0\x49\x92\xfa\xf3\x6c\xf9\xa5\xea\xf1\xf9', drbg._CTRDRBG__key)
        self.assertEqual(b'\x59\x07\xab\x44\x7a\x88\xe5\x10\x67\x53\x50\x7c\xc9\x7e\x0f\xd5', drbg._CTRDRBG__V)


if __name__ == "__main__":
    unittest.main()