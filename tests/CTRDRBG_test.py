'''Unit tests for CTRDRBG'''

import sys
sys.path.append("..")
import unittest
from details.MJRCTRDRBG import CTRDRBG
from details.MJRAES import AES
from binascii import unhexlify


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
        entropy_input = b'0f65da13dca407999d4773c2b4a11d85'
        nonce = b'5209e5b4ed82a234'
        personalization_string = b''
        additional_input1 = b''
        additional_input2 = b''
        expected_key1 = b'0c42ea6804303954deb197a07e6dbdd2'
        expected_V1 = b'80941680713df715056fb2a3d2e998b2'
        reseed_entropy = b'1dea0a12c52bf64339dd291c80d8ca89'
        reseed_additional_input = b''
        expected_key2 = b'32fbfd0109f364ed21ef21a6e5c763e7'
        expected_V2 = b'f2bacbb233252fba35fb0582f9286179'
        expected_key3 = b'757c8eb766f9aaa4650d6500b58624a3'
        expected_V3 = b'99003d630bba500fe17c37f8c7331bf6'
        expected_bits = b'2859cc468a76b08661ffd23b28547ffd0997ad526a0f51261b99ed3a37bd407bf418dbe6c6c3e26ed0ddefcb7474d899bd99f3655427519fc5b4057bcaf306d4'
        expected_key4 = b'e421ff2445e04992faf36cf9a5eaf1f9'
        expected_V4 = b'5907ab447a88e5106753507cc97e0fd5'
        
        drbg._CTRDRBG__Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._CTRDRBG__Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._CTRDRBG__Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._CTRDRBG__Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)

        drbg = CTRDRBG(AES, 16)
        entropy_input = b'070d59639873a5452738227b7685d1a9'
        nonce = b'74181f3c22f64920'
        personalization_string = b'4e6179d4c272a14cf13df65ea3a6e50f'
        additional_input1 = b''
        additional_input2 = b''
        expected_key1 = b'32a76abdc2d8fc1143edd742d0fae60a'
        expected_V1 = b'4e8e758d22f36d10e598d4ae68a828b7'
        reseed_entropy = b'4a47c2f38516b46f002e71daed169b5c'
        reseed_additional_input = b''
        expected_key2 = b'ca51adea091be6972644c4aa1be16aca'
        expected_V2 = b'847dcefd0abc31b0f5b0cfa7e377349e'
        expected_key3 = b'1e4bf36111637d53f022f7959fe8c971'
        expected_V3 = b'074e82340d41b6fec662ce9b591f6ccb'
        expected_bits = b'31c99109f8c510133cd396f9bc2c12c07cc1615fa30999afd7f236fd401a8bf23338ee1d035f83b7a253dcee18fca7f2ee96c6c2cd0cff02767069aa69d13be8'
        expected_key4 = b'884d79cf24be82e60dce9bcdf327f207'
        expected_V4 = b'4b45ad20c126e38664e4f34b5a5b0c2e'

        drbg._CTRDRBG__Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._CTRDRBG__Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._CTRDRBG__Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._CTRDRBG__Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)
        
if __name__ == "__main__":
    unittest.main()