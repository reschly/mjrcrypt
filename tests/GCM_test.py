'''Unit tests for MJRGCM'''

import unittest
from MJRGCM import GCM

class GCM_test(unittest.TestCase):
    '''TestCase for MJRAES'''

    def test_incr32(self):
        '''Tests the __incr32 method'''
        iv0 = bytearray(b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xff\xff\xff\xfd')
        iv1 = bytearray(b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xff\xff\xff\xfe')
        iv2 = bytearray(b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xff\xff\xff\xff')
        iv3 = bytearray(b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x00\x00\x00\x00')
        iv4 = bytearray(b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x00\x00\x00\x01')
        GCM._GCM__incr32(iv0) # @UndefinedVariable
        self.assertEqual(iv0, iv1)
        GCM._GCM__incr32(iv0) # @UndefinedVariable
        self.assertEqual(iv0, iv2)
        GCM._GCM__incr32(iv0) # @UndefinedVariable
        self.assertEqual(iv0, iv3)
        GCM._GCM__incr32(iv0) # @UndefinedVariable
        self.assertEqual(iv0, iv4)
        iv0 = bytearray(b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x43\xff\x39\xfd')
        iv1 = bytearray(b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x43\xff\x39\xfe')
        iv2 = bytearray(b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x43\xff\x39\xff')
        iv3 = bytearray(b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x43\xff\x3a\x00')
        iv4 = bytearray(b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x43\xff\x3a\x01')
        GCM._GCM__incr32(iv0) # @UndefinedVariable
        self.assertEqual(iv0, iv1)
        GCM._GCM__incr32(iv0) # @UndefinedVariable
        self.assertEqual(iv0, iv2)
        GCM._GCM__incr32(iv0) # @UndefinedVariable
        self.assertEqual(iv0, iv3)
        GCM._GCM__incr32(iv0) # @UndefinedVariable
        self.assertEqual(iv0, iv4)
