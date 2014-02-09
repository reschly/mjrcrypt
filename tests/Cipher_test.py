'''Unit tests for Cipher'''

import sys
sys.path.append("..")
import unittest
from MJRCipher import Cipher


class Cipher_test(unittest.TestCase):
    '''TestCase for Cipher'''
    
    def test_increment_iv(self):
        '''test for _increment_iv'''
        iv = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\xeb\xfe'
        iv1 = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\xeb\xff'
        iv2 = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\xec\x00'
        iv3 = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\xec\x01'
    
        cipher = Cipher(b'\x00' * 16)
        cipher.set_iv(iv)
        cipher._increment_iv()
        self.assertEqual(iv1, cipher._iv)
        cipher._increment_iv()
        self.assertEqual(iv2, cipher._iv)        
        cipher._increment_iv()
        self.assertEqual(iv3, cipher._iv)
        
        iv = b'\xff' * 12
        cipher.set_iv(iv)
        cipher._increment_iv()
        self.assertEqual(b'\x00' * 12, cipher._iv)
        
    def test_encrypt_decrypt(self):
        '''test for encrypt and decrypt.  Test cases from gcm-spec.pdf'''
        # Test Case 1
        cip = Cipher(b'\x00' * 16)
        iv = b'\x00' * 12
        plain = b''
        aad = b''
        expected_cipher = b''
        expected_tag = b'\x58\xe2\xfc\xce\xfa\x7e\x30\x61\x36\x7f\x1d\x57\xa4\xe7\x45\x5a'
        cip.set_iv(iv)
        cipher = cip.encrypt(plain, aad)
        self.assertEqual(cipher, expected_cipher + expected_tag)
        cip.set_iv(iv)
        dec_plain = cip.decrypt(cipher, aad)
        self.assertEqual(dec_plain, plain)
        try:
            cip.decrypt(cipher+iv, aad)
            self.fail("Failed to throw exception on bad tag")
        except ValueError:
            pass
        # Test Case 2
        cip = Cipher(b'\x00' * 16)
        iv = b'\x00' * 12
        plain = b'\x00' * 16
        aad = b''
        expected_cipher = b'\x03\x88\xda\xce\x60\xb6\xa3\x92\xf3\x28\xc2\xb9\x71\xb2\xfe\x78'
        expected_tag = b'\xab\x6e\x47\xd4\x2c\xec\x13\xbd\xf5\x3a\x67\xb2\x12\x57\xbd\xdf'
        cip.set_iv(iv)
        cipher = cip.encrypt(plain, aad)
        self.assertEqual(cipher, expected_cipher + expected_tag)
        cip.set_iv(iv)
        dec_plain = cip.decrypt(cipher, aad)
        self.assertEqual(dec_plain, plain)
        try:
            cip.decrypt(cipher+iv, aad)
            self.fail("Failed to throw exception on bad tag")
        except ValueError:
            pass
        # Test Case 3
        cip = Cipher(b'\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08')
        iv = b'\xca\xfe\xba\xbe\xfa\xce\xdb\xad\xde\xca\xf8\x88'
        plain = (b'\xd9\x31\x32\x25\xf8\x84\x06\xe5\xa5\x59\x09\xc5\xaf\xf5\x26\x9a' +
                 b'\x86\xa7\xa9\x53\x15\x34\xf7\xda\x2e\x4c\x30\x3d\x8a\x31\x8a\x72' +
                 b'\x1c\x3c\x0c\x95\x95\x68\x09\x53\x2f\xcf\x0e\x24\x49\xa6\xb5\x25' +
                 b'\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57\xba\x63\x7b\x39\x1a\xaf\xd2\x55')
        aad = b''
        expected_cipher = (b'\x42\x83\x1e\xc2\x21\x77\x74\x24\x4b\x72\x21\xb7\x84\xd0\xd4\x9c' +
                 b'\xe3\xaa\x21\x2f\x2c\x02\xa4\xe0\x35\xc1\x7e\x23\x29\xac\xa1\x2e' +
                 b'\x21\xd5\x14\xb2\x54\x66\x93\x1c\x7d\x8f\x6a\x5a\xac\x84\xaa\x05' +
                 b'\x1b\xa3\x0b\x39\x6a\x0a\xac\x97\x3d\x58\xe0\x91\x47\x3f\x59\x85')
        expected_tag = b'\x4d\x5c\x2a\xf3\x27\xcd\x64\xa6\x2c\xf3\x5a\xbd\x2b\xa6\xfa\xb4'
        cip.set_iv(iv)
        cipher = cip.encrypt(plain, aad)
        self.assertEqual(cipher, expected_cipher + expected_tag)
        cip.set_iv(iv)
        dec_plain = cip.decrypt(cipher, aad)
        self.assertEqual(dec_plain, plain)
        try:
            cip.decrypt(cipher+iv, aad)
            self.fail("Failed to throw exception on bad tag")
        except ValueError:
            pass
        # Test Case 4
        cip = Cipher(b'\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08')
        iv = b'\xca\xfe\xba\xbe\xfa\xce\xdb\xad\xde\xca\xf8\x88'
        plain = (b'\xd9\x31\x32\x25\xf8\x84\x06\xe5\xa5\x59\x09\xc5\xaf\xf5\x26\x9a' +
                 b'\x86\xa7\xa9\x53\x15\x34\xf7\xda\x2e\x4c\x30\x3d\x8a\x31\x8a\x72' +
                 b'\x1c\x3c\x0c\x95\x95\x68\x09\x53\x2f\xcf\x0e\x24\x49\xa6\xb5\x25' +
                 b'\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57\xba\x63\x7b\x39')
        aad = b'\xfe\xed\xfa\xce\xde\xad\xbe\xef\xfe\xed\xfa\xce\xde\xad\xbe\xef\xab\xad\xda\xd2'
        expected_cipher = (b'\x42\x83\x1e\xc2\x21\x77\x74\x24\x4b\x72\x21\xb7\x84\xd0\xd4\x9c' +
                 b'\xe3\xaa\x21\x2f\x2c\x02\xa4\xe0\x35\xc1\x7e\x23\x29\xac\xa1\x2e' +
                 b'\x21\xd5\x14\xb2\x54\x66\x93\x1c\x7d\x8f\x6a\x5a\xac\x84\xaa\x05' +
                 b'\x1b\xa3\x0b\x39\x6a\x0a\xac\x97\x3d\x58\xe0\x91')
        expected_tag = b'\x5b\xc9\x4f\xbc\x32\x21\xa5\xdb\x94\xfa\xe9\x5a\xe7\x12\x1a\x47'
        cip.set_iv(iv)
        cipher = cip.encrypt(plain, aad)
        self.assertEqual(cipher, expected_cipher + expected_tag)
        cip.set_iv(iv)
        dec_plain = cip.decrypt(cipher, aad)
        self.assertEqual(dec_plain, plain)
        try:
            cip.decrypt(cipher+iv, aad)
            self.fail("Failed to throw exception on bad tag")
        except ValueError:
            pass
        # Test Case 5 skipped: IV of length other than 12 not supported
        # Test Case 6 skipped: IV of length other than 12 not supported
        # Test Case 7:
        cip = Cipher(b'\x00' * 24)
        iv = b'\x00' * 12
        plain = b''
        aad = b''
        expected_cipher = b''
        expected_tag = b'\xcd\x33\xb2\x8a\xc7\x73\xf7\x4b\xa0\x0e\xd1\xf3\x12\x57\x24\x35'
        cip.set_iv(iv)
        cipher = cip.encrypt(plain, aad)
        self.assertEqual(cipher, expected_cipher + expected_tag)
        cip.set_iv(iv)
        dec_plain = cip.decrypt(cipher, aad)
        self.assertEqual(dec_plain, plain)
        try:
            cip.decrypt(cipher+iv, aad)
            self.fail("Failed to throw exception on bad tag")
        except ValueError:
            pass
        # Test Case 8:
        cip = Cipher(b'\x00' * 24)
        iv = b'\x00' * 12
        plain = b'\x00' * 16
        aad = b''
        expected_cipher = b'\x98\xe7\x24\x7c\x07\xf0\xfe\x41\x1c\x26\x7e\x43\x84\xb0\xf6\x00'
        expected_tag = b'\x2f\xf5\x8d\x80\x03\x39\x27\xab\x8e\xf4\xd4\x58\x75\x14\xf0\xfb'
        cip.set_iv(iv)
        cipher = cip.encrypt(plain, aad)
        self.assertEqual(cipher, expected_cipher + expected_tag)
        cip.set_iv(iv)
        dec_plain = cip.decrypt(cipher, aad)
        self.assertEqual(dec_plain, plain)
        try:
            cip.decrypt(cipher+iv, aad)
            self.fail("Failed to throw exception on bad tag")
        except ValueError:
            pass
        # Test Case 9:
        cip = Cipher(b'\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08\xfe\xff\xe9\x92\x86\x65\x73\x1c')
        iv = b'\xca\xfe\xba\xbe\xfa\xce\xdb\xad\xde\xca\xf8\x88'
        plain = (b'\xd9\x31\x32\x25\xf8\x84\x06\xe5\xa5\x59\x09\xc5\xaf\xf5\x26\x9a' +
                 b'\x86\xa7\xa9\x53\x15\x34\xf7\xda\x2e\x4c\x30\x3d\x8a\x31\x8a\x72' +
                 b'\x1c\x3c\x0c\x95\x95\x68\x09\x53\x2f\xcf\x0e\x24\x49\xa6\xb5\x25' +
                 b'\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57\xba\x63\x7b\x39\x1a\xaf\xd2\x55')
        aad = b''
        expected_cipher = (b'\x39\x80\xca\x0b\x3c\x00\xe8\x41\xeb\x06\xfa\xc4\x87\x2a\x27\x57' +
                 b'\x85\x9e\x1c\xea\xa6\xef\xd9\x84\x62\x85\x93\xb4\x0c\xa1\xe1\x9c' +
                 b'\x7d\x77\x3d\x00\xc1\x44\xc5\x25\xac\x61\x9d\x18\xc8\x4a\x3f\x47' +
                 b'\x18\xe2\x44\x8b\x2f\xe3\x24\xd9\xcc\xda\x27\x10\xac\xad\xe2\x56')
        expected_tag = b'\x99\x24\xa7\xc8\x58\x73\x36\xbf\xb1\x18\x02\x4d\xb8\x67\x4a\x14'
        cip.set_iv(iv)
        cipher = cip.encrypt(plain, aad)
        self.assertEqual(cipher, expected_cipher + expected_tag)
        cip.set_iv(iv)
        dec_plain = cip.decrypt(cipher, aad)
        self.assertEqual(dec_plain, plain)
        try:
            cip.decrypt(cipher+iv, aad)
            self.fail("Failed to throw exception on bad tag")
        except ValueError:
            pass
        # Test Case 10:
        cip = Cipher(b'\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08\xfe\xff\xe9\x92\x86\x65\x73\x1c')
        iv = b'\xca\xfe\xba\xbe\xfa\xce\xdb\xad\xde\xca\xf8\x88'
        plain = (b'\xd9\x31\x32\x25\xf8\x84\x06\xe5\xa5\x59\x09\xc5\xaf\xf5\x26\x9a' +
                 b'\x86\xa7\xa9\x53\x15\x34\xf7\xda\x2e\x4c\x30\x3d\x8a\x31\x8a\x72' +
                 b'\x1c\x3c\x0c\x95\x95\x68\x09\x53\x2f\xcf\x0e\x24\x49\xa6\xb5\x25' +
                 b'\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57\xba\x63\x7b\x39')
        aad = b'\xfe\xed\xfa\xce\xde\xad\xbe\xef\xfe\xed\xfa\xce\xde\xad\xbe\xef\xab\xad\xda\xd2'
        expected_cipher = (b'\x39\x80\xca\x0b\x3c\x00\xe8\x41\xeb\x06\xfa\xc4\x87\x2a\x27\x57' +
                 b'\x85\x9e\x1c\xea\xa6\xef\xd9\x84\x62\x85\x93\xb4\x0c\xa1\xe1\x9c' +
                 b'\x7d\x77\x3d\x00\xc1\x44\xc5\x25\xac\x61\x9d\x18\xc8\x4a\x3f\x47' +
                 b'\x18\xe2\x44\x8b\x2f\xe3\x24\xd9\xcc\xda\x27\x10')
        expected_tag = b'\x25\x19\x49\x8e\x80\xf1\x47\x8f\x37\xba\x55\xbd\x6d\x27\x61\x8c'
        cip.set_iv(iv)
        cipher = cip.encrypt(plain, aad)
        self.assertEqual(cipher, expected_cipher + expected_tag)
        cip.set_iv(iv)
        dec_plain = cip.decrypt(cipher, aad)
        self.assertEqual(dec_plain, plain)
        try:
            cip.decrypt(cipher+iv, aad)
            self.fail("Failed to throw exception on bad tag")
        except ValueError:
            pass
        # Test Case 11 skipped: IV of length other than 12 not supported
        # Test Case 12 skipped: IV of length other than 12 not supported
        # Test Case 13:
        cip = Cipher(b'\x00' * 32)
        iv = b'\x00' * 12
        plain = b''
        aad = b''
        expected_cipher = b''
        expected_tag = b'\x53\x0f\x8a\xfb\xc7\x45\x36\xb9\xa9\x63\xb4\xf1\xc4\xcb\x73\x8b'
        cip.set_iv(iv)
        cipher = cip.encrypt(plain, aad)
        self.assertEqual(cipher, expected_cipher + expected_tag)
        cip.set_iv(iv)
        dec_plain = cip.decrypt(cipher, aad)
        self.assertEqual(dec_plain, plain)
        try:
            cip.decrypt(cipher+iv, aad)
            self.fail("Failed to throw exception on bad tag")
        except ValueError:
            pass
        # Test Case 14:
        cip = Cipher(b'\x00' * 32)
        iv = b'\x00' * 12
        plain = b'\x00' * 16
        aad = b''
        expected_cipher = b'\xce\xa7\x40\x3d\x4d\x60\x6b\x6e\x07\x4e\xc5\xd3\xba\xf3\x9d\x18'
        expected_tag = b'\xd0\xd1\xc8\xa7\x99\x99\x6b\xf0\x26\x5b\x98\xb5\xd4\x8a\xb9\x19'
        cip.set_iv(iv)
        cipher = cip.encrypt(plain, aad)
        self.assertEqual(cipher, expected_cipher + expected_tag)
        cip.set_iv(iv)
        dec_plain = cip.decrypt(cipher, aad)
        self.assertEqual(dec_plain, plain)
        try:
            cip.decrypt(cipher+iv, aad)
            self.fail("Failed to throw exception on bad tag")
        except ValueError:
            pass
        # Test Case 15:
        cip = Cipher(b'\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08')
        iv = b'\xca\xfe\xba\xbe\xfa\xce\xdb\xad\xde\xca\xf8\x88'
        plain = (b'\xd9\x31\x32\x25\xf8\x84\x06\xe5\xa5\x59\x09\xc5\xaf\xf5\x26\x9a' +
                 b'\x86\xa7\xa9\x53\x15\x34\xf7\xda\x2e\x4c\x30\x3d\x8a\x31\x8a\x72' +
                 b'\x1c\x3c\x0c\x95\x95\x68\x09\x53\x2f\xcf\x0e\x24\x49\xa6\xb5\x25' +
                 b'\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57\xba\x63\x7b\x39\x1a\xaf\xd2\x55')
        aad = b''
        expected_cipher = (b'\x52\x2d\xc1\xf0\x99\x56\x7d\x07\xf4\x7f\x37\xa3\x2a\x84\x42\x7d' +
                 b'\x64\x3a\x8c\xdc\xbf\xe5\xc0\xc9\x75\x98\xa2\xbd\x25\x55\xd1\xaa' +
                 b'\x8c\xb0\x8e\x48\x59\x0d\xbb\x3d\xa7\xb0\x8b\x10\x56\x82\x88\x38' +
                 b'\xc5\xf6\x1e\x63\x93\xba\x7a\x0a\xbc\xc9\xf6\x62\x89\x80\x15\xad')
        expected_tag = b'\xb0\x94\xda\xc5\xd9\x34\x71\xbd\xec\x1a\x50\x22\x70\xe3\xcc\x6c'
        cip.set_iv(iv)
        cipher = cip.encrypt(plain, aad)
        self.assertEqual(cipher, expected_cipher + expected_tag)
        cip.set_iv(iv)
        dec_plain = cip.decrypt(cipher, aad)
        self.assertEqual(dec_plain, plain)
        try:
            cip.decrypt(cipher+iv, aad)
            self.fail("Failed to throw exception on bad tag")
        except ValueError:
            pass
        # Test Case 16:
        cip = Cipher(b'\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08')
        iv = b'\xca\xfe\xba\xbe\xfa\xce\xdb\xad\xde\xca\xf8\x88'
        plain = (b'\xd9\x31\x32\x25\xf8\x84\x06\xe5\xa5\x59\x09\xc5\xaf\xf5\x26\x9a' +
                 b'\x86\xa7\xa9\x53\x15\x34\xf7\xda\x2e\x4c\x30\x3d\x8a\x31\x8a\x72' +
                 b'\x1c\x3c\x0c\x95\x95\x68\x09\x53\x2f\xcf\x0e\x24\x49\xa6\xb5\x25' +
                 b'\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57\xba\x63\x7b\x39')
        aad = b'\xfe\xed\xfa\xce\xde\xad\xbe\xef\xfe\xed\xfa\xce\xde\xad\xbe\xef\xab\xad\xda\xd2'
        expected_cipher = (b'\x52\x2d\xc1\xf0\x99\x56\x7d\x07\xf4\x7f\x37\xa3\x2a\x84\x42\x7d' +
                 b'\x64\x3a\x8c\xdc\xbf\xe5\xc0\xc9\x75\x98\xa2\xbd\x25\x55\xd1\xaa' +
                 b'\x8c\xb0\x8e\x48\x59\x0d\xbb\x3d\xa7\xb0\x8b\x10\x56\x82\x88\x38' +
                 b'\xc5\xf6\x1e\x63\x93\xba\x7a\x0a\xbc\xc9\xf6\x62')
        expected_tag = b'\x76\xfc\x6e\xce\x0f\x4e\x17\x68\xcd\xdf\x88\x53\xbb\x2d\x55\x1b'
        cip.set_iv(iv)
        cipher = cip.encrypt(plain, aad)
        self.assertEqual(cipher, expected_cipher + expected_tag)
        cip.set_iv(iv)
        dec_plain = cip.decrypt(cipher, aad)
        self.assertEqual(dec_plain, plain)
        try:
            cip.decrypt(cipher+iv, aad)
            self.fail("Failed to throw exception on bad tag")
        except ValueError:
            pass
        # Test Case 17 skipped: IV of length other than 12 not supported
        # Test Case 18 skipped: IV of length other than 12 not supported
        
if __name__ == "__main__":
    unittest.main()