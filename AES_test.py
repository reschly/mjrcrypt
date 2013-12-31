import unittest
from MJRAES import AES

class AES_test(unittest.TestCase):
    
    # test cases from FIPS 197 section 4.2.1
    def test_mul(self):
        self.assertEqual(AES._AES__mul(0x57, 0x13), 0xfe)  # @UndefinedVariable
        self.assertEqual(AES._AES__mul(0x13, 0x57), 0xfe)  # @UndefinedVariable
        self.assertEqual(AES._AES__mul(0x57, 0x83), 0xc1)  # @UndefinedVariable
        self.assertEqual(AES._AES__mul(0x83, 0x57), 0xc1)  # @UndefinedVariable
        
    # test case from FIPS 197 section 5.1.1
    def test_sbox(self):
        self.assertEqual(AES._AES__sbox[0x53], 0xed)  # @UndefinedVariable
        
        
if __name__ == "__main__":
    unittest.main()