import unittest
from MJRAES import AES

class AES_test(unittest.TestCase):
    
    def test_mul(self):
        self.assertEqual(AES._AES__mul(0x57, 0x13), 0xfe)  # @UndefinedVariable
        self.assertEqual(AES._AES__mul(0x13, 0x57), 0xfe)  # @UndefinedVariable
        self.assertEqual(AES._AES__mul(0x57, 0x83), 0xc1)  # @UndefinedVariable
        self.assertEqual(AES._AES__mul(0x83, 0x57), 0xc1)  # @UndefinedVariable
        
        
if __name__ == "__main__":
    unittest.main()