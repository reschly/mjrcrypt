'''My GCM Module'''
from MJRUTIL import constant_time_eq


class GCM(object):
    '''An implementation of the GCM mode of operation'''

    @staticmethod
    def __GF_mul(x, y):
        '''Multiplication in GF(2^128), from section 2.5 of the GCM spec ('algorithm 1')'''
        x_int = int.from_bytes(x, byteorder='big')
        y_int = int.from_bytes(y, byteorder='big')
        z_int = 0;
        v = x_int;
        r = 0xe1000000000000000000000000000000
        for i in range(128):
            if (y_int & (1 << (127-i))):
                z_int ^= v
            if ((v & 1) == 0):
                v >>= 1
            else:
                v = (v >> 1) ^ r
        z_arr = bytearray(int.to_bytes(z_int, 16, byteorder='big'))
        return z_arr
       
    @staticmethod
    def __incr32(iv):
        '''Increments the low 32-bits of a 128-bit IV'''
        if (len(iv) != 16):
            raise ValueError("IV must be 128-bits / 16 bytes")
        for i in [15, 14, 13, 12]:
            iv[i] = (iv[i] + 1) & 0xff
            if (iv[i] != 0):
                break
   
    @staticmethod
    def __pad128(data):
        '''appends 0's to the input data to make it a full block length in size'''
        l = len(data) % 16
        if (l):
            for i in range(16-l):
                data.append(0)
   
    def _auth_encrypt(self, iv, plaintext, aad):
        '''Authenticated encryption.  iv, plaintext, and aad'''
        if (len(iv) != 12):
            raise ValueError("IV must be 96 bits / 12 bytes")
        # buffer to be re-used on multiple occasions
        buffer = bytearray(16)
        # create the mask for the tag
        iv_copy = bytearray(iv)
        GCM.__pad128(iv_copy)
        GCM.__incr32(iv_copy)
        self._cipher._encrypt(iv_copy, buffer)
        tag_mask = bytearray(buffer)
        # Create cipher text
        cipher = bytearray(0)
        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i+16]
            GCM.__incr32(iv_copy)
            self._cipher._encrypt(iv_copy, buffer)
            for j in range(len(block)):
                cipher.append(block[j] ^ buffer[j])
        raw_tag = self.__ghash(aad, cipher)
        tag = bytearray(len(raw_tag))
        for i in range(len(tag)):
            tag[i] = raw_tag[i] ^ tag_mask[i]
        return (cipher, tag)
   
    def _auth_decrypt(self, iv, cipher, aad, tag):
        '''Authenticated decryption.  iv, plaintext, and aad'''
        if (len(iv) != 12):
            raise ValueError("IV must be 96 bits / 12 bytes")
        # buffer to be re-used on multiple occasions
        buffer = bytearray(16)
        # calculate tag mask
        iv_copy = bytearray(iv)
        GCM.__pad128(iv_copy)
        GCM.__incr32(iv_copy)
        self._cipher._encrypt(iv_copy, buffer)
        calculated_tag_mask = bytearray(buffer)
        # calculate tag
        calculated_raw_tag = self.__ghash(aad, cipher)
        calculated_tag = bytearray(len(calculated_raw_tag))
        for i in range(len(calculated_tag)):
            calculated_tag = calculated_raw_tag[i] ^ calculated_tag_mask[i]
        # compare calculated, actual tag
        if not constant_time_eq(calculated_tag, tag):
            raise ValueError("Bad tag")
        # tag correct -- provide decrypt
        plaintext = bytearray(0)
        for i in range(0, len(cipher), 16):
            block = cipher[i:i+16]
            GCM.__incr32(iv_copy)
            self._cipher._encrypt(iv_copy, buffer)
            for j in range(len(block)):
                plaintext.append(block[j] ^ buffer[j])
        return plaintext
   
    def __ghash(self, A, C):
        '''The GHASH function'''
        result = bytearray(16)
        for i in range(0, len(A), 16):
            block = bytearray(A[i:i+16])
            GCM.__pad128(block)
            for j in range(len(block)):
                result[j] ^= block[j]
            result = GCM.__GF_mul(result, self._H)
        for i in range(0, len(C), 16):
            block = bytearray(C[i:i+16])
            GCM.__pad128(block)
            for j in range(len(block)):
                result[j] ^= block[j]
            result = GCM.__GF_mul(result, self._H)
        a_len = len(A) * 8
        c_len = len(C) * 8
        for i in range(8):
            result[7-i] ^= (a_len & 0xff)
            result[15-i] ^= (c_len & 0xff)
            a_len >>= 8
            c_len >>= 8
        result = GCM.__GF_mul(result, self._H)
        return result
                     
    def __init__(self, cipher):
        '''Constructor.  cipher = an initialized instance of a 16-byte block cipher'''
        self._cipher = cipher
        # generate H
        self._H = bytearray(16)
        self._cipher._encrypt(b'\x00' * 16, self._H)