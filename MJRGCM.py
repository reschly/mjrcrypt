'''My GCM Module'''


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
            if (v & 1):
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
            iv[i] += 1
            if (iv[i] != 0):
                break
    
    @staticmethod
    def __pad128(data):
        '''appends 0's to the input data to make it a full block length in size'''
        l = len(data) % 16
        if (l):
            for i in range(16-l):
                data.append(0)
    
    def __auth_encrypt(self, iv, plaintext, aad):
        '''Authenticated encryption.  iv, plaintext, and aad'''
        if (len(iv) != 12):
            raise ValueError("IV must be 96 bits / 12 bytes")
        # buffer to be re-used on multiple occasions
        buffer = bytearray(16)
        # generate H
        self._cipher._encrypt(b'\x00' * 16, buffer)
        H = bytearray(buffer)
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
        raw_tag = GCM.__ghash(H, aad, cipher)
        tag = bytearray(len(raw_tag))
        for i in range(len(tag)):
            tag[i] = raw_tag[i] ^ tag_mask[i]
        return (cipher, tag)
    
    def __auth_decrypt(self, iv, cipher, aad, tag):
        '''Authenticated decryption.  iv, plaintext, and aad'''
        if (len(iv) != 12):
            raise ValueError("IV must be 96 bits / 12 bytes")
        # buffer to be re-used on multiple occasions
        buffer = bytearray(16)
        # generate H
        self._cipher._encrypt(b'\x00' * 16, buffer)
        H = bytearray(buffer)
        # calculate tag mask
        iv_copy = bytearray(iv)
        GCM.__pad128(iv_copy)
        GCM.__incr32(iv_copy)
        self._cipher._encrypt(iv_copy, buffer)
        calculated_tag_mask = bytearray(buffer)
        # calculate tag
        calculated_raw_tag = GCM.__ghash(H, aad, cipher)
        calculated_tag = bytearray(len(calculated_raw_tag))
        # TODO: make this const_time_eq a util function
        for i in range(len(calculated_tag)):
            calculated_tag = calculated_raw_tag[i] ^ calculated_tag_mask[i]
        # compare calculated, actual tag
        if len(tag) != len(calculated_tag):
            raise ValueError("Bad tag length")
        diff = 0;
        for i in range(len(tag)):
            diff |= (tag[i] ^ calculated_tag[i])
        if (tag != 0):
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
    
    @staticmethod
    def __ghash(H, A, C):
        '''The GHASH function'''
        result = bytearray(16)
        for i in range(0, len(A), 16):
            block = A[i:i+16]
            GCM.__pad128(block)
            for j in range(len(block)):
                result[j] ^= block[j]
            result = GCM.__GF_mul(result, H)
        for i in range(0, len(C), 16):
            block = C[i:i+16]
            GCM.__pad128(block)
            for j in range(len(block)):
                result[j] ^= block[j]
            result = GCM.__GF_mul(result, H)
        a_len = len(A) * 8
        c_len = len(C) * 8
        for i in range(8):
            result[8-i] ^= (a_len & 0xff)
            result[16-i] ^= (c_len & 0xff)
        result = GCM.__GF_mul(result, H)
                      
        
            