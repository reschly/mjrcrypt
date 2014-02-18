'''My CTR-DRBG module Module'''


class CTRDRBG(object):
    '''
    An implementation of CTR-DRBG from NIST SP 800-90A (Jan 2012 edition)
    '''
    
    def __df(self, input_string, num_bytes):
        '''Block_Cipher_df, section 10.4.2
        Either returns the requted number of bytes,
        or raisees an Error'''
        
        # Step 1
        if (num_bytes > 64):
            raise ValueError("num_bytes must be <= 64")
        

        # Step 4
        S = (len(input_string).to_bytes(4, byteorder='big') +
            num_bytes.to_bytes(4, byteorder='big') +
            input_string + b'\x80')
        
        # step 5
        if (len(S) % self.outlen):
            S += b'\x00' * (self.outlen - (len(S) % self.outlen))
            
        # step 6
        temp = bytearray(b'')
        # step 7
        i = 0
        
        # Step 8
        K = (b'\x00\x01\x02\x03\x04\05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f' +
             b'\x10\x11\x12\x13\x14\05\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f')[0:self.keylen]
             
        # Step 9
        while (len(temp) < (self.keylen + self.outlen)):
            IV = i.to_bytes(4, byteorder='big') + (b'\x00' * (self.outlen - 4))
            temp += self.__BCC(K, IV + S)
            i += 1
            
        # Step 10
        K = temp[0:self.keylen]
        # Step 11
        X = temp[self.keylen:self.keylen+self.outlen]
        # step 12
        temp = bytearray(b'')
    
        # step 13:
        while (len(temp) < num_bytes):
            X = self.__Block_Encrypt(K, X)
            temp += X
        
        return temp[0:num_bytes]
    
    def __BCC(self, key, data):
        '''BCC function, section 10.4.3
        As far as I can tell, this is identical to CBC-MAC'''
        
        # Step 1
        chaining_value = b'\x00' * self.outlen
        # Step 2
        n = len(data) // self.outlen
    
        # Step 4
        for i in range(n):
            # Step 3
            block = data[self.outlen * i:self.outlen*(i+1)]
            # Step 4.1
            input_block = bytes([block[i] ^ chaining_value[i] for i in range(self.outlen)])
            # Step 4.2
            chaining_value = self.__Block_Encrypt(key, input_block)
        return chaining_value
    
    def __Block_Encrypt(self, key, data):
        '''Section 10.4.3: Returns the encryption of a single block of data,
        by the underlying cipher with the specified key'''
        return self._cipher(key)._encrypt(data)            