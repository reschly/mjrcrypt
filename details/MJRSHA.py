'''My SHA (256, 384, 512) module.'''

from details.MJRUTIL import ROTR, ROTL, SHR, NOT, ADDWORD, MAJORITY, CHOOSE, CHUNKS


class SHA(object):
    '''
    An implementation of SHA-256, 384, 512 from FIPS 180-4
    '''

    def __bigsigma(self, x, offsets):
        '''FIPS 180-4, Section 4.1.2 / 4.1.3'''
        return (ROTR(x, offsets[0], bitlen = self.__bitlength) ^ 
                ROTR(x, offsets[1], bitlen = self.__bitlength) ^ 
                ROTR(x, offsets[2], bitlen = self.__bitlength))

    def _littlesigma(self, x, offsets):
        '''FIPS 180-4, Section 4.1.2 / 4.1.3'''
        return (ROTR(x, offsets[0], bitlen = self.__bitlength) ^ 
                ROTR(x, offsets[1], bitlen = self.__bitlength) ^ 
                SHR(x, offsets[2]))
        
    # offsets for sigma functions
    __bigsigma_offsets_256 = [[2, 13, 22], [6, 11, 25]]
    __littlesigma_offsets_256 = [[7, 18, 3], [17, 19, 10]]
    __bigisgma_offsets_384 = [[28, 34, 39], [14, 18, 41]]
    __littlesigma_offsets_384 = [[1, 8, 7], [19, 61, 6]] 
    __bigisgma_offsets_512 = __bigisgma_offsets_384
    __littlesigma_offsets_512 = __littlesigma_offsets_384
        
    # SHA-256 constants, FIPS 180-4 Section 4.2.2
    __K256 = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
              0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
              0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
              0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
              0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
              0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
              0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
              0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]
    
    # SHA-384  FIPS 180-4 Section 4.2.3
    __K384 = [0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
              0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
              0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
              0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
              0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
              0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
              0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
              0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
              0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
              0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
              0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
              0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
              0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
              0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
              0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
              0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
              0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
              0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
              0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
              0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817]
    
    # SHA-512 constants FIPS 180-4 Section 4.2.3 (same as SHA-384 constants)
    __K512 = __K384
    
    def __add_padding(self):
        # Creates a padding string for a SHA message.  See FIPS 180-4 Section 5.1

        # size of the last block prior to length value
        desired_size = (self._block_size * 7) // 8   # Note that 56 = (7/8) * 64, 112 = (7/8) * 128
        # size of the length value
        length_size = (self._block_size // 8)
        # amount of zero bytes = (desired size - (data)) mod block_size
        zero_bytes = desired_size - ((self.__length + 1) %  self._block_size)
        if (zero_bytes < 0):
            zero_bytes += self._block_size
        
        # padding = 0x80 + zeroes + length
        padding = b'\x80' + b'\x00' * (zero_bytes) + (self.__length*8).to_bytes(length_size, order='big')
        
        self.__current_block += padding
        self.__length += len(padding)
          
    # Initial H values for SHA-256, FIPS 180-4 Section 5.3.3
    __initial_h_256 = [0x6a09e667,
                       0xbb67ae85,
                       0x3c6ef372,
                       0xa54ff53a,
                       0x510e527f,
                       0x9b05688c,
                       0x1f83d9ab,
                       0x5be0cd19]
    
    # Initial H values for SHA-384, FIPS 180-4 Section 5.3.4    
    __initial_h_384 = [0xcbbb9d5dc1059ed8,
                       0x629a292a367cd507,
                       0x9159015a3070dd17,
                       0x152fecd8f70e5939,
                       0x67332667ffc00b31,
                       0x8eb44a8768581511,
                       0xdb0c2e0d64f98fa7,
                       0x47b5481dbefa4fa4]   

    # Initial H values for SHA-512, FIPS 180-4 Section 5.3.5    
    __initial_h_512 = [0x6a09e667f3bcc908,
                       0xbb67ae8584caa73b,
                       0x3c6ef372fe94f82b,
                       0xa54ff53a5f1d36f1,
                       0x510e527fade682d1,
                       0x9b05688c2b3e6c1f,
                       0x1f83d9abfb41bd6b,
                       0x5be0cd19137e2179]


    # SHA-256 initialization, from FIPS 180-4, Section 6.2.1
    def _SHA256_init(self):
        self.__state = SHA.__initial_h_256;
        self.__length = 0;
        self.__unhashed_data = b'';
        
    # SHA-256 update, based on FIPS 180-4, Section 6.2.2
    def _SHA256_update(self, data):
        self.__unhashed_data += data;
        self.__length += len(data); 
        blocks = [];
        if len(self.__unhashed_data) == self._block_size:
            blocks = [self.__unhashed_data];
            self.__unhashed_data = b'';
        if len(self.__unhashed_data >= self._block_size):
            blocks = CHUNKS(self.__unhashed_data, self._block)
            self.__unhashed_data = blocks[len(blocks)-1];
            blocks = blocks[0:len(blocks)-1];
        for block in blocks:
            # Prepare message schedule
            block_words = CHUNKS(block, 4)
            W = [0] * 80
            for i in range(0, 16):
                W[i] = int.from_bytes(block_words[i], byteorder='big')
            for i in range(16, 64):
                W[i] = self._littlesigma(W[i-2], SHA.__littlesigma_offsets_256[1]) + \
                    W[i-7] + self._littlesigma(W[i-15], SHA.__littlesigma_offsets_256[0]) + \
                    W[i-16]
                W[i] &= 0xffffffff
            #initialize 8 working variables
            a, b, c, d, e, f, g, h = self.__state
            # step 3
            for t in range(0, 64):
                T1 = h + self.__bigsigma(e, SHA.__bigsigma_offsets_256[1]) + \
                    CHOOSE(e, f, g, self.__bitlen) + \
                    SHA.__K256[t] + W[t]
                T1 &= 0xffffffff
                T2 = self.__bigsigma(a, SHA.__bigsigma_offsets_256[0]) + MAJORITY(a, b, c)
                T2 &= 0xffffffff
                h = g
                g = f
                f = e
                e = (d + T1) & 0xffffffff
                d = c
                c = b
                b = a
                a = (T1 + T2) & 0xffffffff
            # set state
            self.__state[0] = (self.__state[0] + a) & 0xffffffff
            self.__state[1] = (self.__state[1] + a) & 0xffffffff
            self.__state[2] = (self.__state[2] + a) & 0xffffffff
            self.__state[3] = (self.__state[3] + a) & 0xffffffff
            self.__state[4] = (self.__state[4] + a) & 0xffffffff
            self.__state[5] = (self.__state[5] + a) & 0xffffffff
            self.__state[6] = (self.__state[6] + a) & 0xffffffff
            self.__state[7] = (self.__state[7] + a) & 0xffffffff
        # end for block in blocks
    # end _SHA256_update
    
    def _SHA256_final(self):
        self.__add_padding()
        self._SHA256_update(b'')
        result = b''
        for word in self.__state:
            result += int.to_bytes(word, 4, byteorder='big')
        return result