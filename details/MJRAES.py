'''My AES Module'''


class AES(object):
    '''An implementation of the AES Encryption Routine
    Note that decryption is not implemented, as the
    only mode that is planned to be supported is GCM
    mode, which does not require the Decryption routine'''

    # blocksize
    _blocksize = 16

    # bytes of key : number of rounds
    # FIPS 197 section 5
    __numrounds = {16 : 10, 24 : 12, 32 : 14}

    def __input_to_state_array(self, inbytes):
        '''Converts input to the state array
        See FIPS 197 section 3.4'''
        self.__state[0][0] = inbytes[0]
        self.__state[1][0] = inbytes[1]
        self.__state[2][0] = inbytes[2]
        self.__state[3][0] = inbytes[3]
        self.__state[0][1] = inbytes[4]
        self.__state[1][1] = inbytes[5]
        self.__state[2][1] = inbytes[6]
        self.__state[3][1] = inbytes[7]
        self.__state[0][2] = inbytes[8]
        self.__state[1][2] = inbytes[9]
        self.__state[2][2] = inbytes[10]
        self.__state[3][2] = inbytes[11]
        self.__state[0][3] = inbytes[12]
        self.__state[1][3] = inbytes[13]
        self.__state[2][3] = inbytes[14]
        self.__state[3][3] = inbytes[15]

    def __state_array_to_output(self, outbytes):
        '''Converts state array to output array
        See FIPS 197 section 3.4'''
        outbytes[0] = self.__state[0][0]
        outbytes[1] = self.__state[1][0]
        outbytes[2] = self.__state[2][0]
        outbytes[3] = self.__state[3][0]
        outbytes[4] = self.__state[0][1]
        outbytes[5] = self.__state[1][1]
        outbytes[6] = self.__state[2][1]
        outbytes[7] = self.__state[3][1]
        outbytes[8] = self.__state[0][2]
        outbytes[9] = self.__state[1][2]
        outbytes[10] = self.__state[2][2]
        outbytes[11] = self.__state[3][2]
        outbytes[12] = self.__state[0][3]
        outbytes[13] = self.__state[1][3]
        outbytes[14] = self.__state[2][3]
        outbytes[15] = self.__state[3][3]

    def __column(self, col):
        '''Returns one state column as a 32-bit word
        See FIPS 197 section 3.5'''
        return (self.__state[0][col] << 24) + \
            (self.__state[1][col] << 16) + \
            (self.__state[2][col] << 8) + \
            (self.__state[3][col])

    @staticmethod
    def __add(a, b):
        '''adds two 8-bit values
        See FIPS 197 section 4.1'''
        return a ^ b

    @staticmethod
    def __xtime(x):
        '''Multiplies input modulo 0x11b
        helper function from FIPS 197 sesction 4.2.1'''
        res = 2*x
        if res > 255:
            res = (res ^ 0x11b)
        return res

    @staticmethod
    def __mul(a, b):
        '''Multiplies two 8-bit values
        See FIPS 197 section 4.2'''
        res = 0
        xt = a
        while b:
            if b & 0x1:
                res ^= xt
            xt = AES.__xtime(xt)
            b = b >> 1
        return res

    @staticmethod
    def __GF_add(a, b):
        '''Adds two GF(2^8) polynomials
        See FIPS 197 section 4.3'''
        res = [a[0] ^ b[0],
               a[1] ^ b[1],
               a[2] ^ b[2],
               a[3] ^ b[3]]
        return res

    @staticmethod
    def __GF_mul(a, b):
        '''Multiplies two GF(2^8) polynomials mod x^4+1
        See FIPS 197 section 4.3'''
        res = []
        res[0] = (a[0]*b[0] ^ a[3]*b[1] ^ a[2]*b[2] ^ a[1]*b[3])&0xff
        res[1] = (a[1]*b[0] ^ a[0]*b[1] ^ a[3]*b[2] ^ a[2]*b[3])&0xff
        res[2] = (a[2]*b[0] ^ a[1]*b[1] ^ a[0]*b[2] ^ a[3]*b[3])&0xff
        res[3] = (a[3]*b[0] ^ a[2]*b[1] ^ a[1]*b[2] ^ a[0]*b[3])&0xff
        return res


    def __cipher(self, inbytes, outbytes):
        '''The Cipher method from FIPS 197 Figure 5, section 5.1'''
        self.__input_to_state_array(inbytes)

        self.__AddRoundKey(0)

        for i in range(1, AES.__numrounds[self.__keysize]):
            self.__SubBytes()
            self.__ShiftRows()
            self.__MixColumns()
            self.__AddRoundKey(i)
        # end for

        self.__SubBytes()
        self.__ShiftRows()
        self.__AddRoundKey(AES.__numrounds[self.__keysize])

        self.__state_array_to_output(outbytes)
    # end __cipher


    # AES S-box
    # FIPS 197 section 5.1.1, Figure 7
    __sbox = b'\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5\x30\x01\x67\x2b\xfe\xd7\xab\x76\
\xca\x82\xc9\x7d\xfa\x59\x47\xf0\xad\xd4\xa2\xaf\x9c\xa4\x72\xc0\
\xb7\xfd\x93\x26\x36\x3f\xf7\xcc\x34\xa5\xe5\xf1\x71\xd8\x31\x15\
\x04\xc7\x23\xc3\x18\x96\x05\x9a\x07\x12\x80\xe2\xeb\x27\xb2\x75\
\x09\x83\x2c\x1a\x1b\x6e\x5a\xa0\x52\x3b\xd6\xb3\x29\xe3\x2f\x84\
\x53\xd1\x00\xed\x20\xfc\xb1\x5b\x6a\xcb\xbe\x39\x4a\x4c\x58\xcf\
\xd0\xef\xaa\xfb\x43\x4d\x33\x85\x45\xf9\x02\x7f\x50\x3c\x9f\xa8\
\x51\xa3\x40\x8f\x92\x9d\x38\xf5\xbc\xb6\xda\x21\x10\xff\xf3\xd2\
\xcd\x0c\x13\xec\x5f\x97\x44\x17\xc4\xa7\x7e\x3d\x64\x5d\x19\x73\
\x60\x81\x4f\xdc\x22\x2a\x90\x88\x46\xee\xb8\x14\xde\x5e\x0b\xdb\
\xe0\x32\x3a\x0a\x49\x06\x24\x5c\xc2\xd3\xac\x62\x91\x95\xe4\x79\
\xe7\xc8\x37\x6d\x8d\xd5\x4e\xa9\x6c\x56\xf4\xea\x65\x7a\xae\x08\
\xba\x78\x25\x2e\x1c\xa6\xb4\xc6\xe8\xdd\x74\x1f\x4b\xbd\x8b\x8a\
\x70\x3e\xb5\x66\x48\x03\xf6\x0e\x61\x35\x57\xb9\x86\xc1\x1d\x9e\
\xe1\xf8\x98\x11\x69\xd9\x8e\x94\x9b\x1e\x87\xe9\xce\x55\x28\xdf\
\x8c\xa1\x89\x0d\xbf\xe6\x42\x68\x41\x99\x2d\x0f\xb0\x54\xbb\x16'


    def __SubBytes(self):
        '''The SubBytes method from
        FIPS 197 section 5.1.1.'''
        for i in range(len(self.__state)):
            for j in range(len(self.__state[i])):
                self.__state[i][j] = AES.__sbox[self.__state[i][j]]

    def __ShiftRows(self):
        '''The ShiftRows method from
        FIPS 197 section 5.1.2'''
        # 0-shift of row 0
        # 1 shift-left of row 1
        [a, b, c, d] = self.__state[1]
        self.__state[1] = [b, c, d, a]
        # 2 shift-left of row 2
        [a, b, c, d] = self.__state[2]
        self.__state[2] = [c, d, a, b]
        # 3 shift-left of row 3
        [a, b, c, d] = self.__state[3]
        self.__state[3] = [d, a, b, c]

    def __MixColumns(self):
        '''The MixColumns method from
        FIPS 197 section 5.1.3'''
        for i in range(len(self.__state[0])): # for each column:
            a = AES.__mul(self.__state[0][i], 2) ^ \
                AES.__mul(self.__state[1][i], 3) ^ \
                self.__state[2][i] ^ self.__state[3][i]
            b = AES.__mul(self.__state[1][i], 2) ^ \
                AES.__mul(self.__state[2][i], 3) ^ \
                self.__state[0][i] ^ self.__state[3][i]
            c = AES.__mul(self.__state[2][i], 2) ^ \
                AES.__mul(self.__state[3][i], 3) ^ \
                self.__state[0][i] ^ self.__state[1][i]
            d = AES.__mul(self.__state[3][i], 2) ^ \
                AES.__mul(self.__state[0][i], 3) ^ \
                self.__state[1][i] ^ self.__state[2][i]
            self.__state[0][i] = a
            self.__state[1][i] = b
            self.__state[2][i] = c
            self.__state[3][i] = d


    def __AddRoundKey(self, r):
        '''The AddRoundKey method from
        FIPS 197 section 5.1.4'''
        self.__state[0][0] ^= self.__roundkeys[r][0]
        self.__state[1][0] ^= self.__roundkeys[r][1]
        self.__state[2][0] ^= self.__roundkeys[r][2]
        self.__state[3][0] ^= self.__roundkeys[r][3]
        self.__state[0][1] ^= self.__roundkeys[r][4]
        self.__state[1][1] ^= self.__roundkeys[r][5]
        self.__state[2][1] ^= self.__roundkeys[r][6]
        self.__state[3][1] ^= self.__roundkeys[r][7]
        self.__state[0][2] ^= self.__roundkeys[r][8]
        self.__state[1][2] ^= self.__roundkeys[r][9]
        self.__state[2][2] ^= self.__roundkeys[r][10]
        self.__state[3][2] ^= self.__roundkeys[r][11]
        self.__state[0][3] ^= self.__roundkeys[r][12]
        self.__state[1][3] ^= self.__roundkeys[r][13]
        self.__state[2][3] ^= self.__roundkeys[r][14]
        self.__state[3][3] ^= self.__roundkeys[r][15]


    def __KeyExpansion(self, key):
        '''The KeyExpansion method from
        FIPS 197 section 5.2'''
        numrounds = AES.__numrounds[len(key)]
        for i in range(len(key)):
            self.__roundkeys[i//16][i%16] = key[i]

        for i in range(len(key), 16*(numrounds+1), 4):
            temp = self.__roundkeys[(i-4)//16][(i-4)%16:((i-4)%16) + 4]

            if (i % len(key)) == 0:
                temp = AES.__RotWord(temp)
                temp = AES.__SubWord(temp)
                temp[0] ^= AES.__Rcon[i//len(key)]
            elif (len(key) > 24) and (i % len(key) == 16):
                temp = AES.__SubWord(temp)

            self.__roundkeys[i//16][i%16] = temp[0] ^ \
                self.__roundkeys[(i-len(key))//16][(i-len(key))%16]
            self.__roundkeys[(i+1)//16][(i+1)%16] = temp[1] ^ \
                self.__roundkeys[(i+1-len(key))//16][(i+1-len(key))%16]
            self.__roundkeys[(i+2)//16][(i+2)%16] = temp[2] ^ \
                self.__roundkeys[(i+1-len(key))//16][(i+2-len(key))%16]
            self.__roundkeys[(i+3)//16][(i+3)%16] = temp[3] ^ \
                self.__roundkeys[(i+1-len(key))//16][(i+3-len(key))%16]
    # end for i in range(len(key), 16*numrounds+1, 4)

    @staticmethod
    def __SubWord(word):
        '''The SubWord method from
        FIPS 197 section 5.2'''
        for i in range(len(word)):
            word[i] = AES.__sbox[word[i]]
        return word

    @staticmethod
    def __RotWord(word):
        '''The RotWord method from
        FIPS 197 section 5.2'''
        [a, b, c, d] = word
        word = [b, c, d, a]
        return word

    # Rcon
    # FIPS 197 section 5.2
    __Rcon = b'\x00\x01\x02\x04\x08\x10\x20\x40\x80\x1b\x36'


    def __init__(self, key):
        '''Initializer

        Inputs:
        key: raw aes key, as a (16, 24, or 32)-byte array
        '''
        assert len(key) in [16, 24, 32], \
            "Bad key size: " + str(len(key)) + ".  Must be 16, 24, or 32 bytes."
        self.__roundkeys = [bytearray(16)
                            for i in range(AES.__numrounds[len(key)]+1)]
        self.__state = [bytearray(4) for i in range(4)]
        self.__KeyExpansion(key)
        self.__keysize = len(key)
        
    def _encrypt(self, inbytes, outbytes):
        '''Encrypted a single block in ECB mode.  
        Do not use unless you know what you're doing'''
        self.__cipher(inbytes, outbytes)
