


class AES:
    
    # bytes of key : number of rounds
    # FIPS 197 section 5
    __numrounds = { 16 : 10, 24 : 12, 32 : 14 }
    
    # input to __state array
    # FIPS 197 section 3.4
    def __input_to_state_array(self, inbytes):
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
        
    # __state array to output
    # FIPS 197 section 3.4
    def __state_array_to_output(self, outbytes):
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
    
    # one __state-column as a 32-bit word
    # FIPS 197 section 3.5    
    def __column(self, col):
        return (self.__state[0][col] << 24) + \
            (self.__state[1][col] << 16) + \
            (self.__state[2][col] << 8) + \
            (self.__state[3][col])
    
    # add two 8-bit values
    # FIPS 197 section 4.1
    @staticmethod    
    def __add(a, b):
        return (a ^ b)

    # multiply input * 2 modulo 0x11b
    # helper function from FIPS 187 section 4.2.1
    @staticmethod
    def __xtime(x):
        res = 2*x;
        if (res > 255):
            res = (res ^ 0x11b);
        return res;
    
    # multiply two 8-bit values
    # FIPS 197 section 4.2
    @staticmethod
    def __mul(a,b):
        res = 0
        xt = a;
        while (b):
            if (b & 0x1):
                res ^= xt;
            xt = AES.__xtime(xt);
            b = b >> 1;
        return res;
    
    # add two GF(2^8) polynomials
    # FIPS 197 section 4.3
    @staticmethod
    def __GF_add(a,b):
        res = [ a[0] ^ b[0],
               a[1] ^ b[1],
               a[2] ^ b[2],
               a[3] ^ b[3]]
        return res;
    
    # multiply two GF(2^8) polynomials mod x^4+1
    # FIPS 197 section 4.3
    @staticmethod
    def __GF_mul(a,b):
        res = []
        res[0] = (a[0]*b[0] ^ a[3]*b[1] ^ a[2]*b[2] ^ a[1]*b[3])&0xff;
        res[1] = (a[1]*b[0] ^ a[0]*b[1] ^ a[3]*b[2] ^ a[2]*b[3])&0xff;
        res[2] = (a[2]*b[0] ^ a[1]*b[1] ^ a[0]*b[2] ^ a[3]*b[3])&0xff;
        res[3] = (a[3]*b[0] ^ a[2]*b[1] ^ a[1]*b[2] ^ a[0]*b[3])&0xff;
        return res


    # Cipher
    # FIPS 197 Figure 5, Section 5.1
    def __cipher(self, inbytes, outbytes):
        self.__input_to_state_array(inbytes)
        
        self.__AddRoundKey(0);
        
        for i in range(1, AES.__numrounds[self.keysize]):
            self.__SubBytes()
            self.__ShiftRows()
            self.__MixColumns()
            self.__AddRoundKey(i)
        # end for
        
        self.__SubBytes()
        self.__ShiftRows()
        self.__AddRoundKey(AES.__numrounds[self.keysize])
        
        self.__state_array_to_output(outbytes)
    # end __cipher
    
    
    # AES S-box
    # FIPS 197 section 5.1.1, Figure 7
    __sbox = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
                  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
                  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
                  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
                  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
                  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
                  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
                  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
                  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
                  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
                  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
                  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
                  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
                  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
                  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
                  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]

    
    # SubBytes()
    # FIPS 197 Section 5.1.1
    def __SubBytes(self):
        for i in range(len(self.__state)):
            for j in range(len(self.__state[i])):
                self.__state[i][j] = AES.__sbox[self.state[i][j]]
    
    # ShiftRows()
    # FIPS 197 Section 5.1.2
    def __ShiftRows(self):
        # 0-shift of row 0
        # 1 shift-left of row 1
        [a,b,c,d] = self.__state[1]
        self.__state[1] = [b,c,d,a]
        # 2 shift-left of row 2
        [a,b,c,d] = self.__state[2]
        self.__state[2] = [c,d,a,b]
        # 3 shift-left of row 3
        [a,b,c,d] = self.__state[3]
        self.__state[3] = [d,a,b,c]
    
    # MixColumns()
    # FIPS 197 Section 5.1.3
    def __MixColumns(self):
        for i in range(len(self.__state[0])): # for each column:
            a = AES.__GF_mul(self.__state[0][i], 2) ^ \
                AES.__GF_mul(self.__state[1][i], 3) ^ \
                self.__state[2][i] ^ self.__state[3][i]
            b = AES.__GF_mul(self.__state[1][i], 2) ^ \
                AES.__GF_mul(self.__state[2][i], 3) ^ \
                self.__state[0][i] ^ self.__state[3][i]
            c = AES.__GF_mul(self.__state[2][i], 2) ^ \
                AES.__GF_mul(self.__state[3][i], 3) ^ \
                self.__state[0][i] ^ self.__state[1][i]
            d = AES.__GF_mul(self.__state[3][i], 2) ^ \
                AES.__GF_mul(self.__state[0][i], 3) ^ \
                self.__state[1][i] ^ self.__state[2][i]
            self.__state[0][i] = a
            self.__state[1][i] = b
            self.__state[2][i] = c
            self.__state[3][i] = d
            
    # AddRoundKey()
    # FIPS 197 Section 5.1.4
    def __AddRoundKey(self, r):
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
    
        
    # KeyExpansion()
    # FIPS 197 Section 5.2
    def __KeyExpansion(self, key):
        numrounds = AES.__numrounds[len(key)] 
        for i in range(len(key)):
            self.__roundkeys[i//16][i%16] = key[i];
            
        for i in range(len(key), 16*(numrounds+1), 4):
            temp = self.__roundkeys[(i-4)//16][(i-4)%16:((i-4)%16) + 4]

            if (i % len(key)) == 0:
                AES.__RotWord(temp)
                AES.__SubWord(temp)
                temp[0] ^= AES.__Rcon[i//len(key)] 
            elif ((len(key) > 24) and (i % len(key) == 16)):
                AES.__SubWord(temp)
            
            self.__roundkeys[i//16][i%16] = temp[0]
            self.__roundkeys[(i+1)//16][(i+1)%16] = temp[1]
            self.__roundkeys[(i+2)//16][(i+2)%16] = temp[2]
            self.__roundkeys[(i+3)//16][(i+3)%16] = temp[3]
    # end for i in range(len(key), 16*numrounds+1, 4)
 
    # SubWord()
    # FIPS 197 section 5.2
    @staticmethod
    def __SubWord(word):
        for i in len(word):
            word[i] = AES.__sbox[word[i]]

    # RotWord()
    # FIPS 197 Section 5.2
    @staticmethod
    def __RotWord(word):
        [a,b,c,d] = word;
        word = [b,c,d,a]
        
    # Rcon
    # FIPS 197 section 5.2
    __Rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

        

        