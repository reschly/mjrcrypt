


class AES:
    
    # bytes of key : number of rounds
    # FIPS 197 section 5
    __numrounds = { 16 : 10, 24 : 12, 32 : 14 }
    
    # input to state array
    # FIPS 197 section 3.4
    def __input_to_state_array(self, inbytes):
        self.state[0][0] = inbytes[0]
        self.state[1][0] = inbytes[1]
        self.state[2][0] = inbytes[2]
        self.state[3][0] = inbytes[3]
        self.state[0][1] = inbytes[4]
        self.state[1][1] = inbytes[5]
        self.state[2][1] = inbytes[6]
        self.state[3][1] = inbytes[7]
        self.state[0][2] = inbytes[8]
        self.state[1][2] = inbytes[9]
        self.state[2][2] = inbytes[10]
        self.state[3][2] = inbytes[11]
        self.state[0][3] = inbytes[12]
        self.state[1][3] = inbytes[13]
        self.state[2][3] = inbytes[14]
        self.state[3][3] = inbytes[15]
        
    # state array to output
    # FIPS 197 section 3.4
    def __state_array_to_output(self, outbytes):
        outbytes[0] = self.state[0][0]
        outbytes[1] = self.state[1][0]
        outbytes[2] = self.state[2][0]
        outbytes[3] = self.state[3][0]
        outbytes[4] = self.state[0][1]
        outbytes[5] = self.state[1][1]
        outbytes[6] = self.state[2][1]
        outbytes[7] = self.state[3][1]
        outbytes[8] = self.state[0][2]
        outbytes[9] = self.state[1][2]
        outbytes[10] = self.state[2][2]
        outbytes[11] = self.state[3][2]
        outbytes[12] = self.state[0][3]
        outbytes[13] = self.state[1][3]
        outbytes[14] = self.state[2][3]
        outbytes[15] = self.state[3][3]
    
    # one state-column as a 32-bit word
    # FIPS 197 section 3.5    
    def __column(self, col):
        return (self.state[0][col] << 24) + \
            (self.state[1][col] << 16) + \
            (self.state[2][col] << 8) + \
            (self.state[3][col])
    
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