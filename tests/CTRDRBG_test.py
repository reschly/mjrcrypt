'''Unit tests for CTRDRBG'''

import sys
sys.path.append("..")
import unittest
from details.MJRCTRDRBG import CTRDRBG
from details.MJRAES import AES
from binascii import unhexlify


class CTRDRBG_test(unittest.TestCase):
    '''TestCase for Cipher'''
    
    def test_array_increment(self):
        '''Unit test for _array_increment'''
        ar0 = bytearray(b'\x01\x02\x03\xff\xfe')
        ar1 = b'\x01\x02\x03\xff\xff'
        ar2 = b'\x01\x02\x04\x00\x00'
        ar3 = b'\x01\x02\x04\x00\x01'
        CTRDRBG._array_increment(ar0)
        self.assertEqual(ar0, ar1)
        CTRDRBG._array_increment(ar0)
        self.assertEqual(ar0, ar2)
        CTRDRBG._array_increment(ar0)
        self.assertEqual(ar0, ar3)
        ar0 = bytearray(b'\xff\xff\xff\xfe')
        ar1 = b'\xff\xff\xff\xff'
        ar2 = b'\x00\x00\x00\x00'
        ar3 = b'\x00\x00\x00\x01'
        CTRDRBG._array_increment(ar0)
        self.assertEqual(ar0, ar1)
        CTRDRBG._array_increment(ar0)
        self.assertEqual(ar0, ar2)
        CTRDRBG._array_increment(ar0)
        self.assertEqual(ar0, ar3)
        
    def test_aes128_df(self):
        '''Test aes128-ctr-drbg with derivation function'''
        drbg = CTRDRBG(AES, 16)
        entropy_input = b'0f65da13dca407999d4773c2b4a11d85'
        nonce = b'5209e5b4ed82a234'
        personalization_string = b''
        additional_input1 = b''
        additional_input2 = b''
        expected_key1 = b'0c42ea6804303954deb197a07e6dbdd2'
        expected_V1 = b'80941680713df715056fb2a3d2e998b2'
        reseed_entropy = b'1dea0a12c52bf64339dd291c80d8ca89'
        reseed_additional_input = b''
        expected_key2 = b'32fbfd0109f364ed21ef21a6e5c763e7'
        expected_V2 = b'f2bacbb233252fba35fb0582f9286179'
        expected_key3 = b'757c8eb766f9aaa4650d6500b58624a3'
        expected_V3 = b'99003d630bba500fe17c37f8c7331bf6'
        expected_bits = b'2859cc468a76b08661ffd23b28547ffd0997ad526a0f51261b99ed3a37bd407bf418dbe6c6c3e26ed0ddefcb7474d899bd99f3655427519fc5b4057bcaf306d4'
        expected_key4 = b'e421ff2445e04992faf36cf9a5eaf1f9'
        expected_V4 = b'5907ab447a88e5106753507cc97e0fd5'
        
        drbg._CTRDRBG__Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._CTRDRBG__Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._CTRDRBG__Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._CTRDRBG__Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)

        drbg = CTRDRBG(AES, 16)
        entropy_input = b'070d59639873a5452738227b7685d1a9'
        nonce = b'74181f3c22f64920'
        personalization_string = b'4e6179d4c272a14cf13df65ea3a6e50f'
        additional_input1 = b''
        additional_input2 = b''
        expected_key1 = b'32a76abdc2d8fc1143edd742d0fae60a'
        expected_V1 = b'4e8e758d22f36d10e598d4ae68a828b7'
        reseed_entropy = b'4a47c2f38516b46f002e71daed169b5c'
        reseed_additional_input = b''
        expected_key2 = b'ca51adea091be6972644c4aa1be16aca'
        expected_V2 = b'847dcefd0abc31b0f5b0cfa7e377349e'
        expected_key3 = b'1e4bf36111637d53f022f7959fe8c971'
        expected_V3 = b'074e82340d41b6fec662ce9b591f6ccb'
        expected_bits = b'31c99109f8c510133cd396f9bc2c12c07cc1615fa30999afd7f236fd401a8bf23338ee1d035f83b7a253dcee18fca7f2ee96c6c2cd0cff02767069aa69d13be8'
        expected_key4 = b'884d79cf24be82e60dce9bcdf327f207'
        expected_V4 = b'4b45ad20c126e38664e4f34b5a5b0c2e'

        drbg._CTRDRBG__Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._CTRDRBG__Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._CTRDRBG__Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._CTRDRBG__Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)

        drbg = CTRDRBG(AES, 16)
        entropy_input = b'e14ed7064a97814dd326b9a05bc44543'
        nonce = b'876240c1f7de3dba'
        personalization_string = b'26ccf56848a048721d0aad87d6fc65f0'
        expected_key1 = b'c5f6207dddce79208d4c8630923fb9c1'
        expected_V1 = b'033b9f1df720c2677abbea63f5c425fa'
        reseed_entropy = b'7ec4ac660fa0bbfa66ac3802e511901f'
        reseed_additional_input = b'8835d28e7f85a4e95087bdd1bb7ad57e'
        expected_key2 = b'9161985f966d7f675e783f39f39b3bc8'
        expected_V2 = b'373f52ce22f3690c351ad65ca0424303'
        additional_input1 = b'2a9bd50bbb20fefe24649f5f80eede66'
        expected_key3 = b'14e9256df61235c867233af47107739f'
        expected_V3 = b'f60e23434fd8f63712553a23ce4ff918'
        additional_input2 = b'f7ce3d5c6c381e56b25410c6909c1074'
        expected_bits = b'd2f3130d309bed1da65545b9d793e035fd2564303d1fdcfb6c7fee019500d9f5d434fab2d3c8d15e39a25f965aaa804c7141407e90c4a86a6c8d303ce83bfb34'
        expected_key4 = b'e68df737b3c0edfb66a9e357121c85ae'
        expected_V4 = b'd81e79df9064de25368697716c01b7fa'

        drbg._CTRDRBG__Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._CTRDRBG__Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._CTRDRBG__Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._CTRDRBG__Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)

        drbg = CTRDRBG(AES, 16)
        entropy_input = b'8fb9573a546253cdbf6215a1805a4138'
        nonce = b'7c2ce65402bca683'
        personalization_string = b''
        expected_key1 = b'dd3b8c125fff2f1f4e56cc03efaaa530'
        expected_V1 = b'6c7a476a1f259956c44149f0a907e222'
        reseed_entropy = b'bc5ad89ae18c491f90a2ae9e7e2cf99d'
        reseed_additional_input = b''
        expected_key2 = b'07cd9c722c8950ef8adfcd869187154b'
        expected_V2 = b'91e3a0e61dc1e28b43290df1a347f258'
        additional_input1 = b''
        expected_key3 = b'f1744ccaabd4cacf906a3dee97d3350e'
        expected_V3 = b'8a1fbbc9b772c97975da470db2ebd0c9'
        additional_input2 = b''
        expected_bits = b'076282e80e65d7701a35b3446368b616f8d96223b9b5116423a3a232c72ceabf4accc40ac619d6aa68aedb8b2670b807cce99fc21b8fa516ef75b68fc06c87c7'
        expected_key4 = b'ecf5b5ebce3665a01db39994b45b3719'
        expected_V4 = b'0b126334b7a8f75fbfdd72e492083e20'

        drbg._CTRDRBG__Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._CTRDRBG__Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._CTRDRBG__Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._CTRDRBG__Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)

        drbg = CTRDRBG(AES, 16)
        entropy_input = b'0ebf2b35e3bb324759439b95a288061f'
        nonce = b'85a82c13cc42d712'
        personalization_string = b''
        expected_key1 = b'0ac60944e77912f6754c88d872d95382'
        expected_V1 = b'26af8b1144518defebd180df7673bfa3'
        reseed_entropy = b'dffb5d118bea701d8851b32c87eff01c'
        reseed_additional_input = b'a5381920805718f3f6b30661011a575d'
        expected_key2 = b'82e1a870e8f6758daa86f3245ce447a7'
        expected_V2 = b'5a992a64423260748d2eb914382a4426'
        additional_input1 = b'62901ff5dba574f53e13c6a62f89a292'
        expected_key3 = b'a23e50b64a282eb01c5c22b30bc005cc'
        expected_V3 = b'8c0823adcc170af64e921af67e365822'
        additional_input2 = b'f1d5092bbb3fdf50ca79f3d8b76ca793'
        expected_bits = b'0f248aa875fa2c12d5411ddcd3fb5b466e14d92bab2e024eed612e988cf50db1a7545df09f886d516da5e021124dfc80f606fe08a6653764abbcfa04575fb0c0'
        expected_key4 = b'3d103fc0f1ca3a4e62ae4b65fe369fdc'
        expected_V4 = b'3e01f9dbbb380f7d7f0f916d98ce087b'

        drbg._CTRDRBG__Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._CTRDRBG__Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._CTRDRBG__Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._CTRDRBG__Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)

        drbg = CTRDRBG(AES, 16)
        entropy_input = b'13fa3e445aa961eefcf6016e499f559f'
        nonce = b'30dc8d2604a56005'
        personalization_string = b'da2064c659de89b4f0cf658d4354c280'
        expected_key1 = b'29c9f6a822edda86c5feddc209cff346'
        expected_V1 = b'3c9f14e18d632c2cc6b5a1c7816753cc'
        reseed_entropy = b'0dd9fb5e7a47e28cd49297a6c13d9fa5'
        reseed_additional_input = b''
        expected_key2 = b'7ada77416d9fc4e119c261606695b5ca'
        expected_V2 = b'fd341ed14d37a5b4142b19f135992c40'
        additional_input1 = b''
        expected_key3 = b'0fd1e335c84a96a51a5343c4ed571bac'
        expected_V3 = b'237b7a131859bf2189699a521473e803'
        additional_input2 = b''
        expected_bits = b'659e9210052d6c5b5fd5e49c7f6bb534a53e95f31df0eca7b9968e2cf3d5fe7b4d20b69726db5e2c8a80e8b6f60eee71074a9fcd264320b1c533af92c823ac7a'
        expected_key4 = b'cd23de3390f9f5749eddc2b5b3ed3745'
        expected_V4 = b'60d5a70c749938bb5890ab88209338c7'

        drbg._CTRDRBG__Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._CTRDRBG__Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._CTRDRBG__Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._CTRDRBG__Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)

        drbg = CTRDRBG(AES, 16)
        entropy_input = b'e9095c1899e1ea7dbd867d915d8e3def'
        nonce = b'cea157889daa5c09'
        personalization_string = b'b9ae881d60b2445330d1aa2d49edb168'
        expected_key1 = b'8b25c49163f470b60ed2f019754f7b03'
        expected_V1 = b'f4119419ff363113af1e0e17987fecf1'
        reseed_entropy = b'3c66906419047d58f47ae788c49c7a69'
        reseed_additional_input = b'b0190579cc71c2142e2b4b147b4f0149'
        expected_key2 = b'1b533c65bef82b055a909a7909b06fdc'
        expected_V2 = b'86f6549c778cba87d7b6a95e7a86493a'
        additional_input1 = b'b2b478915253c784e3aed97b26cbc9e5'
        expected_key3 = b'1fccb93be772accd7016954667571dfc'
        expected_V3 = b'b982544aa5983805e54bb614052bf41c'
        additional_input2 = b'd2419fcce3643bb49cb7ad93ec09c769'
        expected_bits = b'06410639613584b3b1455919b2e9df5cb3c190c668a0ab473da4e715f81e4472b57afde082727090e3a0d07829ac71850debea34cf0f2899fc3b15dab84180e4'
        expected_key4 = b'11d3476dd8db5193be4c6f39f0492fb7'
        expected_V4 = b'11f3f91a8635f8e42268b5b5280289ea'

        drbg._CTRDRBG__Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._CTRDRBG__Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._CTRDRBG__Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._CTRDRBG__Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)

        drbg = CTRDRBG(AES, 16)
        entropy_input = b'845229e42c4b39c41573544fca838c2f'
        nonce = b'bcb23a5b7b280c41'
        personalization_string = b''
        expected_key1 = b'a180f594c26a3b89a092774549ecc113'
        expected_V1 = b'3f2e7420e3eebc113bb4f2c2b04d7d6e'
        reseed_entropy = b'e549f5815ad32953b115b8da6d2c3dc9'
        reseed_additional_input = b''
        expected_key2 = b'e5cd6e9e14490f4b80e3398bcf618b78'
        expected_V2 = b'4b3f764e72fa60c4b8c04cdadc903a68'
        additional_input1 = b''
        expected_key3 = b'31720abbb6dfd7cfb2f462f1f11d2bf1'
        expected_V3 = b'6ec5f9d2992eda6e99e803cfa6548067'
        additional_input2 = b''
        expected_bits = b'45338bb67d2731c9f62ead904a61eb816f93efe0605fb4495f92521d9553adfc5c1b0230216d4c2a384f7ae162ff6319fbdc4e1108446f3372fb6ba5cd6de21e'
        expected_key4 = b'4dc24b8068d75b8b3675793c3cb9c994'
        expected_V4 = b'596dc51e5a926ddbb3249489dc260af7'

        drbg._CTRDRBG__Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._CTRDRBG__Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._CTRDRBG__Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._CTRDRBG__Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)

        drbg = CTRDRBG(AES, 16)
        entropy_input = b'34d0f9f714d1539a298b21d3ea188d0e'
        nonce = b'f2ff4bd5f6cf7812'
        personalization_string = b''
        expected_key1 = b'd0f4f464516d43bc86ac72d2b4cc0d8d'
        expected_V1 = b'e2394fd68829153fb8f35677ac7b0b4b'
        reseed_entropy = b'cd44f41dc3fd07d88500b4084a65a9a0'
        reseed_additional_input = b'19c3b70ba950ac8535a4b54e1176e7e1'
        expected_key2 = b'b3c219c446a5ef3def3d66f02f458b4a'
        expected_V2 = b'3b31174da4a76b5b5e16df9d2f760be7'
        additional_input1 = b'2335699d1e4dc4f7781375750fd6dd86'
        expected_key3 = b'860f4e4b928ce46b216995ba15022eb8'
        expected_V3 = b'ac46b1d63125e2fa93ebd965f335eb70'
        additional_input2 = b'25a84ee746665d8c50b0d672445a9f04'
        expected_bits = b'064054ac13c9daab5906b648314979376063508bba8721fff6fedc452219081f6fe03f7cff48f6a582dfe33ca7e57644af2088fd6774dfa59cb93c1160edf8b3'
        expected_key4 = b'2af7529a51ea7e0e281bebed3c44a706'
        expected_V4 = b'9495474f5654b545544d0824c4023df2'

        drbg._CTRDRBG__Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._CTRDRBG__Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._CTRDRBG__Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._CTRDRBG__Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)

        drbg = CTRDRBG(AES, 16)
        entropy_input = b'ae5a2f9726ea953e4ec057c4c96ddd83'
        nonce = b'7fe815f735253bf2'
        personalization_string = b'd4914e8870c298365c8c5df216d259f3'
        expected_key1 = b'5195c41c491d1e748ca7161fac57e36e'
        expected_V1 = b'456204a699790abf5ce4309abd506f6e'
        reseed_entropy = b'2cf2fad8c59c50508608555549cd611e'
        reseed_additional_input = b''
        expected_key2 = b'51b8ba836792ff066f7d7f52bc58c593'
        expected_V2 = b'41aa4eab14e9f5b72a4ab326db641a8e'
        additional_input1 = b''
        expected_key3 = b'ad8b14cbf21dddc6d571aa90b305ed63'
        expected_V3 = b'ea81dc23a6f9e3fb4d91a2ecc3f2824b'
        additional_input2 = b''
        expected_bits = b'f9120eaa71e3d8543333cbd0a83b46ec86a22200878616106c866e13a8cbd646915ad81c7a11aed8396a25f98b324b5352eaffd501fdc9920b5353590eb0409f'
        expected_key4 = b'7b2385314488218c599cf9c7289a4ec0'
        expected_V4 = b'44fd19d0fecb38c817a625f0b82ae00d'

        drbg._CTRDRBG__Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._CTRDRBG__Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._CTRDRBG__Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._CTRDRBG__Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)

        drbg = CTRDRBG(AES, 16)
        entropy_input = b'b7025264dca8576bd52a26c2d64b5011'
        nonce = b'e59d54d2c03032cd'
        personalization_string = b'801f88c61c577fa16134053d07bf6f0f'
        expected_key1 = b'3852cdaec9032bb0b1562012684eb3d3'
        expected_V1 = b'9e7a5dc60da8e53d38b6a3c412c9169a'
        reseed_entropy = b'91ae03a1b4b4316611094373f9349a57'
        reseed_additional_input = b'652f24f936551b0bbeb3e829dd1ec9ad'
        expected_key2 = b'1c41ab19ffd10b871cc1d2d5b2adfb60'
        expected_V2 = b'2c44496473e639ac66b0d9ae8d347bdf'
        additional_input1 = b'c07d36375b0ba8e7d9bd7e9f53e2d98c'
        expected_key3 = b'4f8fe810ccaabf2bfa5fff2c1c786375'
        expected_V3 = b'a7fba30c7aa0b0ba4236e879aeaeea2d'
        additional_input2 = b'209953abe850459d83e5ddd15d21505b'
        expected_bits = b'4b153e0ad2e8d26ea0517290de365e3e5bbebf6e76002b3e8bbd4ee9eddef8cbc9c4dc85ace21d8217ef25e6883429c16321a458b50e6c15acc6d5324b55e5f3'
        expected_key4 = b'65f9613aeed126e45a99396e5b9b81fa'
        expected_V4 = b'006726b9af0324b60edf1fc485662b22'

        drbg._CTRDRBG__Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._CTRDRBG__Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._CTRDRBG__Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._CTRDRBG__Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)

        drbg = CTRDRBG(AES, 16)
        entropy_input = b'b25e5c411c47c68711f62a1c95c6094d'
        nonce = b'f49dca3c2cd31643'
        personalization_string = b''
        expected_key1 = b'ea552371bf19f334bb1465ab43ae94df'
        expected_V1 = b'6abbda6273976c123898477126c7b0cb'
        reseed_entropy = b'84806941378019ab90b1e845f1b4afa9'
        reseed_additional_input = b''
        expected_key2 = b'5de9e3e05d15be8ba1fa08711b1039fd'
        expected_V2 = b'9386a8e8d774e936d9da03ac9f0ad193'
        additional_input1 = b''
        expected_key3 = b'f1e079d80a4e92c1a88aaa343b53218b'
        expected_V3 = b'9e6fd58f87d0e0f42af0e9b3b88015ae'
        additional_input2 = b''
        expected_bits = b'25e548218a2d851d596b02ed1c18acea5c5abbf438fb838ef4762f736eb89fc87068e1455c6ac32d162dc32e543cf5dff09b9d3a19d73b0dd25c4e3fbd0b9309'
        expected_key4 = b'8f9802dbf93eb8a01fc9c5910a38bbc9'
        expected_V4 = b'31530077ae8880888f09459739be67d0'

        drbg._CTRDRBG__Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._CTRDRBG__Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._CTRDRBG__Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._CTRDRBG__Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)

        drbg = CTRDRBG(AES, 16)
        entropy_input = b'096af1704bcab313f8a4e9a2b1ed506e'
        nonce = b'58f0eb1375a0bd20'
        personalization_string = b''
        expected_key1 = b'a3baa009a72f4df94168172a50f506fb'
        expected_V1 = b'1ce312dac40de350dff47d1291d30069'
        reseed_entropy = b'4b5579cd548bf9eaf3f175459613f3c8'
        reseed_additional_input = b'2f233b8d0124b7a0ac81cee2ea1e7ef4'
        expected_key2 = b'aa666a45668220ff730c9c2bee3ec16a'
        expected_V2 = b'c68975279f39119792338e5cba7e028d'
        additional_input1 = b'19f8dbdcc77851f36b4005908620e403'
        expected_key3 = b'024ee3b6ecd08b4a9d2e570addae5daf'
        expected_V3 = b'd3968ed11a0ae4561bbd7647e04300f3'
        additional_input2 = b'eb89422293b9c9aa20a50c429ebdad6e'
        expected_bits = b'824451fd9819ef4e300ea6eaa1d20512fad1a6cea43c47a92dc50756b5917b848887e705b17d717815a5f6c3bbc0f4b3e1b392519e5e7147da126fd0c58a25bd'
        expected_key4 = b'9e280dde976c775933c1d47e74d15cb1'
        expected_V4 = b'85896b908f3d63b7ff5853143f652f7d'

        drbg._CTRDRBG__Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._CTRDRBG__Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._CTRDRBG__Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._CTRDRBG__Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)

        drbg = CTRDRBG(AES, 16)
        entropy_input = b'81052d3322a260fcf3339b53f6cf5d6d'
        nonce = b'57303972ab58f064'
        personalization_string = b'c3cee8564d8bb2fb8efe6b16aa2616a6'
        expected_key1 = b'ca02b6e2ac0c1ef7a52120a17a9384d6'
        expected_V1 = b'2b9c0f3c66dd0dbf641fc42c7567a3dd'
        reseed_entropy = b'c9b103f3779aa63e379841b714196cf6'
        reseed_additional_input = b''
        expected_key2 = b'03b9fd298b834189e3fe20f2b3172197'
        expected_V2 = b'82af4f90f3bfe11a6c1326dc2957715b'
        additional_input1 = b''
        expected_key3 = b'd2f105dcb9a79f46c8fa7e28157b6f36'
        expected_V3 = b'dee52d04d535b008aa43eb04cb7adb81'
        additional_input2 = b''
        expected_bits = b'd53712482c2b3336403c40aae156203c5859a6b3fae4b553e72b8a6687c0152bbdafe4099439e197e5d60f8e602e5b550aeb7387a4347ecde6e3a04288390f13'
        expected_key4 = b'de7cd3939522a9d6e7feaebeef43308d'
        expected_V4 = b'7c43329416dd9bb9c9e376c4c05e16ab'

        drbg._CTRDRBG__Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._CTRDRBG__Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._CTRDRBG__Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._CTRDRBG__Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)

        drbg = CTRDRBG(AES, 16)
        entropy_input = b'e796b728ec69cf79f97eaa2c06e7187f'
        nonce = b'3568f011c282c01d'
        personalization_string = b'b5ae693192ff057e682a629b84b8feec'
        expected_key1 = b'88e3c2863755ba00ae20f6b6cd72011a'
        expected_V1 = b'de8f801d3a6fdace09da6d05343820b4'
        reseed_entropy = b'31c4db5713e08e4e8cfbf777b9621a04'
        reseed_additional_input = b'b6997617e4e2c94d8a3bf3c61439a55e'
        expected_key2 = b'8cb85b6e35038ddbc7289ecdd348a467'
        expected_V2 = b'2b3e5bcfd5f912daf09fffad648a72c9'
        additional_input1 = b'c3998f9edd938286d7fad2cc75963fdd'
        expected_key3 = b'a91566ef468c6683a4f3abe5b8d485f9'
        expected_V3 = b'04e6d56ddcb15751a4231ec7dc9287f5'
        additional_input2 = b'648fc7360ae27002e1aa77d85895b89e'
        expected_bits = b'6ce1eb64fdca9fd3b3ef61913cc1c214f93bca0e515d0514fa488d8af529f49892bb7cd7fbf584eb020fd8cb2af9e6dbfce8a8a3439be85d5cc4de7640b4ef7d'
        expected_key4 = b'ad3921ed4d1f3cf485ebb0b0df89ab96'
        expected_V4 = b'5bcd6bafd744a764eb10c6034ea381d2'

        drbg._CTRDRBG__Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._CTRDRBG__Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._CTRDRBG__Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._CTRDRBG__Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)


    def test_aes192_df(self):
        '''Test aes192-ctr-drbg with derivation function'''
        drbg = CTRDRBG(AES, 24)
        entropy_input = b'b11d8b104a7ced9b9f37e5d92ad3dfcbb817552b1ae88f6a'
        nonce = b'017510f270c66586a51313eadc32b07e'
        personalization_string = b''
        expected_key1 = b'b9b3d73bc0c784a7d78db344109707c73abbff7dc2dfa864'
        expected_V1 = b'9e5767ab537fe663c71e4054ba618c8d'
        reseed_entropy = b'6d14cfb36f30c9c1a1ba0e0a32c2f99d1b47f219a3a8ac14'
        reseed_additional_input = b''
        expected_key2 = b'3e18d4984d454e5f986e49bfa7a569dab3667ece8130cba1'
        expected_V2 = b'c8563c5a4adc3b579f79f898c4b69854'
        additional_input1 = b''
        expected_key3 = b'b42a24cbb9e8c014bb65350afa28a67b273a41e599bde5b8'
        expected_V3 = b'087a3112e191f60619acae2a556f333b'
        additional_input2 = b''
        expected_bits = b'53fbba563ae014ebc080767aab8452a9f36ce40bbf68f1a12dc0a6388c870c8dfa4250526cbc8c983fee6449903c6bd7c2c02e327680a66b464267edbc4e6797'
        expected_key4 = b'1f5e987ac2259b7072867e4ae59167094d0162111062f6f8'
        expected_V4 = b'84f344f8277841e920464ca475b10276'

        drbg._CTRDRBG__Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._CTRDRBG__Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._CTRDRBG__Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._CTRDRBG__Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)

    def test_aes256_df(self):
        '''Test aes256-ctr-drbg with derivation function'''
        drbg = CTRDRBG(AES, 32)
        entropy_input = b'2d4c9f46b981c6a0b2b5d8c69391e569ff13851437ebc0fc00d616340252fed5'
        nonce = b'0bf814b411f65ec4866be1abb59d3c32'
        personalization_string = b''
        expected_key1 = b'd64160c3e965f377caef625c7eb21dd37728bcf84bfc23b92e267611feaffda8'
        expected_V1 = b'446ce986bd722ad1a514ebb7d274ec99'
        reseed_entropy = b'93500fae4fa32b86033b7a7bac9d37e710dcc67ca266bc8607d665937766d207'
        reseed_additional_input = b''
        expected_key2 = b'50d9feb33fc77303b83232b7deded04f1bfa4afaa937712f88458d6b64c046c5'
        expected_V2 = b'0b8e38a54036f1ba80a2880d4f17bb09'
        additional_input1 = b''
        expected_key3 = b'a2203a6f082ecdc0cd38f0b3b19f1a8cd6a5f110a13bb488c1e70f9f95a93024'
        expected_V3 = b'84b0a849c5459e27fe7f8c5db26fa13d'
        additional_input2 = b''
        expected_bits = b'322dd28670e75c0ea638f3cb68d6a9d6e50ddfd052b772a7b1d78263a7b8978b6740c2b65a9550c3a76325866fa97e16d74006bc96f26249b9f0a90d076f08e5'
        expected_key4 = b'de721178a341a85eb54a2f7e2b3cd4bcc201417e739eb183fa958f9af8535b2c'
        expected_V4 = b'de67dd5f9a431fc46dd1825cd1a2bff3'

        drbg._CTRDRBG__Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._CTRDRBG__Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._CTRDRBG__Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._CTRDRBG__Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)


        
if __name__ == "__main__":
    unittest.main()