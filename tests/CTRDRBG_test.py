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
        
        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
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

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
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

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
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

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
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

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
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

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
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

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
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

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
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

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
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

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
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

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
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

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
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

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
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

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
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

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
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

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)

        drbg = CTRDRBG(AES, 24)
        entropy_input = b'3a09c9cc5e01f152ea2ed3021d49b4d6386aa6f04521ebde'
        nonce = b'490bd4ee628cf9615035543e70fce4e2'
        personalization_string = b''
        expected_key1 = b'a4283dc9450ac97bf22c387082e3816728243473cedaa2af'
        expected_V1 = b'59a45ccbc3864f79b896c30d4a231d46'
        reseed_entropy = b'df06e5668d41a6fa7660aef477eff7a0ffc0542c1cd406d5'
        reseed_additional_input = b'59b8c26626aab69e462752722f19450d12e2c0e959882d4d06ef4177e396855d'
        expected_key2 = b'9c4d7784fe341619e21f2535d404866df3b75e9a7940d471'
        expected_V2 = b'5857d49a1552923931926dca1682fbc2'
        additional_input1 = b'28e57a9128e479985cce391e98127fd126f37ad0f317fd5f97b8c18e762f360b'
        expected_key3 = b'6a8fddde995255f89ea3c9454cc481045ff0e16ce5a34693'
        expected_V3 = b'bb8ed7bcbe1203be861b8e6570fe116b'
        additional_input2 = b'd488672b52e867816178369f542190685bbe8672720c1943d8a4378cc9b9dd0c'
        expected_bits = b'5c233e2850e4981bab0f6513a76ca2c9f9f97b89b7fedd3d9aaffecf305d89fd5306cf24715895ad9ba7dac8c389fd87f95b4973003150871fa281e962f270cb'
        expected_key4 = b'5dec9ad1f5f3d0e7bb59ae581097a3f616e443e4f5bd804a'
        expected_V4 = b'1cf82a0638c421bb43401943498d0f88'

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)

        drbg = CTRDRBG(AES, 24)
        entropy_input = b'35811473d105a6ae332bf72aa98a443ba97da55badb2e3c3'
        nonce = b'385bd442b5b7210c2d66109f88ac1ed1'
        personalization_string = b'16ed4ee59401550c67cdab99620257e54cfc7aa312c6814f81352123e4a28f11'
        expected_key1 = b'156ec65bfa898955b50c1382560ceeb381032106f33e54fd'
        expected_V1 = b'647843cb184a5b6cf7f20bbfce36fa08'
        reseed_entropy = b'a835e0140b52ae14df3343b65b110192baafd17ec2bcb10a'
        reseed_additional_input = b''
        expected_key2 = b'8b68106fb5f98280e6dd01769a85e4a2ac520df6c365a4b5'
        expected_V2 = b'bfbe10d329dd00466bff445cb61b00af'
        additional_input1 = b''
        expected_key3 = b'14b7cde98f88f8ee4e0f0a384a6c67f8229fd83621cf4641'
        expected_V3 = b'0cdc96325f2e28d2bf5ffb95476873c3'
        additional_input2 = b''
        expected_bits = b'4b8afb7c20bf941db7fb2cac02b46a45313334c04034b7e411b3607e19fc921dca47f19c5877e92086547cc6f1158ca4cfd62001f7e0f3af8a62e3c9888bf9ad'
        expected_key4 = b'4daf44235f486b895251f0cfd83af4ddd16df913dde039cb'
        expected_V4 = b'a44c4ceb53c82f65d6b4bbb9ed157e4c'

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)

        drbg = CTRDRBG(AES, 24)
        entropy_input = b'c4b1e6a99587eacd7ec8517f40f9433ca432cea8686433f0'
        nonce = b'd03a29e548e58ca7cbf0ac707b1464e3'
        personalization_string = b'0daaead21779b2a428d2b7fb12d9ab8316899edbe26b5460de1549c99e4781c9'
        expected_key1 = b'4ca21c47704c6a86cb6fafa1b77e14b860b76e53c18ee305'
        expected_V1 = b'e037477b43c7f08b53191f332e2365fa'
        reseed_entropy = b'2229144c1b4efb79ab5fe079cda26bc33acbb2a0a87f642c'
        reseed_additional_input = b'f116a683ca485fda846a598b8d9b079e78c2828286ad530bf01f693cc8af9f84'
        expected_key2 = b'08251c8316ea37fe0c8a4f67979d162ee3047ef8e2b1f4fd'
        expected_V2 = b'720adaef1786017a67880ca4bc98f9e1'
        additional_input1 = b'7c89de353298935bd26aa18517355313df0630da5f45ea0240e809179363080b'
        expected_key3 = b'a8c80c088b7b244df52d413d66c1cfd8920ada71c041175f'
        expected_V3 = b'301b9d734b7793cf7979fc47b42d949b'
        additional_input2 = b'e978b8fe56afc908bed129a46d57a8698d66034d4dbcc7aba3a33d5796fb7559'
        expected_bits = b'8ce7e9589c2975fd6989a450aa65da9114e515777c97351da037ccb72d4987eb69c680411724ed602e6ac76cd2d085725616c92777a4664d43a59c3ae9946134'
        expected_key4 = b'607900261bf8088caf189ee144a8b79cfe3503d47245e7ea'
        expected_V4 = b'e8654266617de1e197e522fdd8c297ad'

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)


        drbg = CTRDRBG(AES, 24)
        entropy_input = b'ff25661b6b585c5a31217a9b5c20a6e307f70b126fda2e25'
        nonce = b'1be8f51afebd48145541603df92e5d0d'
        personalization_string = b''
        expected_key1 = b'284a29d10393b1da8bc5052a3cc1cc144f26cc96998f9647'
        expected_V1 = b'3fc3e3e26dd363dad4b14b3146171f72'
        reseed_entropy = b'29855dfe13480058562d337e16ae0c8753cc4eb5420c8825'
        reseed_additional_input = b''
        expected_key2 = b'924f1f5a1eaf0ea25808b02d364758c2e93c437939589901'
        expected_V2 = b'a3bfb1ad964b08fe8aafd24d72dbe737'
        additional_input1 = b''
        expected_key3 = b'f206d02199b5237662ddb2c9949d6c976909f3deb32fbcfb'
        expected_V3 = b'491f8f2a846c8efd164599e6a55a3c35'
        additional_input2 = b''
        expected_bits = b'8607c9d784548f2f37f2616b244e9f27a30092df9424c47b3464862e675f03d4ec6cd5ff79f9f4a5d388a603e7495d39477955460ac2ee0c2ce4d3d834ef5174'
        expected_key4 = b'6b282d7d6989f7892f44551f8110b2575f1c18301cb0bb48'
        expected_V4 = b'd5a4cb9286847f5b2054d4b7a24cc597'

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)

        drbg = CTRDRBG(AES, 24)
        entropy_input = b'1a1a4a3bec7bbdf98f53592418d903aed3e114a7f0114563'
        nonce = b'f0b7b7424f108f6db6cfcbfd2d40a5b6'
        personalization_string = b''
        expected_key1 = b'a690e27c59f4777641e82b45e0c1a36a8e1405034dc21789'
        expected_V1 = b'7919919112554707c26434c4e72cac09'
        reseed_entropy = b'6f78afb310ee0dae6732e0ed979c63a3ad8792333662f624'
        reseed_additional_input = b'9f050542a1097f935c68f373824ab9cac17827badbe07cf9dee48af33a31991f'
        expected_key2 = b'79f5e6ed34311b5a0274cb4888114e268a021bb65b6c1f4a'
        expected_V2 = b'90c43c6557971a10857379ddd1875d5f'
        additional_input1 = b'38d68cc7c89866d8d2708a215776af154b3c082d550c555e1aaa5a72ef2f5be0'
        expected_key3 = b'12c455d7b3e4e97bef488b5d57642cdd09410038a545b573'
        expected_V3 = b'd233d3a05cf2c0dbb79599df37f2889b'
        additional_input2 = b'40f8314489c3258dd4b13ba59b7e8f3ec95db00829a2353a08cd758b4989c053'
        expected_bits = b'15cc0ce77ee55ca4d72b2e75c32887694dcac97f7d261fbe9ee1d09970b7b0313fb318630afa4ac369b9979c22647f60a3799739942d7808d4fbb14f7ac49037'
        expected_key4 = b'50e8507526506e55a370a29d74bca06be7ed646422d2573d'
        expected_V4 = b'37b5fc94b0993888ed2dcd075afeb8a8'

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)


        drbg = CTRDRBG(AES, 24)
        entropy_input = b'a7118c155d69705519f1a56f3f524efcb32aeb32a98ae81a'
        nonce = b'0207f3534f118c71cc11f181f5c6fc0f'
        personalization_string = b'8d11491c83dede012f271c263f8d4246c3efdfdd288710c67e979f4fbbc864cd'
        expected_key1 = b'600ac5103eb9897ab12a3faacd9a8c5e439a5d0602d282ce'
        expected_V1 = b'dd90413f1d76411ef712d1e7d406483d'
        reseed_entropy = b'66abef82f794f35ed94282deef0dfc228ca5ec83257e81d7'
        reseed_additional_input = b''
        expected_key2 = b'8a41d687e1a2b94ba7f1596a88cf9a496e52f737c65f6521'
        expected_V2 = b'2372668b73de781fcc2b5087858bd4d1'
        additional_input1 = b''
        expected_key3 = b'fa958850fc65a1615079c4ad7f18eb680f4a1443473d6c4b'
        expected_V3 = b'7b18c86979a740c177b7ab36b49e0fff'
        additional_input2 = b''
        expected_bits = b'5ddd46baf5c6a5e30943c5bda12f5db8ec19c537f1702afea31292b4a9a8d425763a9f92b36f616f4ffdb9160774d8776433b7c05c46fe6f66c403736a044be5'
        expected_key4 = b'5d95380f26b49dde8ba131dbb1891d7d09b478858336d201'
        expected_V4 = b'c33bb1ea34b7ba23c4698c17ef71533d'

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)
        
        
        drbg = CTRDRBG(AES, 24)
        entropy_input = b'e89d54f816f802a1256fb9c9c239887ebcf6c64d68557940'
        nonce = b'4f022171cace97c081df28cf425d0956'
        personalization_string = b'53cc6834e9fcbb3eca6880a0ae90d3a7760aaf5a1c0d074b092b9f937031a68a'
        expected_key1 = b'5bb8156417add46aa822b0bb108a7384b52e550a25383299'
        expected_V1 = b'156582ce38489361bbea46a70f9697c1'
        reseed_entropy = b'6e5c51ab74c8552c16be257bd1626df3af7926be67b62c0c'
        reseed_additional_input = b'73972f57c4a3e30a795d8c10ee801ef0f6c8be7f79fffb96b541d322ba7fd9cc'
        expected_key2 = b'540c133031ba04197135509a37cbe0cc076a651c76d74bd5'
        expected_V2 = b'4f94da48d690eeba5309df7054cf2cec'
        additional_input1 = b'ece1b64c51bb97ee3e72c1c7d4caa3a3d48b6410914240ca033f35ed5b898331'
        expected_key3 = b'8b3da69525d4d105537bcb348597b9cfbaa60348a690e6f0'
        expected_V3 = b'165f23d6ad1ae2561b906eb39e6616a6'
        additional_input2 = b'e7d5dabd56f92029a09cf17cd64aaad8ba6b4d72dbfa07003cd4eafd83c170e5'
        expected_bits = b'b0e03cef0fbbfaec5754a0a2c1b396a7df6e44df6ac0554ae19d77e6fbe4f0136483380cbb81568c1c1f0ae7fc02758d8d1e796866b7a6a6d173ecc016b81f26'
        expected_key4 = b'9831c9c5ad73bf8aac03400c35c3a81acc97143f73b97116'
        expected_V4 = b'd17f89705ebb02a625131c246a3d209e'

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)


        drbg = CTRDRBG(AES, 24)
        entropy_input = b'8516a8788f6a58ddadedf8175aa289a2bc310c07ef0d0d82'
        nonce = b'5db7be3e068300b25bd94974475e58f5'
        personalization_string = b''
        expected_key1 = b'f487699d74200a488b7f106be3501a955299e0e881ecf084'
        expected_V1 = b'47d4ccf5a11bd83847083b235b6b8d35'
        reseed_entropy = b'423b9912e0e6fbef38642c46df7dbaee2197173352f15267'
        reseed_additional_input = b''
        expected_key2 = b'ee9e9068247068a35d77e5a432125247a9ad511024d37736'
        expected_V2 = b'4782bbda7b687afd4ccb20055e27fc4d'
        additional_input1 = b''
        expected_key3 = b'0074df18f6bcc0627779b558f1adc3aa6afd93b719c2f66c'
        expected_V3 = b'7f931c4f50d8e110e98a7599a689521a'
        additional_input2 = b''
        expected_bits = b'c612ffdb9ea6e20901e8f58c180dc4d79b9a25bb51ffb75d7b4076f8f6791c232eeaabb2e43f309155e53810ae795eba667124a9f697f6bb356785edd9ff3959'
        expected_key4 = b'4c0288a89e2eb41469143c315ebb6ba9813c535d126afa83'
        expected_V4 = b'fb257fad47a053d21d03b36bc95b6d9b'

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
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

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)
        
        
        drbg = CTRDRBG(AES, 32)
        entropy_input = b'6f60f0f9d486bc23e1223b934e61c0c78ae9232fa2e9a87c6dacd447c3f10e9e'
        nonce = b'401e3f87762fa8a14ab232ccb8480a2f'
        personalization_string = b''
        expected_key1 = b'6d9aa2e029466438d3e4c22530bd071dbe57b549b87370957b28da8ae083f8d6'
        expected_V1 = b'ee534dcfd9d2be3a3f9c65a6c5f599b0'
        reseed_entropy = b'350be52552a65a804a106543ebb7dd046cffae104e4e8b2f18936d564d3c1950'
        reseed_additional_input = b'7a3688adb1cfb6c03264e2762ece96bfe4daf9558fabf74d7fff203c08b4dd9f'
        expected_key2 = b'b5953178a900b2fcf052b5cbc1d882ea944da2965e84fef59c4919bb4d5c892d'
        expected_V2 = b'433725f6c4b8c662c3b2db4b75f38d86'
        additional_input1 = b'67cf4a56d081c53670f257c25557014cd5e8b0e919aa58f23d6861b10b00ea80'
        expected_key3 = b'b2b9e9f1ffcfd84c050445f93dfad90d6ca240494bbed5d44a0deb38fbaeb751'
        expected_V3 = b'2c342b2ab12bd3484e4660b8dd5f85eb'
        additional_input2 = b'648d4a229198b43f33dd7dd8426650be11c5656adcdf913bb3ee5eb49a2a3892'
        expected_bits = b'2d819fb9fee38bfc3f15a07ef0e183ff36db5d3184cea1d24e796ba103687415abe6d9f2c59a11931439a3d14f45fc3f4345f331a0675a3477eaf7cd89107e37'
        expected_key4 = b'770600434fe0af64e045f5530e2b9732da9e3b4c3af342994a4f1f7ee5c4144e'
        expected_V4 = b'a9729f842063b9464e74018c0ab30df3'

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)

        drbg = CTRDRBG(AES, 32)
        entropy_input = b'5bb14bec3a2e435acab8b891f075107df387902cb2cd996021b1a1245d4ea2b5'
        nonce = b'12ac7f444e247f770d2f4d0a65fdab4e'
        personalization_string = b'2e957d53cba5a6b9b8a2ce4369bb885c0931788015b9fe5ac3c01a7ec5eacd70'
        expected_key1 = b'0f7d80bc727ca13bbd82a951e44d8f237a5e54e59ca4b2a1055897ab600afed1'
        expected_V1 = b'afe78f607ce6cd120b7f41991979c157'
        reseed_entropy = b'19f30c84f6dbf1caf68cbec3d4bb90e5e8f5716eae8c1bbadaba99a2a2bd4eb2'
        reseed_additional_input = b''
        expected_key2 = b'88c5e72dfbd595fecf56b7d5742d80404c1f2457f3049550d2241ce5d12c0e3b'
        expected_V2 = b'228ed64284184eea0552f5374fdb163a'
        additional_input1 = b''
        expected_key3 = b'0a5a3c762cf84b5a108a6672fb3e5eb00e0e4412caa268c1391d8c1ac78caa1d'
        expected_V3 = b'9a62ed92b79c5f048638fb6690c6452c'
        additional_input2 = b''
        expected_bits = b'b7dd8ac2c5eaa97c779fe46cc793b9b1e7b940c318d3b531744b42856f298264e45f9a0aca5da93e7f34f0ebc0ed0ea32c009e3e03cf01320c9a839807575405'
        expected_key4 = b'af19f197191b229dbbd2c9ba8e38538e00ea59d52181fec6574998fcd2476478'
        expected_V4 = b'8c91ebe5697151aa97f3d04654db5131'

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)
        

        drbg = CTRDRBG(AES, 32)
        entropy_input = b'174b46250051a9e3d80c56ae7163dafe7e54481a56cafd3b8625f99bbb29c442'
        nonce = b'98ffd99c466e0e94a45da7e0e82dbc6b'
        personalization_string = b'7095268e99938b3e042734b9176c9aa051f00a5f8d2a89ada214b89beef18ebf'
        expected_key1 = b'2eef0ab3e7ee8e82a549eae68272a379af025ffbd3d0a62f1668ab3f6b2f8e07'
        expected_V1 = b'8bdcbbb8ed356c02e2dc805f461dbcf4'
        reseed_entropy = b'e88be1967c5503f65d23867bbc891bd679db03b4878663f6c877592df25f0d9a'
        reseed_additional_input = b'cdf6ad549e45b6aa5cd67d024931c33cd133d52d5ae500c3015020beb30da063'
        expected_key2 = b'695ec793a3c19e53e4cba9b2a4cd89320b6762273c8bef6f03ffdaa970df34da'
        expected_V2 = b'ea405f98e64399a587c560c3fb8ce8fa'
        additional_input1 = b'c7228e90c62f896a09e11684530102f926ec90a3255f6c21b857883c75800143'
        expected_key3 = b'6306bce4ccea9e9233662634f374b68adfde2394ddd8fb77e452293323d566dc'
        expected_V3 = b'429cb6dcefcf43e291e9672156788f50'
        additional_input2 = b'76a94f224178fe4cbf9e2b8acc53c9dc3e50bb613aac8936601453cda3293b17'
        expected_bits = b'1a6d8dbd642076d13916e5e23038b60b26061f13dd4e006277e0268698ffb2c87e453bae1251631ac90c701a9849d933995e8b0221fe9aca1985c546c2079027'
        expected_key4 = b'4e558b0df4e7427d7fdc8b8cef4c19021a831506d93c92f7394349d6081673c8'
        expected_V4 = b'128cd27a8721f1e7dbb1f982bc6146e5'

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)
        
        
        drbg = CTRDRBG(AES, 32)
        entropy_input = b'a89d08185b539a830b1e9b74c01f59e2b75bd2e2cbcf95c185a83a8069439e42'
        nonce = b'c675e3b634b075db09789e5d8a39c5e8'
        personalization_string = b''
        expected_key1 = b'98f25891464385602955af2e3ed1d7a057c852d4c8e6a025eac2623d44b2c3e4'
        expected_V1 = b'ea3bf51f2f6d59f3e58aad6a33d1026e'
        reseed_entropy = b'0ed8e63b823af5476dcb9702daf46185d3f4953df704749d3dea2fbe0c7a46dd'
        reseed_additional_input = b''
        expected_key2 = b'612a750b1de2a7692c2f07a65809a38507a871c8d5ba99b6538935e0d6be61a8'
        expected_V2 = b'd2801a70c49b9f6a3e8f3b1a20fba661'
        additional_input1 = b''
        expected_key3 = b'dc798cd4a4075577778d2106a32a218a9b2a8db08c013dca0ea14041f7a83a43'
        expected_V3 = b'dc49dfc410343166537d64f2419b3b0c'
        additional_input2 = b''
        expected_bits = b'61f1fb64c0668747d270d4fab17c34db3a69829ea08fe43ec359ae174ffb0caae8bcba3a4fffb5b29b900f0e2ef2394c39292bf295623f894617ce9500228bb4'
        expected_key4 = b'f232ba128666c6eddc169def395c9fc634206ef534f8c139f4d0f4fdf9d657a5'
        expected_V4 = b'2875b7691dd63fdca83f726006b48638'

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)
        

        drbg = CTRDRBG(AES, 32)
        entropy_input = b'44a690d590f443bca7abe4c20c70ddb0df0ee29ed23edfc1cbe923ae7a4eb6c7'
        nonce = b'334fc355f9f07459d8f014ebde24bcb6'
        personalization_string = b''
        expected_key1 = b'd8e0774339b8c657264a8e0cb1a12274a6327cfc5f0b7c0caf22afa504e7bdfb'
        expected_V1 = b'51f9db79f74640f803dd4bda5f471d6a'
        reseed_entropy = b'1bb49e9bad9fc94d363df01c02388af391f4564abd8cce10298875d2934df891'
        reseed_additional_input = b'0092b99efa09a6b30bb6f0d9fd5fded490e745c4be3fa5615b318444b5593db5'
        expected_key2 = b'2165c525b004a468958fd155809e945d9cd7d725d713aeb72c7fef1fb8304fc5'
        expected_V2 = b'99a53af6130f5ebff8f9c9dd1b07db11'
        additional_input1 = b'f5f698f0dd171c38d24a5bb3c5bf6115bf1af23c38517292e94dd7f576597db5'
        expected_key3 = b'd79258cad46014e4d44eefa9e71c8caad54ca205f8faa77b46f4ee8d62648e7f'
        expected_V3 = b'5f88621d1563e8e152b9703692b10a12'
        additional_input2 = b'2da719aa44a96910e73fcf27e46d8dbb1c7b5d82f5713a2980aada6cf2a45104'
        expected_bits = b'27a2fb7704a714e207fd31a796c4c053b0355a1599d47d201b1b5bb37f79cf32f9289bd263ac6bdd8e83cc451b3a3baa8f27cf3b5ba6a9a4a7d2d6ae607dbc22'
        expected_key4 = b'3bae369fc4e2e59d6b7b0b83359da33ab36a4c11611e215dcb06b2dac99e9fb0'
        expected_V4 = b'5bdd5280b24a68df396dc3590861257f'

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)

        drbg = CTRDRBG(AES, 32)
        entropy_input = b'4cfb218673346d9d50c922e49b0dfcd090adf04f5c3ba47327dfcd6fa63a785c'
        nonce = b'016962a7fd2787a24bf6be47ef3783f1'
        personalization_string = b'88eeb8e0e83bf3294bdacd6099ebe4bf55ecd9113f71e5ebcb4575f3d6a68a6b'
        expected_key1 = b'f647e591ce264f5e2f3db03d8393ac635805ed476ebd0c9d46fc80c0dd88aa1d'
        expected_V1 = b'c6282d4c705b80f349f1576577efa41f'
        reseed_entropy = b'b7ec46072363834a1b0133f2c23891db4f11a68651f23e3a8b1fdc03b192c7e7'
        reseed_additional_input = b''
        expected_key2 = b'b4936849a07439563a6dba604e2153f8d150dffe3a0c762883ec6011b2095d04'
        expected_V2 = b'da23a6f07fe66aea597288347d8a1eb2'
        additional_input1 = b''
        expected_key3 = b'a05c7cc4388a381cd93eb179c5e22fbed94ed567461067b74c88380523cf5919'
        expected_V3 = b'd9b6032d7c528abc071ae71ffbaa2ed7'
        additional_input2 = b''
        expected_bits = b'a55180a190bef3adaf28f6b795e9f1f3d6dfa1b27dd0467b0c75f5fa931e971475b27cae03a29654e2f40966ea33643040d1400fe677873af8097c1fe9f00298'
        expected_key4 = b'a2d85338ed69bf372a6886473307c1b9858cdc475ca5825ee39d3c1eb3073915'
        expected_V4 = b'6e49d379731c5cf5543b62a7cc041eec'

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)


        drbg = CTRDRBG(AES, 32)
        entropy_input = b'6c0ff37351e787d35805810750394854dfc7b3704cadea32593458e1ef67f2dc'
        nonce = b'f0d342f2cb1270ed3cc935b1d3059d0f'
        personalization_string = b'e1b95c7069bb22475d5a7a99fc8beedced73bbed785c73ce5663740c46568884'
        expected_key1 = b'30ddd58b91b78b28b718149df9f3fe3b6ccb2df03021199957a28884459fa04b'
        expected_V1 = b'a96460260762b03e0902db33b1925f9e'
        reseed_entropy = b'1140a47dbe3b89362922b375502300c7e7566224accac3ebdb99c8fa776594dd'
        reseed_additional_input = b'66ccb8ddaf0201a7f2f7fef04939f2c802e480e4acc1c3177571f34248bbfce1'
        expected_key2 = b'd65c82978955a51fa62a5a1a2252b8c53f1988102ce76e9aed440edc36dd0b6b'
        expected_V2 = b'2134d66008b4b3f28497f952915652a9'
        additional_input1 = b'53f74ba9d0eb69010cc4eda1da037c8e6056c1154248bcf4632b44d6a59811f1'
        expected_key3 = b'e921565b4d2e3b3f82d1f19fb4f4f5b0768d71f65e9781e10d760ac794f57266'
        expected_V3 = b'218ae15e1754fb1381d34886a8a28fe5'
        additional_input2 = b'1cdbb531803e7bcac8de8aaf9c3534184cf737c9ceda1a7a16056b0c53a828ff'
        expected_bits = b'743e9cb60389d649113a93e9ba3500adcff05193934602797c5a36084dc1b3f2db7c65d7b6425dbf3bb572239e8845a05b3ee5366b538a1010d4fe2a0919c1a9'
        expected_key4 = b'aa848b22bdf2dc7be73ed3cf165336bf312866cc3983d36ba8dc387be62ad64f'
        expected_V4 = b'72a3270ba3147a60a68ee688ccc048df'

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)

 
        drbg = CTRDRBG(AES, 32)
        entropy_input = b'830bdfd33486f26f4af9f2a699db1e49652635aed6984e04a0cea2c9a87e43d2'
        nonce = b'21ede5be36404c34b1b85c2d2369bf09'
        personalization_string = b''
        expected_key1 = b'78681a0122c5be8607d08a5c167904276b013698ae4e62d7a8f86438a4c011f5'
        expected_V1 = b'fbe2cf130885e85b2972429c4451b276'
        reseed_entropy = b'8c721957a6300794862a004574f98af9bbc074ecdde22becb081f360535f3f1f'
        reseed_additional_input = b''
        expected_key2 = b'5b8902234b465a75c1172fed17166860a836e2b1565de886c2e095a46601c7dc'
        expected_V2 = b'1f4d5129a0dd33ab1026fff21af9acec'
        additional_input1 = b''
        expected_key3 = b'a040a4c9a75f1adbd2034ed8197694cf46effde83e33fa098b2fa950d93f5e30'
        expected_V3 = b'bacecad0914ea52350adbc66ebe08178'
        additional_input2 = b''
        expected_bits = b'3f63eb5de3a13a3097e25399c3d9ed7d5e6591931461a851ba645bcffdd0c07f2b71cfbb8329bb1934971d1403dc68cafb0bd6ca4e4a6c28976ad5e8bb13a35f'
        expected_key4 = b'4aaaefc2f3a240c4a182d854d5a610148311a9f3801c562098db2aeaf0769ae5'
        expected_V4 = b'56a0100e0359dd990b7eaef48a93315e'

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)


        drbg = CTRDRBG(AES, 32)
        entropy_input = b'9f073580368ab5edea6d6d667bfcf36a0105982d53c7b7b05575964b9f32fdd6'
        nonce = b'4a08d6e7b53d7829266fd849aa2d576e'
        personalization_string = b''
        expected_key1 = b'1b5a62a9d0841042b49d1d1ca5ad3991d2c43e390dc276f736f2465337d28c11'
        expected_V1 = b'e193c1cb4aed59b3f5414cc5c2f972ea'
        reseed_entropy = b'09c11834d1a273d5c5d12ac71c11ff0daed3b520d62b8041cd608ba7853ac1a3'
        reseed_additional_input = b'e24426c159bde6e1f0c1ed20af189f155260a8f20a02da693df33ada4aba5c32'
        expected_key2 = b'9e0af69cf3324a3b90ee30c34b61a6c7846796be8a5f7746e88753b6c6e10d19'
        expected_V2 = b'bd2f206b932d870202ae806a5cac59f5'
        additional_input1 = b'9055b015aeed80a3edd5226c64331fd0a65f82e781dedc03453f5dcbb1a27032'
        expected_key3 = b'4b82acf4bcf72832ab61be886cff55d938acf81e108041df4138b94738238dac'
        expected_V3 = b'4be95cb7b14e77cb7c36c98b0025d73f'
        additional_input2 = b'b634353f5b713e1ce0778a6a19325a1a1deb02bcf1ccf1de5c2c2cb6d469e42f'
        expected_bits = b'43e7e62ffa98f436efa34b1fe0e4e633bdfe10fd20a2ab1c6f7d8f5ca551dcd14a8b9696e549b4e6fee4c6d69a890c6aa42468dad9c566aaaf164a9c81983f11'
        expected_key4 = b'39e81cafe867ba799d197dbf2b7ff6c1f6e949a866039d820b41cf3472a988d4'
        expected_V4 = b'a7f4f09c173d3ccd73a8adc3c8ea272f'

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)


        drbg = CTRDRBG(AES, 32)
        entropy_input = b'7fc5c67c1e8eaebf19be6463c9ee13825b1c63bd38e58ce73a776887d95ff920'
        nonce = b'36b6aac81c45458d48e3a1a342ff667c'
        personalization_string = b'2196680672e2c4e164059cde6d2fe91ba3c396cf4b61b5e23fb1667816f9bda4'
        expected_key1 = b'26f064dd58ef2df440f71fd19c08e8803e03371ae22640d561e3b85abb17d2ee'
        expected_V1 = b'5695f5765c167de521847f8267715ba5'
        reseed_entropy = b'114475d8eeb771a0d9bad451245f3633e709592442e5005845d0ebafed5f680d'
        reseed_additional_input = b''
        expected_key2 = b'903e07db349de08fd22c9a6587b3bf3095c1e4e3707a4ae4f87f7d5d8cb1cbe6'
        expected_V2 = b'5936b9574b18b48f70624c593ad6c1b5'
        additional_input1 = b''
        expected_key3 = b'f14ea0570f52067f3d63b1f3b30d7d58c5acc405c2065291780944260688f1c6'
        expected_V3 = b'355deadd96623350686cf941d731f4f7'
        additional_input2 = b''
        expected_bits = b'cc7c9020a9b11501440464e3c306d38262c45838da3a0dd26552ee7a9edd9fc382d3f7b187e9fb370be97d9bf43466a551e9738929f38697c738bf267b664984'
        expected_key4 = b'46f4a47c0af8792f5143fbf9e4f7705cfac03f11dcdeb16ed4ab95984878718a'
        expected_V4 = b'effd45c572161a9a4cf0be2497250ab0'

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)


        drbg = CTRDRBG(AES, 32)
        entropy_input = b'fafa5b9d43aefb062aff960c01d1f7439f8f00e5de1b2328c8ddf1dfc6cc5f33'
        nonce = b'6cf9c5925efd886cab50ce85bb078bd3'
        personalization_string = b'bfc8c5eb0e41077eb9fbb0aa82bed7a7692a3abf897f00a021897a0183d85901'
        expected_key1 = b'aec5ce9d48a8b70b2e7c722badd18996aef9933cd84418efe62598a8903941c4'
        expected_V1 = b'9c33f7dece699ac97a651affb3f44c50'
        reseed_entropy = b'234761b58f9f7935ed4e4201a876cf796465f90b94d885e8b724894a19a6723f'
        reseed_additional_input = b'43a4e484d147a9255299ebb89345f2a2b9f38bb58fd295d737e8ac2f4f02a676'
        expected_key2 = b'e4994b6e5a4bb2e78f5c71847d72d0d46a7df7e3e982a5054c0ac9f043117a34'
        expected_V2 = b'd7b79d761bd78519310d7bfa705afbe6'
        additional_input1 = b'0ce18400ccf510a38fe7e2da4af7d93874b1282d8aa49074b7de924adb40dc3e'
        expected_key3 = b'd5a75546d485ce93c416249a3d37b4f0b09d454df2835c2c939f0b31d0277bfa'
        expected_V3 = b'3222499247b088c0ecce8d10f56ab2de'
        additional_input2 = b'68742f4543d1a2506600f2ae8fb718decb2fa30b24cc5bd6d3daf0511a9d91e8'
        expected_bits = b'966db3b1c92715cb59ac23860d2b134b54112a99b116b8d498366c2926f1ccda76ba3f7d7c282d5edc1f664d22738a45d4bb2440e55b6fd92be89ca7c1ce875d'
        expected_key4 = b'9cab20432c12fdd589192ca9078010dd7f2548d13476154f90277d08807c3d40'
        expected_V4 = b'8ad9ae989097d5a99931265533fe7253'

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)
        

        drbg = CTRDRBG(AES, 32)
        entropy_input = b'd5559102cf8f234a89b6c48cbf473b1572a7d0c342d7b61adde3d6a0124d3991'
        nonce = b'5be948d054bb66e176b93fa848da0f51'
        personalization_string = b''
        expected_key1 = b'f7735e03e203103efe498ed9541bc816f4efc9c91c50f0f70ae480761a622387'
        expected_V1 = b'3b6746bdfd8200a92cc874b998bce5dc'
        reseed_entropy = b'8bd544ef239be98ff315261ad3a3e23a8400f1ebdcca65e0f46c7c661fc421a6'
        reseed_additional_input = b''
        expected_key2 = b'0e368d875b3e2a777d28b1f69c0a55ddcddf9a36eb75026884630c4ef35cee09'
        expected_V2 = b'ec6b56ea3acc93010736007b4412119c'
        additional_input1 = b''
        expected_key3 = b'c74cee37b3339bba5732aa384111f2978abb41d0606acc374a7e862c6bb91f98'
        expected_V3 = b'bb41e05a0f0fc7dda18fbc945d21a49a'
        additional_input2 = b''
        expected_bits = b'e1bdd0bdb4d51b010b111e9088df562d216ca7371409d729f95250e8100f9753a60099a49408bb0065f99d59dce5081bd67cebd54c2b21fbf35184f26d1c4706'
        expected_key4 = b'99caa9f7a7968668932013426c1b3460a4645fe98ef4a549601b375facf0dbba'
        expected_V4 = b'5b54e18570984267cd3f71cf87c02b4b'

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)


        drbg = CTRDRBG(AES, 32)
        entropy_input = b'a6e860414e2fe8d4740ea204b877c76b50280722c3b91863257434c75304dafe'
        nonce = b'8f12c9327d28e2c2741e4ad7e27bb124'
        personalization_string = b''
        expected_key1 = b'a580acb192aa41308143439acc7f37b14a1e64dcc7a2fb846a3d6b933ec7c9f3'
        expected_V1 = b'73d915c08b4d3c6d05d981e7eda21f76'
        reseed_entropy = b'c32e3b4cf97c06fab41b545870add8c3f98fa6751aab02988d2d34c95d199965'
        reseed_additional_input = b'f0d9a64fabbf346c871d7731e71586bcce748b08ff0726d68d54bfed27b10b27'
        expected_key2 = b'865bac05d369f9979adfd260b389c4ec68b0cb6051e9ef6499a8690b498234b5'
        expected_V2 = b'ee4f5e5ce5620d7a0d33e138ad5dbfea'
        additional_input1 = b'c72f45581a7973cb4148fb9e8eacfca0e513c40ab8925313b499b1b83a99e372'
        expected_key3 = b'0505868bf313811cb72e7b5775b3de4c2d892c1e047f8b4656f9a11d9d0da10d'
        expected_V3 = b'6ba020f997c1710ca6ff81df92de965a'
        additional_input2 = b'7dfacd72c084c324f721f03addbe72b646a4a723e78b5e401aef844cf2b91333'
        expected_bits = b'db2529862011f45d95918d843b7ef0d7ab18a6d6e3f0bcec109497502b68b5ed9ceae85514af51597e8479196d59190cda414e566ad638d39156351afbaeafd9'
        expected_key4 = b'f3496f0b9e090a52d822f2db2f73e621d353762b65b2ed16558c5036bacdf0f8'
        expected_V4 = b'52654a64f0e98464fc3037f7348313fc'

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)


        drbg = CTRDRBG(AES, 32)
        entropy_input = b'fbae3ee02105a8a2353bbe9d806829cf78c8c312c782abf1554c6646cc37a1e5'
        nonce = b'b0479900a404e8e79c5f2fd7819232b9'
        personalization_string = b'54909fafc8f70428892f8d32ed51e95672892192d3955409e89c53dc6980d0af'
        expected_key1 = b'b08542e63e5b64952011ae38db68a5dd0f0c87583779448fab6dcd8e756c6a70'
        expected_V1 = b'28a9de5b9b99e37bdb763ef0a20327b7'
        reseed_entropy = b'aab36c9fab8bea6b9deb701fdf565d51e7a18b389808f8b938375d76f8657842'
        reseed_additional_input = b''
        expected_key2 = b'3554cc4eaa463cdac4f6899c939b13e2848040362b9a0d23732746ed1c6a21de'
        expected_V2 = b'e4afda91ceb72c47581999455c4623b2'
        additional_input1 = b''
        expected_key3 = b'5d263ac452beb81b478253a8b8b3eee83547bb58ebe75c89d66672e0570e7b6f'
        expected_V3 = b'947b28932ec3f51a55e0a432f17fc5bb'
        additional_input2 = b''
        expected_bits = b'8d1700f1f632df3400af0cc91c4d3d11da034993df5043cefa49fbc01784ed78099eec91d09395084df325ba02cdbd5b1abc64f9e347d81ae091ec081fe27d4c'
        expected_key4 = b'52a9a4cab12e2f8e2094fabafb1cf078f086700d8d98dd679a767733635c8a33'
        expected_V4 = b'e2173d3edc0dd3ec91a1bd74a1fa9d48'

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)


        drbg = CTRDRBG(AES, 32)
        entropy_input = b'e2f75cf553035b3cb4d21e567ca5c203623d4a4b5885326f63ea61a020a4984e'
        nonce = b'a666ee4b26dae5897fc5e85c643fc630'
        personalization_string = b'19275bbd7a0109d8179334c55337bc0a3f5ac48cb8c4959c888c0b65f7ac9a84'
        expected_key1 = b'7778c4dab6a0945bb276c82b1a17525a9bf9f128153ea11b12514b8ea925d7ea'
        expected_V1 = b'f20cb02cc8917f1ffbf1b41827182067'
        reseed_entropy = b'f6672d022226b05db5d3c59c0da5b20a1be05ecabbd1744483ca4ce5571d93f4'
        reseed_additional_input = b'8c8f940af45aec864c8aa8be60b100f82bb9670c7e2a392a4ab6f4b20eefbbaa'
        expected_key2 = b'24343571d0cf186762a3eafa9107a1ed0c60885a8261b4a907fae7369510c42e'
        expected_V2 = b'16bf5a7afee786299d7c0b44375e70bb'
        additional_input1 = b'26b5f0dadc891e0b1b78878e7ae75aee843376c0968c54c12759c18def21d363'
        expected_key3 = b'f5d3d0da273749450d26fb333d81ac8b3f59f049abf3eb5a625394955f486130'
        expected_V3 = b'23f0a9d6741928dfd14d3823ec59207c'
        additional_input2 = b'ff6791f4d4b29996b0399d95a14a28b8e2e20787531d916e7ed2ec040bbd7c84'
        expected_bits = b'eb8f289bb05be84084840c3d2c9deea0245487a98d7e1a4017b860e48635213d622a4a4eae91efdd5342ade94093f199c16deb1e58d0088b9b4a0f24a5d15775'
        expected_key4 = b'2ac85be48c4b86fea6a3c6826c3d495f03bf4a273a038578b78c3e642a5431e4'
        expected_V4 = b'57bc95505c2b95d293e628127ca2cb16'

        drbg._Instantiate(unhexlify(entropy_input), unhexlify(nonce), unhexlify(personalization_string))
        self.assertEqual(unhexlify(expected_key1), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V1), drbg._CTRDRBG__V)
                
        drbg._Reseed(unhexlify(reseed_entropy), unhexlify(reseed_additional_input))
        self.assertEqual(unhexlify(expected_key2), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V2), drbg._CTRDRBG__V)
        
        drbg._Generate(64, unhexlify(additional_input1))
        self.assertEqual(unhexlify(expected_key3), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V3), drbg._CTRDRBG__V)
        
        returned_bits = drbg._Generate(64, unhexlify(additional_input2))
        self.assertEqual(unhexlify(expected_bits), returned_bits)
        self.assertEqual(unhexlify(expected_key4), drbg._CTRDRBG__key)
        self.assertEqual(unhexlify(expected_V4), drbg._CTRDRBG__V)


        
if __name__ == "__main__":
    unittest.main()