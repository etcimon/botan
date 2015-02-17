/**
* AES Key Wrap (RFC 3394)
* 
* Copyright:
* (C) 2011 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.constructs.rfc3394;

import botan.constants;
static if (BOTAN_HAS_RFC3394_KEYWRAP):

import botan.algo_base.symkey;
import botan.algo_factory.algo_factory;
import botan.block.block_cipher;
import botan.utils.loadstor;
import botan.utils.exceptn;
import botan.utils.xor_buf;
import botan.utils.mem_ops;
import botan.algo_factory.algo_factory;
import botan.utils.types;

/**
* Encrypt a key under a key encryption key using the algorithm
* described in RFC 3394
*
* Params:
*  key = the plaintext key to encrypt
*  kek = the key encryption key
*  af = an algorithm factory
* Returns: key encrypted under kek
*/
SecureVector!ubyte rfc3394Keywrap()(auto const ref SecureVector!ubyte key,
                                    in SymmetricKey kek,
                                    AlgorithmFactory af)
{
    if (key.length % 8 != 0)
        throw new InvalidArgument("Bad input key size for NIST key wrap");
    
    Unique!BlockCipher aes = makeAes(kek.length, af);
    aes.setKey(kek);
    
    const size_t n = key.length / 8;
    
    SecureVector!ubyte R = SecureVector!ubyte((n + 1) * 8);
    SecureVector!ubyte A = SecureVector!ubyte(16);
    
    foreach (size_t i; 0 .. 8)
        A[i] = 0xA6;
    
    copyMem(&R[8], key.ptr, key.length);
    
    foreach (size_t j; 0 .. 5 + 1)
    {
        foreach (size_t i; 1 .. n + 1)
        {
            const uint t = cast(uint) ((n * j) + i);
            
            copyMem(&A[8], &R[8*i], 8);
            
            aes.encrypt(A.ptr);
            copyMem(&R[8*i], &A[8], 8);
            
            ubyte[4] t_buf;
            storeBigEndian(t, t_buf.ptr);
            xorBuf(&A[4], t_buf.ptr, 4);
        }
    }
    
    copyMem(R.ptr, A.ptr, 8);
    
    return R;
}

/**
* Decrypt a key under a key encryption key using the algorithm
* described in RFC 3394
*
* Params:
*  key = the encrypted key to decrypt
*  kek = the key encryption key
*  af = an algorithm factory
* Returns: key decrypted under kek
*/
SecureVector!ubyte rfc3394Keyunwrap()(auto const ref SecureVector!ubyte key,
                                      in SymmetricKey kek,
                                      AlgorithmFactory af)
{
    if (key.length < 16 || key.length % 8 != 0)
        throw new InvalidArgument("Bad input key size for NIST key unwrap");
    
    Unique!BlockCipher aes = makeAes(kek.length, af);
    aes.setKey(kek);
    
    const size_t n = (key.length - 8) / 8;
    
    SecureVector!ubyte R = SecureVector!ubyte(n * 8);
    SecureVector!ubyte A = SecureVector!ubyte(16);
    
    foreach (size_t i; 0 .. 8)
        A[i] = key[i];
    
    copyMem(R.ptr, &key[8], key.length - 8);
    
    foreach (size_t j; 0 .. 5 + 1)
    {
        for (size_t i = n; i != 0; --i)
        {
            const uint t = cast(uint)( (5 - j) * n + i );
            
            ubyte[4] t_buf;
            storeBigEndian(t, &t_buf);
            
            xorBuf(&A[4], t_buf.ptr, 4);
            
            copyMem(&A[8], &R[8*(i-1)], 8);
            
            aes.decrypt(A.ptr);
            
            copyMem(&R[8*(i-1)], &A[8], 8);
        }
    }
    
    if (loadBigEndian!ulong(A.ptr, 0) != 0xA6A6A6A6A6A6A6A6)
        throw new IntegrityFailure("NIST key unwrap failed");
    
    return R;
}

private:

BlockCipher makeAes(size_t keylength, AlgorithmFactory af)
{
    if (keylength == 16)
        return af.makeBlockCipher("AES-128");
    else if (keylength == 24)
        return af.makeBlockCipher("AES-192");
    else if (keylength == 32)
        return af.makeBlockCipher("AES-256");
    else
        throw new InvalidArgument("Bad KEK length for NIST keywrap");
}


static if (BOTAN_TEST):

import botan.test;
import botan.codec.hex;
import botan.libstate.libstate;

size_t keywrapTest(string key_str,
                   string expected_str,
                   string kek_str)
{
    size_t fail = 0;
    
    try
    {
        SymmetricKey key = SymmetricKey(key_str);
        SymmetricKey expected = SymmetricKey(expected_str);
        SymmetricKey kek = SymmetricKey(kek_str);
        
        AlgorithmFactory af = globalState().algorithmFactory();
        
        SecureVector!ubyte enc = rfc3394Keywrap(key.bitsOf(), kek, af);
        
        if (enc != expected.bitsOf())
        {
            logTrace("NIST key wrap encryption failure: ", hexEncode(enc), " != ", hexEncode(expected.bitsOf()));
            fail++;
        }
        
        SecureVector!ubyte dec = rfc3394Keyunwrap(expected.bitsOf(), kek, af);
        
        if (dec != key.bitsOf())
        {
            logTrace("NIST key wrap decryption failure: " ~ hexEncode(dec) ~ " != " ~ hexEncode(key.bitsOf()));
            fail++;
        }
    }
    catch(Exception e)
    {
        logTrace(e.msg);
        fail++;
    }
    
    return fail;
}

static if (!SKIP_RFC3394_TEST) unittest
{
    logDebug("Testing rfc3394.d ...");

    size_t fails = 0;
    
    fails += keywrapTest("00112233445566778899AABBCCDDEEFF",
                         "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
                         "000102030405060708090A0B0C0D0E0F");
    
    fails += keywrapTest("00112233445566778899AABBCCDDEEFF",
                         "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
                         "000102030405060708090A0B0C0D0E0F1011121314151617");
    
    fails += keywrapTest("00112233445566778899AABBCCDDEEFF",
                         "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7",
                         "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    
    fails += keywrapTest("00112233445566778899AABBCCDDEEFF0001020304050607",
                         "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2",
                         "000102030405060708090A0B0C0D0E0F1011121314151617");
    
    fails += keywrapTest("00112233445566778899AABBCCDDEEFF0001020304050607",
                         "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1",
                         "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    
    fails += keywrapTest("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
                         "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
                         "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    
    testReport("rfc3394", 6, fails);

}
