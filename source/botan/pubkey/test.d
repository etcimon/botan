/**
* Public Key Cryptography Unit Testing
* 
* Copyright:
* (C) 2009 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.test;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO && BOTAN_TEST):

import botan.test;
import botan.rng.test;
import botan.asn1.oids;
import botan.codec.hex;
import botan.pubkey.x509_key;
import botan.pubkey.pkcs8;
import botan.pubkey.pubkey;
import botan.rng.auto_rng;
import botan.utils.mem_ops;
import botan.filters.filters;
import botan.filters.hex_filt;
import botan.math.numbertheory.numthry;

void dumpData(const ref Vector!ubyte output, const ref Vector!ubyte expected)
{
    Pipe pipe = Pipe(new HexEncoder);
    
    pipe.processMsg(output.dup);
    pipe.processMsg(expected.dup);
    logTrace("Got: " ~ pipe.toString(0));
    logTrace("Exp: " ~ pipe.toString(1));
}

size_t validateSaveAndLoad(const PrivateKey priv_key, RandomNumberGenerator rng)
{
    string name = priv_key.algoName();
    
    size_t fails = 0;
    string pub_pem = x509_key.PEM_encode(priv_key);
    
    try
    {
        DataSourceMemory input_pub = DataSourceMemory(pub_pem);
        PublicKey restored_pub = x509_key.loadKey(cast(DataSource)input_pub);
        
        if (!restored_pub)
        {
            logError("Could not recover " ~ name ~ " public key");
            ++fails;
        }
        else if (restored_pub.checkKey(rng, true) == false)
        {
            logError("Restored pubkey failed self tests " ~ name);
            ++fails;
        }
    }
    catch(Exception e)
    {
        logError("Exception during load of " ~ name ~ " key: " ~ e.msg);
        logTrace("PEM for pubkey was: " ~ pub_pem);
        ++fails;
    }
    
    string priv_pem = pkcs8.PEM_encode(priv_key);
    try {
        auto input_priv = DataSourceMemory(priv_pem);
        Unique!PrivateKey restored_priv = pkcs8.loadKey(cast(DataSource)input_priv, rng);
        
        if (!restored_priv)
        {
            logError("Could not recover " ~ name ~ " private key");
            ++fails;
        }
        else if (restored_priv.checkKey(rng, true) == false)
        {
            logError("Restored privkey failed self tests " ~ name);
            ++fails;
        }
    }
    catch(Exception e)
    {
        logError("Exception during load of " ~ name ~ " key: " ~ e.msg);
        logTrace("PEM for pubkey was: " ~ priv_pem);
        ++fails;
    }
    return fails;
}

ubyte nonzeroByte(RandomNumberGenerator rng)
{
    ubyte b = 0;
    while(b == 0)
        b = rng.nextByte();
    return b;
}

string PKTEST(string expr, string msg) 
{
    return `
        {
            const bool test_result = ` ~ expr ~ `;
            if (!test_result)
            {
                logTrace("Test " ~ ` ~ expr ~ ` ~ " failed: ` ~ msg ~ `");
                ++fails;
            }
        }
    `;
}

size_t validateEncryption(PKEncryptor e, PKDecryptor d,
                           string algo, string input,
                           string random, string exp)
{
    Vector!ubyte message = hexDecode(input);
    Vector!ubyte expected = hexDecode(exp);
    auto rng = scoped!FixedOutputRNG(hexDecode(random));
    
    size_t fails = 0;
    
    const Vector!ubyte ctext = e.encrypt(message, rng);
    if (ctext != expected)
    {
        logError("FAILED (encrypt): " ~ algo);
        dumpData(ctext, expected);
        ++fails;
    }
    
    Vector!ubyte decrypted = unlock(d.decrypt(ctext));
    
    if (decrypted != message)
    {
        logError("FAILED (decrypt): " ~ algo);
        dumpData(decrypted, message);
        ++fails;
    }
    
    if (algo.canFind("/Raw") == -1)
    {
        auto arng = AutoSeededRNG();
        
        for(size_t i = 0; i != ctext.length; ++i)
        {
            Vector!ubyte bad_ctext = ctext.dup;
            
            bad_ctext[i] ^= nonzeroByte(arng);
            
            assert(bad_ctext != ctext, "Made them different");
            
            auto bad_ptext = unlock(d.decrypt(bad_ctext));
            logError(algo ~ " failed - decrypted bad data");
            logTrace(hexEncode(bad_ctext) ~ " . " ~ hexEncode(bad_ptext));
            logTrace(hexEncode(ctext) ~ " . " ~ hexEncode(decrypted));
            ++fails;
        }
    }
    
    return fails;
}

size_t validateSignature(ref PKVerifier v, ref PKSigner s, string algo,
                         string input,
                         RandomNumberGenerator rng,
                         string exp)
{
    return validateSignature(v, s, algo, input, rng, rng, exp);
}

size_t validateSignature(ref PKVerifier v, ref PKSigner s, string algo,
                         string input,
                         RandomNumberGenerator signer_rng,
                         RandomNumberGenerator test_rng,
                         string exp)    
{
    Vector!ubyte message = hexDecode(input);
    Vector!ubyte expected = hexDecode(exp);
    Vector!ubyte sig = s.signMessage(message, signer_rng);
    size_t fails = 0;
    
    if (sig != expected)
    {
        logError("FAILED (sign): " ~ algo);
        dumpData(sig, expected);
        ++fails;
    }
    
    mixin( PKTEST(` v.verifyMessage(message, sig) `, "Correct signature is valid") );
    
    clearMem(sig.ptr, sig.length);
    
    mixin( PKTEST(` !v.verifyMessage(message, sig) `, "All-zero signature is invalid") );
    
    for(size_t i = 0; i != 3; ++i)
    {
        auto bad_sig = sig.dup;
        
        const size_t idx = (test_rng.nextByte() * 256 + test_rng.nextByte()) % sig.length;
        bad_sig[idx] ^= nonzeroByte(test_rng);
        
        mixin( PKTEST(` !v.verifyMessage(message, bad_sig) `, "Incorrect signature is invalid") );
    }
    return fails;
}

size_t validateSignature(ref PKVerifier v, ref PKSigner s, string algo,
                         string input,
                         RandomNumberGenerator rng,
                         string random,
                         string exp)
{
    auto fixed_rng = scoped!FixedOutputRNG(hexDecode(random));
    
    return validateSignature(v, s, algo, input, fixed_rng, rng, exp);
}

size_t validateKas(PKKeyAgreement kas, string algo,
                    const Vector!ubyte pubkey, string output,
                    size_t keylen)
{
    Vector!ubyte expected = hexDecode(output);
    
    Vector!ubyte got = unlock(kas.deriveKey(keylen, pubkey).bitsOf());
    
    size_t fails = 0;
    
    if (got != expected)
    {
        logError("FAILED: " ~ algo);
        dumpData(got, expected);
        ++fails;
    }
    
    return fails;
}