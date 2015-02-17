/**
* DLIES (Discrete Logarithm/Elliptic Curve Integrated Encryption Scheme): 
* Essentially the "DHAES" variant of ElGamal encryption.
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.algo.dlies;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO && BOTAN_HAS_DLIES):

public import botan.pubkey.pubkey;
import botan.mac.mac;
import botan.kdf.kdf;
import botan.utils.xor_buf;
import botan.utils.mem_ops;

/**
* DLIES Encryption
*/
class DLIESEncryptor : PKEncryptor
{
public:
    /*
    * DLIESEncryptor Constructor
    */
    this(in PKKeyAgreementKey key, KDF kdf_obj, MessageAuthenticationCode mac_obj, size_t mac_keylen = 20)
    { 
        m_ka = new PKKeyAgreement(key, "Raw");
        m_kdf = kdf_obj;
        m_mac = mac_obj;
        m_mac_keylen = mac_keylen;
        m_my_key = key.publicValue();
    }

    /*
    * Set the other parties public key
    */
    void setOtherKey()(auto const ref Vector!ubyte ok)
    {
        m_other_key = ok.dup;
    }
protected:
    /*
    * DLIES Encryption
    */
    Vector!ubyte enc(const(ubyte)* input, size_t length, RandomNumberGenerator rng) const
    {
        if (length > maximumInputSize())
            throw new InvalidArgument("DLIES: Plaintext too large");
        if (m_other_key.empty)
            throw new InvalidState("DLIES: The other key was never set");
        
        SecureVector!ubyte output = SecureVector!ubyte(m_my_key.length + length + m_mac.outputLength);
        bufferInsert(output, 0, m_my_key);
        bufferInsert(output, m_my_key.length, input, length);
        
        SecureVector!ubyte vz = SecureVector!ubyte(m_my_key.ptr[0 .. m_my_key.length]);
        vz ~= m_ka.deriveKey(0, m_other_key).bitsOf();
        
        const size_t K_LENGTH = length + m_mac_keylen;
        OctetString K = m_kdf.deriveKey(K_LENGTH, vz);
        
        if (K.length != K_LENGTH)
            throw new EncodingError("DLIES: KDF did not provide sufficient output");
        ubyte* C = &output[m_my_key.length];
        
        xorBuf(C, K.ptr + m_mac_keylen, length);
        Unique!MessageAuthenticationCode mac = m_mac.clone();
        mac.setKey(K.ptr, m_mac_keylen);
        
        mac.update(C, length);
        foreach (size_t j; 0 .. 8)
            mac.update(0);
        
        mac.flushInto(C + length);
        
        return unlock(output);
    }

    /*
    * Return the max size, in bytes, of a message
    */
    size_t maximumInputSize() const
    {
        return 32;
    }

private:
    Vector!ubyte m_other_key, m_my_key;

    Unique!PKKeyAgreement m_ka;
    Unique!KDF m_kdf;
    Unique!MessageAuthenticationCode m_mac;
    size_t m_mac_keylen;
}

/**
* DLIES Decryption
*/
class DLIESDecryptor : PKDecryptor
{
public:
    /*
    * DLIESDecryptor Constructor
    */
    this(in PKKeyAgreementKey key, KDF kdf_obj, MessageAuthenticationCode mac_obj, size_t mac_key_len = 20)
    {
        m_ka = new PKKeyAgreement(key, "Raw");
        m_kdf = kdf_obj;
        m_mac = mac_obj;
        m_mac_keylen = mac_key_len;
        m_my_key = key.publicValue();
    }

protected:
    /*
    * DLIES Decryption
    */
    SecureVector!ubyte dec(const(ubyte)* msg, size_t length) const
    {
        if (length < m_my_key.length + m_mac.outputLength)
            throw new DecodingError("DLIES decryption: ciphertext is too short");
        
        const size_t CIPHER_LEN = length - m_my_key.length - m_mac.outputLength;
        
        Vector!ubyte v = Vector!ubyte(msg[0 .. m_my_key.length]);
        
        SecureVector!ubyte C = SecureVector!ubyte(msg[m_my_key.length .. m_my_key.length + CIPHER_LEN]);
        
        SecureVector!ubyte T = SecureVector!ubyte(msg[m_my_key.length + CIPHER_LEN .. m_my_key.length + CIPHER_LEN + m_mac.outputLength]);
        
        SecureVector!ubyte vz = SecureVector!ubyte(msg[0 .. m_my_key.length]);
        vz ~= m_ka.deriveKey(0, v).bitsOf();
        
        const size_t K_LENGTH = C.length + m_mac_keylen;
        OctetString K = m_kdf.deriveKey(K_LENGTH, vz);
        if (K.length != K_LENGTH)
            throw new EncodingError("DLIES: KDF did not provide sufficient output");
        Unique!MessageAuthenticationCode mac = m_mac.clone();
        mac.setKey(K.ptr, m_mac_keylen);
        mac.update(C);
        foreach (size_t j; 0 .. 8)
            mac.update(0);
        SecureVector!ubyte T2 = mac.finished();
        if (T != T2)
            throw new DecodingError("DLIES: message authentication failed");
        
        xorBuf(C, K.ptr + m_mac_keylen, C.length);
        
        return C;
    }

private:
    Vector!ubyte m_my_key;

    Unique!PKKeyAgreement m_ka;
    Unique!KDF m_kdf;
    Unique!MessageAuthenticationCode m_mac;
    size_t m_mac_keylen;
}


static if (BOTAN_TEST):
import botan.test;
import botan.utils.parsing;
import botan.pubkey.test;
import botan.codec.hex;
import botan.rng.auto_rng;
import botan.pubkey.pubkey;
import botan.libstate.lookup;
import botan.pubkey.algo.dh;
import std.conv : to;
import core.atomic;
import memutils.hashmap;

shared size_t total_tests;

size_t dliesKat(string p,
                string g,
                string x1,
                string x2,
                string msg,
                string ciphertext)
{
    atomicOp!"+="(total_tests, 1);
    auto rng = AutoSeededRNG();
    
    BigInt p_bn = BigInt(p);
    BigInt g_bn = BigInt(g);
    BigInt x1_bn = BigInt(x1);
    BigInt x2_bn = BigInt(x2);

    //logTrace("p_bn: ", p_bn.toString());
    //logTrace("g_bn: ", g_bn.toString());
    //logTrace("x1_bn: ", x1_bn.toString());
    //logTrace("x2_bn: ", x2_bn.toString());

    DLGroup domain = DLGroup(p_bn, g_bn);
    
    auto from = DHPrivateKey(rng, domain.dup, x1_bn.move());
    auto to = DHPrivateKey(rng, domain.dup, x2_bn.move());
    
    const string opt_str = "KDF2(SHA-1)/HMAC(SHA-1)/16";

    Vector!string options = splitter(opt_str, '/');
    
    if (options.length != 3)
        throw new Exception("DLIES needs three options: " ~ opt_str);
    
    const size_t mac_key_len = .to!uint(options[2]);
    
    auto e = scoped!DLIESEncryptor(from, getKdf(options[0]), retrieveMac(options[1]).clone(), mac_key_len);
    
    auto d = scoped!DLIESDecryptor(to, getKdf(options[0]), retrieveMac(options[1]).clone(), mac_key_len);
    
    e.setOtherKey(to.publicValue());
    
    return validateEncryption(e, d, "DLIES", msg, "", ciphertext);
}

static if (!SKIP_DLIES_TEST) unittest
{
    logDebug("Testing dlies.d ...");
    size_t fails = 0;
    
    File dlies = File("../test_data/pubkey/dlies.vec", "r");
    
    fails += runTestsBb(dlies, "DLIES Encryption", "Ciphertext", true,
        (ref HashMap!(string, string) m) {
            return dliesKat(m["P"], m["G"], m["X1"], m["X2"], m["Msg"], m["Ciphertext"]);
        });
    
    testReport("dlies", total_tests, fails);
}