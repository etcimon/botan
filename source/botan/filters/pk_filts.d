/**
* PK Filters
* 
* Copyright:
* (C) 1999-2009 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.filters.pk_filts;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

import botan.filters.filter;
import botan.pubkey.pubkey;
import botan.rng.rng;

/**
* PKEncryptor Filter
*/
final class PKEncryptorFilter : Filter, Filterable
{
public:
    /*
    * Append to the buffer
    */
    override void write(const(ubyte)* input, size_t length)
    {
        m_buffer ~= input[0 .. length];
    }
    /*
    * Encrypt the message
    */
    override void endMsg()
    {
        send(m_cipher.encrypt(m_buffer, m_rng));
        m_buffer.clear();
    }

    this(PKEncryptor c, RandomNumberGenerator rng_ref) 
    {
        m_cipher = c;
        m_rng = rng_ref;
    }

    ~this() { destroy(m_cipher); }

    // Interface fallthrough
    override void setNext(Filter* filters, size_t sz) { super.setNext(filters, sz); }
private:
    PKEncryptor m_cipher;
    RandomNumberGenerator m_rng;
    SecureVector!ubyte m_buffer;
}

/**
* PKDecryptor Filter
*/
final class PKDecryptorFilter : Filter, Filterable
{
public:
    /*
    * Append to the buffer
    */
    override void write(const(ubyte)* input, size_t length)
    {
        m_buffer ~= input[0 .. length];
    }

    /*
    * Decrypt the message
    */
    override void endMsg()
    {
        send(m_cipher.decrypt(m_buffer));
        m_buffer.clear();
    }

    this(PKDecryptor c) {  m_cipher = c; }
    ~this() { destroy(m_cipher); }

    // Interface fallthrough
    override void setNext(Filter* filters, size_t sz) { super.setNext(filters, sz); }
private:
    PKDecryptor m_cipher;
    SecureVector!ubyte m_buffer;
}

/**
* PKSigner Filter
*/
final class PKSignerFilter : Filter, Filterable
{
public:
    /*
    * Add more data
    */
    override void write(const(ubyte)* input, size_t length)
    {
        m_signer.update(input, length);
    }

    /*
    * Sign the message
    */
    override void endMsg()
    {
        send(m_signer.signature(m_rng));
    }


    this(ref PKSigner s,
         RandomNumberGenerator rng_ref)
    {
        m_signer = &s;
        m_rng = rng_ref;
    }

    ~this() {  }

    // Interface fallthrough
    override void setNext(Filter* filters, size_t sz) { super.setNext(filters, sz); }
private:
    PKSigner* m_signer;
    RandomNumberGenerator m_rng;
}

/**
* PKVerifier Filter
*/
final class PKVerifierFilter : Filter, Filterable
{
public:
    /*
    * Add more data
    */
    override void write(const(ubyte)* input, size_t length)
    {
        m_verifier.update(input, length);
    }
    
    /*
    * Verify the message
    */
    override void endMsg()
    {
        if (m_signature.empty)
            throw new InvalidState("PKVerifierFilter: No signature to check against");
        bool is_valid = m_verifier.checkSignature(m_signature);
        send((is_valid ? 1 : 0));
    }

    /*
    * Set the signature to check
    */
    void setSignature(const(ubyte)* sig, size_t length)
    {
        m_signature[] = sig[0 .. length];
    }
    
    /*
    * Set the signature to check
    */
    void setSignature(SecureVector!ubyte sig)
    {
        m_signature = sig;
    }
    


    this(ref PKVerifier v) { m_verifier = &v; }
    /*
    * PKVerifierFilter Constructor
    */
    this(ref PKVerifier v, const(ubyte)* sig, size_t length)
    {
        m_verifier = &v;
        m_signature = SecureVector!ubyte(sig[0 .. length]);
    }
    
    /*
    * PKVerifierFilter Constructor
    */
    this(ref PKVerifier v, in SecureVector!ubyte sig) 
    {
        m_verifier = &v;
        m_signature = sig.dup;
    }

    ~this() {  }

    // Interface fallthrough
    override void setNext(Filter* filters, size_t sz) { super.setNext(filters, sz); }
private:
    PKVerifier* m_verifier;
    SecureVector!ubyte m_signature;
}