/**
* HMAC
* 
* Copyright:
* (C) 1999-2007,2014 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.mac.hmac;

import botan.constants;
static if (BOTAN_HAS_HMAC || BOTAN_HAS_PBE_PKCS_V20):

public import botan.mac.mac;
import botan.hash.hash;
import std.algorithm : fill;
import botan.utils.xor_buf;
import botan.utils.mem_ops;
import std.range : refRange;
/**
* HMAC
*/
final class HMAC : MessageAuthenticationCode
{
public:
    /*
    * Clear memory of sensitive data
    */
    override void clear()
    {
        m_hash.clear();
        zap(m_ikey);
        zap(m_okey);
    }

    /*
    * Return the name of this type
    */
    override @property string name() const
    {
        return "HMAC(" ~ m_hash.name ~ ")";
    }

    /*
    * Return a clone of this object
    */
    override MessageAuthenticationCode clone() const
    {
        return new HMAC(m_hash.clone());
    }

    override @property size_t outputLength() const { return m_hash.outputLength; }

    KeyLengthSpecification keySpec() const
    {
        // Absurd max length here is to support PBKDF2
        return KeyLengthSpecification(0, 512);
    }

    /**
    * Params:
    *  hash = the hash to use for HMACing
    */
    this(HashFunction hash) 
    {
        m_hash = hash;
        if (m_hash.hashBlockSize == 0)
            throw new InvalidArgument("HMAC cannot be used with " ~ m_hash.name);
    }
protected:
    /*
    * Update a HMAC Calculation
    */
    override void addData(const(ubyte)* input, size_t length)
    {
        m_hash.update(input, length);
    }

    /*
    * Finalize a HMAC Calculation
    */
    override void finalResult(ubyte* mac)
    {
        m_hash.flushInto(mac);
        m_hash.update(m_okey);
        m_hash.update(mac, outputLength());
        m_hash.flushInto(mac);
        m_hash.update(m_ikey);
    }

    /*
    * HMAC Key Schedule
    */
    override void keySchedule(const(ubyte)* key, size_t length)
    {
        m_hash.clear();
        
        m_ikey.resize(m_hash.hashBlockSize);
        m_okey.resize(m_hash.hashBlockSize);
        
        std.algorithm.fill(m_ikey.ptr[0 .. m_ikey.length], cast(ubyte)0x36);
        std.algorithm.fill(m_okey.ptr[0 .. m_okey.length], cast(ubyte)0x5C);
        
        if (length > m_hash.hashBlockSize)
        {
            SecureVector!ubyte hmac_key = m_hash.process(key, length);
            xorBuf(m_ikey, hmac_key, hmac_key.length);
            xorBuf(m_okey, hmac_key, hmac_key.length);
        }
        else
        {
            xorBuf(m_ikey, key, length);
            xorBuf(m_okey, key, length);
        }
        
        m_hash.update(m_ikey);
    }

    Unique!HashFunction m_hash;
    SecureVector!ubyte m_ikey, m_okey;
}