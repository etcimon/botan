/**
* HMAC
* 
* Copyright:
* (C) 1999-2007,2014,2020 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
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

        const size_t BS = m_hash.hashBlockSize;
        m_ikey.resize(BS);
        m_okey.resize(BS);
        clearMem(m_ikey.ptr, m_ikey.length);
        clearMem(m_okey.ptr, m_okey.length);

        if (length > BS)
        {
            SecureVector!ubyte hmac_key = m_hash.process(key, length);
            copyMem(m_ikey.ptr, hmac_key.ptr, hmac_key.length);
        }
        else if (length >= 20)
        {
            copyMem(m_ikey.ptr, key, length);
        }
        else if (length)
        {
            static if (BOTAN_HAS_CT)
            {
                import botan.utils.ct : CTMask;
                size_t i_mod_length = 0;
                foreach (i; 0 .. BS)
                {
                    auto needs_reduction = CTMask!size_t.isLte(length, i_mod_length);
                    i_mod_length = needs_reduction.select(0, i_mod_length);
                    const ubyte kb = key[i_mod_length];
                    auto in_range = CTMask!size_t.isLt(i, length);
                    m_ikey[i] = cast(ubyte) in_range.ifSetReturn(kb);
                    i_mod_length += 1;
                }
            }
            else
                copyMem(m_ikey.ptr, key, length);
        }

        foreach (i; 0 .. BS)
        {
            m_ikey[i] ^= 0x36;
            m_okey[i] = m_ikey[i] ^ 0x36 ^ 0x5C;
        }

        m_hash.update(m_ikey);
    }

    Unique!HashFunction m_hash;
    SecureVector!ubyte m_ikey, m_okey;
}