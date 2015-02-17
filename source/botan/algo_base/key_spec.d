/**
* Symmetric Key Length Specification
* 
* Copyright:
* (C) 2010 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.algo_base.key_spec;

import botan.utils.types;
/**
* Represents the length requirements on an algorithm key
*/
struct KeyLengthSpecification
{
public:
    /**
    * Constructor for fixed length keys
    * 
    * Params:
    *  keylen = the supported key length
    */
    this(size_t keylen)
    {
        m_min_keylen = keylen;
        m_max_keylen = keylen;
        m_keylen_mod = 1;
    }

    /**
    * Constructor for variable length keys
    * 
    * Params:
    *  min_k = the smallest supported key length
    *  max_k = the largest supported key length
    *  k_mod = the number of bytes the key must be a multiple of
    */
    this(size_t min_k,
         size_t max_k,
         size_t k_mod = 1)
    {
        m_min_keylen = min_k;
        m_max_keylen = max_k ? max_k : min_k;
        m_keylen_mod = k_mod;
    }

    /**
    * Params:
    *  length = is a key length in bytes
    * 
    * Returns: true iff this length is a valid length for this algo
    */
    bool validKeylength(size_t length) const
    {
        return ((length >= m_min_keylen) &&
                (length <= m_max_keylen) &&
                (length % m_keylen_mod == 0));
    }

    /**
    * Returns: minimum key length in bytes
    */
    size_t minimumKeylength() const
    {
        return m_min_keylen;
    }

    /**
    * Returns: maximum key length in bytes
    */
    size_t maximumKeylength() const
    {
        return m_max_keylen;
    }

    /**
    * Returns: key length multiple in bytes
    */
    size_t keylengthMultiple() const
    {
        return m_keylen_mod;
    }

    KeyLengthSpecification multiple(size_t n) const
    {
        return KeyLengthSpecification(n * m_min_keylen,
                                        n * m_max_keylen,
                                        n * m_keylen_mod);
    }

private:

    size_t m_min_keylen, m_max_keylen, m_keylen_mod;
}