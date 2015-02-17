/**
* KeyedFilter
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.filters.key_filt;
public import botan.filters.filter;
import botan.algo_base.sym_algo;
/**
* This class represents keyed filters, i.e. filters that have to be
* fed with a key in order to function.
*/
abstract class KeyedFilter : Filter
{
public:
    /**
    * Set the key of this filter
    * Params:
    *  key = the key to use
    */
    abstract void setKey(in SymmetricKey key);

    /**
    * Set the initialization vector of this filter. Note: you should
    * call setIv() only after you have called setKey()
    * Params:
    *  iv = the initialization vector to use
    */
    void setIv(in InitializationVector iv)
    {
        if (iv.length != 0)
            throw new InvalidIVLength(name(), iv.length);
    }

    /**
    * Check whether a key length is valid for this filter
    * Params:
    *  length = the key length to be checked for validity
    * Returns: true if the key length is valid, false otherwise
    */
    bool validKeylength(size_t length) const
    {
        return keySpec().validKeylength(length);
    }

    /**
    * Returns: object describing limits on key size
    */
    abstract KeyLengthSpecification keySpec() const;

    /**
    * Check whether an IV length is valid for this filter
    * Params:
    *  length = the IV length to be checked for validity
    * Returns: true if the IV length is valid, false otherwise
    */
    abstract bool validIvLength(size_t length) const;
}