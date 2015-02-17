/**
* Symmetric Algorithm Base Class
*
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
* 
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.algo_base.sym_algo;

import botan.utils.exceptn;
public import botan.algo_base.key_spec;
public import botan.algo_base.symkey;
public import botan.utils.types;

/**
* This class represents a symmetric algorithm object.
*/
interface SymmetricAlgorithm
{
public:
    
    /**
    * Returns: minimum allowed key length
    */
    final size_t maximumKeylength() const
    {
        return keySpec().maximumKeylength();
    }
    
    /**
    * Returns: maxmium allowed key length
    */
    final size_t minimumKeylength() const
    {
        return keySpec().minimumKeylength();
    }
    
    /**
    * Check whether a given key length is valid for this algorithm.
    * 
    * Params:
    *  length = the key length to be checked.
    * 
    * Returns: true if the key length is valid.
    */
    final bool validKeylength(size_t length) const
    {
        return keySpec().validKeylength(length);
    }
    
    /**
    * Set the symmetric key of this object.
    * 
    * Params:
    *  key = the $(D SymmetricKey) to be set.
    */
    final void setKey(in SymmetricKey key)
    {
        setKey(key.ptr, key.length);
    }
    
	/// ditto
    final void setKey(Alloc)(auto const ref RefCounted!(Vector!( ubyte, Alloc ), Alloc) key)
    {
        setKey(key.ptr, key.length);
    }

	/// ditto
    final void setKey(Alloc)(auto const ref Vector!( ubyte, Alloc ) key)
    {
        setKey(key.ptr, key.length);
    }
    
    /**
    * Set the symmetric key of this object.
    * 
    * Params:
    *  key = the to be set as a ubyte array.
    *  length = in bytes of key param
    */
    final void setKey(const(ubyte)* key, size_t length)
    {
        if (!validKeylength(length))
            throw new InvalidKeyLength(name, length);
        keySchedule(key, length);
    }

	/// Clear underlying buffers
    abstract void clear();
    
    /**
    * Returns: object describing limits on key size
    */
    abstract KeyLengthSpecification keySpec() const;

    abstract @property string name() const;
    
protected:
    /**
    * Run the key schedule
    * 
    * Params:
    *  key = the key
    *  length = of key
    */
    abstract void keySchedule(const(ubyte)* key, size_t length);
}

