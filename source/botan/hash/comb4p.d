/**
* Comb4P hash combiner
* 
* Copyright:
* (C) 2010 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.hash.comb4p;

import botan.constants;
static if (BOTAN_HAS_COMB4P):

import botan.hash.hash;
import botan.utils.xor_buf;
import botan.utils.types;
import botan.utils.mem_ops;
import std.exception;

/**
* Combines two hash functions using a Feistel scheme. Described in
* "On the Security of Hash Function Combiners", Anja Lehmann
*/
class Comb4P : HashFunction
{
public:
    /**
    * Params:
    *  h1 = the first hash
    *  h2 = the second hash
    */
    this(HashFunction h1, HashFunction h2)
    {
        m_hash1 = h1;
        m_hash2 = h2;
        if (m_hash1.name == m_hash2.name)
            throw new InvalidArgument("Comb4P: Must use two distinct hashes");
        
        if (m_hash1.outputLength != m_hash2.outputLength)
            throw new InvalidArgument("Comb4P: Incompatible hashes " ~
                                       m_hash1.name ~ " and " ~
                                       m_hash2.name);
        
        clear();
    }


    override @property size_t hashBlockSize() const
    {
        if (m_hash1.hashBlockSize == m_hash2.hashBlockSize)
            return m_hash1.hashBlockSize;
        
        /*
        * Return LCM of the block sizes? This would probably be OK for
        * HMAC, which is the main thing relying on knowing the block size.
        */
        return 0;
    }

    override @property size_t outputLength() const
    {
        return m_hash1.outputLength + m_hash2.outputLength;
    }

    override HashFunction clone() const
    {
        return new Comb4P(m_hash1.clone(), m_hash2.clone());
    }

    override @property string name() const
    {
        return "Comb4P(" ~ m_hash1.name ~ "," ~ m_hash2.name ~ ")";
    }

    override void clear()
    {
        m_hash1.clear();
        m_hash2.clear();
        
        // Prep for processing next message, if any
        m_hash1.update(0);
        m_hash2.update(0);
    }

protected:
    override void addData(const(ubyte)* input, size_t length)
    {
        m_hash1.update(input, length);
        m_hash2.update(input, length);
    }

    override void finalResult(ubyte* output)
    {
        SecureVector!ubyte h1 = m_hash1.finished();
        SecureVector!ubyte h2 = m_hash2.finished();
        
        // First round
        xorBuf(h1.ptr, h2.ptr, std.algorithm.min(h1.length, h2.length));
        
        // Second round
        comb4p_round(h2, h1, 1, *m_hash1, *m_hash2);
        
        // Third round
        comb4p_round(h1, h2, 2, *m_hash1, *m_hash2);
        
        copyMem(output            , h1.ptr, h1.length);
        copyMem(output + h1.length, h2.ptr, h2.length);
        
        // Prep for processing next message, if any
        m_hash1.update(0);
        m_hash2.update(0);
    }

    Unique!HashFunction m_hash1, m_hash2;
}

private:
    
void comb4p_round(ref SecureVector!ubyte output,
                  const ref SecureVector!ubyte input,
                  ubyte round_no,
                  HashFunction h1,
                  HashFunction h2)
{
    h1.update(round_no);
    h2.update(round_no);
    
    h1.update(input.ptr, input.length);
    h2.update(input.ptr, input.length);
    
    SecureVector!ubyte h_buf = h1.finished();
    xorBuf(output.ptr, h_buf.ptr, std.algorithm.min(output.length, h_buf.length));
    
    h_buf = h2.finished();
    xorBuf(output.ptr, h_buf.ptr, std.algorithm.min(output.length, h_buf.length));
}