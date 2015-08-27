/**
* Lion
* 
* Copyright:
* (C) 1999-2007,2014 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.block.lion;

import botan.constants;
static if (BOTAN_HAS_LION):

import botan.block.block_cipher;
import botan.stream.stream_cipher;
import botan.hash.hash;
import botan.utils.xor_buf;
import botan.utils.parsing;
import botan.utils.mem_ops;
import std.conv : to;
import botan.utils.mem_ops;

/**
* Lion is a block cipher construction designed by Ross Anderson and
* Eli Biham, described in "Two Practical and Provably Secure Block
* Ciphers: BEAR and LION". It has a variable block size and is
* designed to encrypt very large blocks (up to a megabyte)

* http://www.cl.cam.ac.uk/~rja14/Papers/bear-lion.pdf
*/
final class Lion : BlockCipher, SymmetricAlgorithm
{
public:
    /*
    * Lion Encryption
    */
    override void encryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        const size_t LEFT_SIZE = leftSize();
        const size_t RIGHT_SIZE = right_size();
        
        SecureVector!ubyte buffer_vec = SecureVector!ubyte(LEFT_SIZE);
        ubyte* buffer = buffer_vec.ptr;
        
        foreach (size_t i; 0 .. blocks)
        {
            xorBuf(buffer, input, m_key1.ptr, LEFT_SIZE);
            m_cipher.setKey(buffer, LEFT_SIZE);
            m_cipher.cipher(input + LEFT_SIZE, output + LEFT_SIZE, RIGHT_SIZE);
            
            m_hash.update(output + LEFT_SIZE, RIGHT_SIZE);
            m_hash.flushInto(buffer);
            xorBuf(output, input, buffer, LEFT_SIZE);
            
            xorBuf(buffer, output, m_key2.ptr, LEFT_SIZE);
            m_cipher.setKey(buffer, LEFT_SIZE);
            m_cipher.cipher1(output + LEFT_SIZE, RIGHT_SIZE);
            
            input += m_block_size;
            output += m_block_size;
        }
    }

    /*
    * Lion Decryption
    */
    override void decryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        const size_t LEFT_SIZE = leftSize();
        const size_t RIGHT_SIZE = right_size();
        
        SecureVector!ubyte buffer_vec = SecureVector!ubyte(LEFT_SIZE);
        ubyte* buffer = buffer_vec.ptr;
        
        foreach (size_t i; 0 .. blocks)
        {
            xorBuf(buffer, input, m_key2.ptr, LEFT_SIZE);
            m_cipher.setKey(buffer, LEFT_SIZE);
            m_cipher.cipher(input + LEFT_SIZE, output + LEFT_SIZE, RIGHT_SIZE);
            
            m_hash.update(output + LEFT_SIZE, RIGHT_SIZE);
            m_hash.flushInto(buffer);
            xorBuf(output, input, buffer, LEFT_SIZE);
            
            xorBuf(buffer, output, m_key1.ptr, LEFT_SIZE);
            m_cipher.setKey(buffer, LEFT_SIZE);
            m_cipher.cipher1(output + LEFT_SIZE, RIGHT_SIZE);
            
            input += m_block_size;
            output += m_block_size;
        }
    }

    override size_t blockSize() const { return m_block_size; }

    override KeyLengthSpecification keySpec() const
    {
        return KeyLengthSpecification(2, 2*m_hash.outputLength, 2);
    }

    /*
    * Clear memory of sensitive data
    */
    override void clear()
    {
        zeroise(m_key1);
        zeroise(m_key2);
        m_hash.clear();
        m_cipher.clear();
    }

    /*
    * Return the name of this type
    */
    override @property string name() const
    {
        return "Lion(" ~ m_hash.name ~ "," ~
            m_cipher.name ~ "," ~
                to!string(blockSize()) ~ ")";
    }

    /*
    * Return a clone of this object
    */
    override BlockCipher clone() const
    {
        return new Lion(m_hash.clone(), m_cipher.clone(), blockSize());
    }


    /**
    * Params:
    *  hash = the hash to use internally
    *  cipher = the stream cipher to use internally
    *  block_size = the size of the block to use
    */
    this(HashFunction hash, StreamCipher cipher, size_t block_size) 
    {
        m_block_size = std.algorithm.max(2*hash.outputLength + 1, block_size);
        m_hash = hash;
        m_cipher = cipher;
        
        if (2*leftSize() + 1 > m_block_size)
            throw new InvalidArgument(name ~ ": Chosen block size is too small");
        
        if (!m_cipher.validKeylength(leftSize()))
            throw new InvalidArgument(name ~ ": This stream/hash combo is invalid");
        
        m_key1.resize(leftSize());
        m_key2.resize(leftSize());
    }
    override @property size_t parallelism() const { return 1; }
protected:

    /*
    * Lion Key Schedule
    */
    override void keySchedule(const(ubyte)* key, size_t length)
    {
        clear();
        
        const size_t half = length / 2;
        copyMem(m_key1.ptr, key, half);
        copyMem(m_key2.ptr, key + half, half);
    }

private:
    size_t leftSize() const { return m_hash.outputLength; }
    size_t right_size() const { return m_block_size - leftSize(); }

    const size_t m_block_size;
    Unique!HashFunction m_hash;
    Unique!StreamCipher m_cipher;
    SecureVector!ubyte m_key1, m_key2;
}
