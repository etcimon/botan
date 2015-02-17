/**
* Block Cipher Cascade
* 
* Copyright:
* (C) 2010 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.block.cascade;

import botan.constants;
static if (BOTAN_HAS_CASCADE):

import botan.block.block_cipher;
import botan.utils.mem_ops;

/**
* Block Cipher Cascade
*/
final class CascadeCipher : BlockCipher, SymmetricAlgorithm
{
public:
    override void encryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        size_t c1_blocks = blocks * (this.blockSize() / m_cipher1.blockSize());
        size_t c2_blocks = blocks * (this.blockSize() / m_cipher2.blockSize());
        
        m_cipher1.encryptN(input, output, c1_blocks);
        m_cipher2.encryptN(output, output, c2_blocks);
    }

    override void decryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        size_t c1_blocks = blocks * (this.blockSize() / m_cipher1.blockSize());
        size_t c2_blocks = blocks * (this.blockSize() / m_cipher2.blockSize());
        
        m_cipher2.decryptN(input, output, c2_blocks);
        m_cipher1.decryptN(output, output, c1_blocks);
    }

    override size_t blockSize() const { return m_block; }

    KeyLengthSpecification keySpec() const
    {
        return KeyLengthSpecification(m_cipher1.maximumKeylength() + m_cipher2.maximumKeylength());
    }

    override void clear()
    {
        m_cipher1.clear();
        m_cipher2.clear();
    }

    @property string name() const
    {
        return "Cascade(" ~ m_cipher1.name ~ "," ~ m_cipher2.name ~ ")";
    }

    override @property size_t parallelism() const { return 1; }

    override BlockCipher clone() const
    {
        return new CascadeCipher(m_cipher1.clone(), m_cipher2.clone());
    }

    /**
    * Create a cascade of two block ciphers
    * Params:
    *  cipher1 = the first cipher
    *  cipher2 = the second cipher
    */
    this(BlockCipher c1, BlockCipher c2) 
    {
        m_cipher1 = c1; 
        m_cipher2 = c2;
        m_block = block_size_for_cascade(m_cipher1.blockSize(), m_cipher2.blockSize());
        
        if (this.blockSize() % m_cipher1.blockSize() || this.blockSize() % m_cipher2.blockSize())
            throw new InternalError("Failure in " ~ name() ~ " constructor");
    }
protected:
    override void keySchedule(const(ubyte)* key, size_t)
    {
        const(ubyte)* key2 = key + m_cipher1.maximumKeylength();
        
        m_cipher1.setKey(key , m_cipher1.maximumKeylength());
        m_cipher2.setKey(key2, m_cipher2.maximumKeylength());
    }

    size_t m_block;
    Unique!BlockCipher m_cipher1, m_cipher2;
}

private:

size_t euclids_algorithm(size_t a, size_t b)
{
    while (b != 0) // gcd
    {
        size_t t = b;
        b = a % b;
        a = t;
    }
    
    return a;
}

size_t block_size_for_cascade(size_t bs, size_t bs2)
{
    if (bs == bs2)
        return bs;
    
    size_t gcd = euclids_algorithm(bs, bs2);
    
    return (bs * bs2) / gcd;
}
