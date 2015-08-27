/**
* DESX
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.block.desx;

import botan.constants;
static if (BOTAN_HAS_DES):

import botan.block.des;
import botan.utils.xor_buf;
import botan.utils.mem_ops;

/**
* DESX
*/
final class DESX : BlockCipherFixedParams!(8, 24), BlockCipher, SymmetricAlgorithm
{
public:
    /*
    * DESX Encryption
    */
    override void encryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        foreach (size_t i; 0 .. blocks)
        {
            xorBuf(output, cast(ubyte*)input, m_K1.ptr, BLOCK_SIZE);
            m_des.encrypt(output);
            xorBuf(output, cast(ubyte*)m_K2.ptr, BLOCK_SIZE);
            
            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }

    /*
    * DESX Decryption
    */
    override void decryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {    
        foreach (size_t i; 0 .. blocks)
        {
            xorBuf(output, cast(ubyte*)input, m_K2.ptr, BLOCK_SIZE);
            m_des.decrypt(output);
            xorBuf(output, m_K1.ptr, BLOCK_SIZE);
            
            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }

    override void clear()
    {
        m_des = new DES;
        zap(m_K1);
        zap(m_K2);
    }

    @property string name() const { return "DESX"; }
    override @property size_t parallelism() const { return 1; }
    override BlockCipher clone() const { return new DESX; }
    override size_t blockSize() const { return super.blockSize(); }
    override KeyLengthSpecification keySpec() const { return super.keySpec(); }

protected:
    /*
    * DESX Key Schedule
    */
    override void keySchedule(const(ubyte)* key, size_t)
    {
        m_K1[] = key[0 .. 8];
        m_des.setKey(key + 8, 8);
        m_K2[] = key[16 .. 24];
    }

    SecureVector!ubyte m_K1, m_K2;
    Unique!DES m_des;
}
