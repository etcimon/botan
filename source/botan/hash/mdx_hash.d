/**
* MDx Hash Function
* 
* Copyright:
* (C) 1999-2008 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.hash.mdx_hash;

public import botan.hash.hash;
import botan.utils.exceptn;
import botan.utils.loadstor;
import botan.utils.types;
import botan.utils.mem_ops;

/**
* MDx Hash Function Base Class
*/
class MDxHashFunction : HashFunction
{
public:
    /**
    * Params:
    *  block_len = is the number of bytes per block
    *  byte_end = specifies if the hash uses big-endian bytes
    *  bit_end = specifies if the hash uses big-endian bits
    *  cnt_size = specifies the size of the counter var in bytes
    */
    this(size_t block_len, bool byte_end, bool bit_end, size_t cnt_size = 8)
    {
        m_buffer.length = block_len;
        m_BIG_BYTE_ENDIAN = byte_end;
        m_BIG_BIT_ENDIAN = bit_end;
        m_COUNT_SIZE = cnt_size;
        m_count = m_position = 0;
    }

    override @property size_t hashBlockSize() const { return m_buffer.length; }
protected:
    /*
    * Update the hash
    */
    override final void addData(const(ubyte)* input, size_t length)
    {
        m_count += length;
        
        if (m_position)
        {
            bufferInsert(m_buffer, m_position, input, length);
            
            if (m_position + length >= m_buffer.length)
            {
                compressN(m_buffer.ptr, 1);
                input += (m_buffer.length - m_position);
                length -= (m_buffer.length - m_position);
                m_position = 0;
            }
        }
        
        const size_t full_blocks = length / m_buffer.length;
        const size_t remaining    = length % m_buffer.length;
        
        if (full_blocks)
            compressN(input, full_blocks);
        
        bufferInsert(m_buffer, m_position, input + full_blocks * m_buffer.length, remaining);
        m_position += remaining;
    }


    /*
    * Finalize a hash
    */
    override final void finalResult(ubyte* output)
    {
        m_buffer[m_position] = (m_BIG_BIT_ENDIAN ? 0x80 : 0x01);
        foreach (size_t i; (m_position+1) .. m_buffer.length)
            m_buffer[i] = 0;
        
        if (m_position >= m_buffer.length - m_COUNT_SIZE)
        {
            compressN(m_buffer.ptr, 1);
            zeroise(m_buffer);
        }
        writeCount(&m_buffer[m_buffer.length - m_COUNT_SIZE]);
        compressN(m_buffer.ptr, 1);
        copyOut(output);
        clear();
    }

    /**
    * Run the hash's compression function over a set of blocks
    * Params:
    *  blocks = the input
    *  block_n = the number of blocks
    */
    abstract void compressN(const(ubyte)* blocks, size_t block_n);

    /*
    * Clear memory of sensitive data
    */
    override void clear()
    {
        zeroise(m_buffer);
        m_count = m_position = 0;
    }

    /**
    * Copy the output to the buffer
    * Params:
    *  buffer = to put the output into
    */
    abstract void copyOut(ubyte* buffer);

    /**
    * Write the count, if used, to this spot
    * Params:
    *  output = where to write the counter to
    */
    final void writeCount(ubyte* output)
    {
        if (m_COUNT_SIZE < 8)
            throw new InvalidState("MDxHashFunction.writeCount: COUNT_SIZE < 8");
        if (m_COUNT_SIZE >= outputLength() || m_COUNT_SIZE >= hashBlockSize)
            throw new InvalidArgument("MDxHashFunction: COUNT_SIZE is too big");
        
        const ulong bit_count = m_count * 8;
        if (m_BIG_BYTE_ENDIAN)
            storeBigEndian(bit_count, output + m_COUNT_SIZE - 8);
        else
            storeLittleEndian(bit_count, output + m_COUNT_SIZE - 8);
    }
private:
    SecureVector!ubyte m_buffer;
    ulong m_count;
    size_t m_position;

    const bool m_BIG_BYTE_ENDIAN, m_BIG_BIT_ENDIAN;
    const size_t m_COUNT_SIZE;
}