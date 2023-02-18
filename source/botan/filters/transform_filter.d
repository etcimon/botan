/**
* Filter interface for Transformations
* 
* Copyright:
* (C) 2013 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.filters.transform_filter;

import botan.constants;
public import botan.algo_base.transform;
public import botan.filters.key_filt;
import botan.filters.transform_filter;
import botan.stream.stream_cipher;
import botan.utils.rounding;
import botan.utils.mem_ops;
import std.algorithm : min;

/**
* Filter interface for Transformations
*/
class TransformationFilter : KeyedFilter, Filterable
{
public:
    this(Transformation transform)
    {
        m_main_block_mod = chooseUpdateSize(transform.updateGranularity());
        m_final_minimum = transform.minimumFinalSize();
        
        if (m_main_block_mod == 0)
            throw new InvalidArgument("main_block_mod == 0");
        
        if (m_final_minimum > m_main_block_mod)
            throw new InvalidArgument("final_minimum > main_block_mod");
        m_buffer_2.resize(2 * m_main_block_mod);
        m_buffer_pos = 0;
        m_nonce = NonceState(transform.defaultNonceLength() == 0);
        m_transform = transform;
        m_buffer = m_transform.updateGranularity();
    }

    override final void setIv(in InitializationVector iv)
    {
        m_nonce.update(*cast(InitializationVector*)&iv);
    }

    override final void setKey(in SymmetricKey key)
    {
        if (KeyedTransform keyed = cast(KeyedTransform)(*m_transform))
            keyed.setKey(key);
        else if (key.length != 0)
            throw new Exception("Transformation " ~ name ~ " does not accept keys");
    }

    override final KeyLengthSpecification keySpec() const
    {
        if (KeyedTransform keyed = cast(KeyedTransform)(*m_transform))
            return keyed.keySpec();
        return KeyLengthSpecification(0);
    }

    override final bool validIvLength(size_t length) const
    {
        return m_transform.validNonceLength(length);
    }

    override @property string name() const
    {
        return m_transform.name;
    }
    /**
    * Write bytes into the buffered filter, which will them emit them
    * in calls to bufferedBlock in the subclass
    * Params:
    *  input = the input bytes
    *  input_size = of input in bytes
    */
    override void write(const(ubyte)* input, size_t input_size)
    {
        if (!input_size)
            return;

        if (m_buffer_pos + input_size >= m_main_block_mod + m_final_minimum)
        {
            size_t to_copy = min(m_buffer_2.length - m_buffer_pos, input_size);

            // assert(m_buffer_2.length > to_copy);

            copyMem(&m_buffer_2[m_buffer_pos], input, to_copy);

            m_buffer_pos += to_copy;
            
            input += to_copy;
            input_size -= to_copy;
            
            size_t total_to_consume = roundDown(min(m_buffer_pos,
                                                    m_buffer_pos + input_size - m_final_minimum),
                                                m_main_block_mod);
            
            bufferedBlock(m_buffer_2.ptr, total_to_consume);
            m_buffer_pos -= total_to_consume;
            // assert(m_buffer_2.length > total_to_consume);
            copyMem(m_buffer_2.ptr, m_buffer_2.ptr + total_to_consume, m_buffer_pos);
        }
        
        if (input_size >= m_final_minimum)
        {
            size_t full_blocks = (input_size - m_final_minimum) / m_main_block_mod;
            size_t to_copy = full_blocks * m_main_block_mod;
            
            if (to_copy)
            {
                bufferedBlock(input, to_copy);
                
                input += to_copy;
                input_size -= to_copy;
            }
        }
        
        // assert(m_buffer_pos + input_size < m_buffer_2.length);
        copyMem(&m_buffer_2[m_buffer_pos], input, input_size);
        m_buffer_pos += input_size;
    }
    
    void write(Alloc)(const ref Vector!( ubyte, Alloc ) input)
    {
        write(input.ptr, input.length);
    }

    // Interface fallthrough
    override bool attachable() { return super.attachable(); }
    override void setNext(Filter* filters, size_t sz) { super.setNext(filters, sz); }

protected:
    /**
    * Returns: block size of inputs
    */
    size_t bufferedBlockSize() const { return m_main_block_mod; }
    
    /**
    * Returns: current position in the buffer
    */
    size_t currentPosition() const { return m_buffer_pos; }
    
    /**
    * Reset the buffer position
    */
    void bufferReset() { m_buffer_pos = 0; }

    final const(Transformation) getTransform() const { return *m_transform; }

    final Transformation getTransform() { return *m_transform; }

    /**
    * Finish a message, emitting to bufferedBlock and bufferedFinal
    * Will throw new an exception if less than final_minimum bytes were
    * written into the filter.
    */
    override void endMsg()
    {
        if (m_buffer_pos < m_final_minimum)
            throw new Exception("Buffered filter endMsg without enough input");
        
        size_t spare_blocks = (m_buffer_pos - m_final_minimum) / m_main_block_mod;
        
        if (spare_blocks)
        {
            size_t spare_bytes = m_main_block_mod * spare_blocks;
            bufferedBlock(m_buffer_2.ptr, spare_bytes);
            bufferedFinal(&m_buffer_2[spare_bytes], m_buffer_pos - spare_bytes);
        }
        else
        {
            bufferedFinal(m_buffer_2.ptr, m_buffer_pos);
        }
        m_buffer_pos = 0;

        //scope(exit) logTrace("endMsg(): ", m_buffer[]);
    }

    override void startMsg()
    {
        send(m_transform.start(m_nonce.get()));
    }

private:

    /**
    * The block processor, implemented by subclasses
    * Params:
    *  input = some input bytes
    *  length = the size of input, guaranteed to be a multiple
    *          of block_size
    */
    final void bufferedBlock(const(ubyte)* input, size_t input_length)
    {
        while (input_length)
        {
            const size_t take = min(m_transform.updateGranularity(), input_length);
            m_buffer = SecureVector!ubyte(input[0 .. take]);
            m_transform.update(m_buffer);
            
            send(m_buffer);
            
            input += take;
            input_length -= take;
        }
    }

    /**
    * The final block, implemented by subclasses
    * Params:
    *  input = some input bytes
    *  length = the size of input, guaranteed to be at least
    *          final_minimum bytes
    */
    final void bufferedFinal(const(ubyte)* input, size_t input_length)
    {
        SecureVector!ubyte buf;
        buf[] = input[0 .. input_length];
        m_transform.finish(buf);
        send(buf);
    }

    struct NonceState
    {
    public:
        this(bool allow_null_nonce)
        {
            m_fresh_nonce = allow_null_nonce;
        }

        void update(in InitializationVector iv)
        {
            m_nonce = unlock(iv.bitsOf());
            m_fresh_nonce = true;
        }

        ref Vector!ubyte get() return
        {
            assert(m_fresh_nonce, "The nonce is fresh for this message");
            
            if (!m_nonce.empty)
                m_fresh_nonce = false;
            return m_nonce;
        }
    private:
        bool m_fresh_nonce;
        Vector!ubyte m_nonce;
    }

private:

    size_t m_main_block_mod, m_final_minimum;
    NonceState m_nonce;
    Unique!Transformation m_transform;
    SecureVector!ubyte m_buffer;
    SecureVector!ubyte m_buffer_2;
    size_t m_buffer_pos;
}

private:

size_t chooseUpdateSize(size_t update_granularity)
{
    const size_t target_size = 1024;
    
    if (update_granularity >= target_size)
        return update_granularity;
    
    return roundUp(target_size, update_granularity);
}