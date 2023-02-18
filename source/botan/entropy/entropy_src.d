/**
* EntropySource
* 
* Copyright:
* (C) 2008-2009,2014 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.entropy.entropy_src;

import memutils.vector;
import botan.utils.types;

/**
* Class used to accumulate the poll results of EntropySources
*/
struct EntropyAccumulator
{
public:
    /**
    * Initialize an EntropyAccumulator
    * Params:
    *  accum = a delegate to send the bytes and entropy value
    */
    this(bool delegate(const(ubyte)*, size_t len, double) accum)
    {
        m_accum_fn = accum; 
        m_done = false;
    }

    ~this() {}

    /**
    * Get a cached I/O buffer (purely for minimizing allocation
    * overhead to polls)
    *
    * Params:
    *  size = requested size for the I/O buffer
    * Returns: cached I/O buffer for repeated polls
    */
    ref SecureVector!ubyte getIoBuffer(size_t size) return
    {
        m_io_buffer.clear();
        m_io_buffer.resize(size);
        return m_io_buffer;
    }

    /**
    * Returns: if our polling goal has been achieved
    */
    bool pollingGoalAchieved() const { return m_done; }

    /**
    * Add entropy to the accumulator
    * Params:
    *  bytes = the input bytes
    *  length = specifies how many bytes the input is
    *  entropy_bits_per_byte = is a best guess at how much
    * entropy per ubyte is in this input
    */
    void add(const void* bytes, size_t length, double entropy_bits_per_byte)
    {
        m_done = m_accum_fn(cast(const(ubyte)*)(bytes), length, entropy_bits_per_byte * length);
    }

    /**
    * Add entropy to the accumulator
    * Params:
    *  v = is some value
    *  entropy_bits_per_byte = is a best guess at how much
    * entropy per ubyte is in this input
    */
    void add(T)(in T v, double entropy_bits_per_byte)
    {
        add(&v, T.sizeof, entropy_bits_per_byte);
    }
private:
    bool delegate(const(ubyte)*, size_t, double) m_accum_fn;
    bool m_done;
    SecureVector!ubyte m_io_buffer;
}

/**
* Abstract interface to a source of entropy
*/
interface EntropySource
{
public:
    /**
    * Returns: name identifying this entropy source
    */
    @property string name() const;

    /**
    * Perform an entropy gathering poll
    * Params:
    *  accum = is an accumulator object that will be given entropy
    */
    void poll(ref EntropyAccumulator accum);
}