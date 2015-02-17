/**
* Output Buffer
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*     2012 Markus Wanner
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.filters.out_buf;

import botan.utils.types;
import botan.filters.pipe;
import botan.filters.secqueue;
/**
* Container of output buffers for Pipe
*/
struct OutputBuffers
{
public:
    /*
    * Read data from a message
    */
    size_t read(ubyte* output, size_t length,
                Pipe.message_id msg)
    {
        SecureQueue q = get(msg);
        if (q)
            return q.read(output, length);
        return 0;
    }

    /*
    * Peek at data in a message
    */
    size_t peek(ubyte* output, size_t length,
                size_t stream_offset,
                Pipe.message_id msg) const
    {
        SecureQueue q = get(msg);
        if (q)
            return q.peek(output, length, stream_offset);
        return 0;
    }

    /*
    * Return the total bytes of a message that have already been read.
    */
    size_t getBytesRead(Pipe.message_id msg) const
    {
        SecureQueue q = get(msg);
        if (q)
            return q.getBytesRead();
        return 0;
    }

    /*
    * Check available bytes in a message
    */
    size_t remaining(Pipe.message_id msg) const
    {
        SecureQueue q = get(msg);
        if (q)
            return q.length;
        return 0;
    }

    /*
    * Add a new output queue
    */
    void add(SecureQueue queue)
    {
        assert(queue, "queue was provided");
        
        // assert(m_buffers.length < m_buffers.capacity, "Room was available in container");
        
        m_buffers.pushBack(queue);
    }

    /*
    * Retire old output queues
    */
    void retire()
    {
        foreach (size_t i; 0 .. m_buffers.length)
            if (m_buffers[i] && m_buffers[i].length == 0)
        {
            destroy(m_buffers[i]);
            m_buffers[i] = null;
        }
        
        while (m_buffers.length && !m_buffers[0])
        {
            m_buffers = Array!SecureQueue(m_buffers[1 .. $]);
            m_offset = m_offset + Pipe.message_id(1);
        }
    }

    /*
    * Return the total number of messages
    */
    Pipe.message_id messageCount() const
    {
        return (m_offset + m_buffers.length);
    }

    ~this()
    {
        for (size_t j = 0; j != m_buffers.length; ++j)
            destroy(m_buffers[j]);
    }
private:
    /*
    * Get a particular output queue
    */
    SecureQueue get(Pipe.message_id msg) const
    {
        if (msg < m_offset)
            return null;
        
        assert(msg < messageCount(), "Message number is in range");
        
        return m_buffers[msg - m_offset];
    }

    Array!SecureQueue m_buffers;
    Pipe.message_id m_offset;
}
