/**
* SecureQueue
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*     2012 Markus Wanner
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.filters.secqueue;

import botan.filters.data_src;
import botan.filters.filter;
import botan.utils.types;
import botan.utils.mem_ops;
import botan.constants;
import std.algorithm;
/**
* A queue that knows how to zeroise itself
*/
final class SecureQueue : FanoutFilter, DataSourceImpl, Filterable
{
public:
    override @property string name() const { return "Queue"; }

    /*
    * Add some bytes to the queue
    */
    override void write(const(ubyte)* input, size_t length)
    {
        if (!m_head)
            m_head = m_tail = new SecureQueueNode;
        while (length)
        {
            const size_t n = m_tail.write(input, length);
            input += n;
            length -= n;
            if (length)
            {
                m_tail.m_next = new SecureQueueNode;
                m_tail = m_tail.m_next;
            }
        }
    }

    /*
    * Read some bytes from the queue
    */
    size_t read(ubyte* output, size_t length)
    {
        size_t got = 0;
        while (length && m_head)
        {
            const size_t n = m_head.read(output, length);
            output += n;
            got += n;
            length -= n;
            if (m_head.length == 0)
            {
                SecureQueueNode holder = m_head.m_next;
                .destroy(m_head);
                m_head = holder;
            }
        }
        bytes_read += got;
        return got;
    }

    /*
    * Read data, but do not remove it from queue
    */
    size_t peek(ubyte* output, size_t length, size_t offset = 0) const
    {
        SecureQueueNode current = cast(SecureQueueNode) m_head;
        
        while (offset && current)
        {
            if (offset >= current.length)
            {
                offset -= current.length;
                current = current.m_next;
            }
            else
                break;
        }
        
        size_t got = 0;
        while (length && current)
        {
            const size_t n = current.peek(output, length, offset);
            offset = 0;
            output += n;
            got += n;
            length -= n;
            current = current.m_next;
        }
        return got;
    }

    /**
    * Return how many bytes have been read so far.
    */
    size_t getBytesRead() const
    {
        return bytes_read;
    }

    /*
    * Test if the queue has any data in it
    */
    bool endOfData() const
    {
        return (size() == 0);
    }


    @property bool empty() const
    {
        return (size() == 0);
    }

    /**
    * Returns: number of bytes available in the queue
    */
    size_t size() const
    {
        SecureQueueNode current = cast(SecureQueueNode) m_head;
        size_t count = 0;
        
        while (current)
        {
            count += current.length;
            current = current.m_next;
        }
        return count;
    }

    @property size_t length() const { return size(); } 

    override bool attachable() { return false; }

    /**
    * SecureQueue default constructor (creates empty queue)
    */
    this()
    {
        bytes_read = 0;
        Filter filt;
        setNext(&filt, 0);
        m_head = m_tail = new SecureQueueNode;
    }

    /**
    * SecureQueue copy constructor
    * Params:
    *  other = the queue to copy
    */
    this(SecureQueue input)
    {
        bytes_read = 0;
        Filter filt;
        setNext(&filt, 0);
        
        m_head = m_tail = new SecureQueueNode;
        SecureQueueNode temp = input.m_head;
        while (temp)
        {
            write(&temp.m_buffer[temp.m_start], temp.m_end - temp.m_start);
            temp = temp.m_next;
        }
    }

    ~this() { destroy(); }

    // Interface fallthrough
    override void startMsg() { super.startMsg(); }
    override void endMsg() { super.endMsg(); }
    override string id() const { return ""; }
    override void setNext(Filter* filters, size_t sz) { super.setNext(filters, sz); }
private:
    size_t bytes_read;

    /*
    * Destroy this SecureQueue
    */
    void destroy()
    {
        SecureQueueNode temp = m_head;
        while (temp)
        {
            SecureQueueNode holder = temp.m_next;
            .destroy(temp);
            temp = holder;
        }
        m_head = m_tail = null;
    }

    SecureQueueNode m_head;
    SecureQueueNode m_tail;
}

/**
* A node in a SecureQueue
*/
class SecureQueueNode
{
public:

    this() 
    { 
        m_buffer = SecureVector!ubyte(DEFAULT_BUFFERSIZE);
        m_next = null; 
        m_start = m_end = 0; }
    
    ~this() { 
        m_next = null; 
        m_start = m_end = 0; 
    }

    size_t write(const(ubyte)* input, size_t length)
    {
        size_t copied = std.algorithm.min(length, m_buffer.length - m_end);
        copyMem(&m_buffer[m_end], input, copied);
        m_end += copied;
        return copied;
    }
    
    size_t read(ubyte* output, size_t length)
    {
        size_t copied = std.algorithm.min(length, m_end - m_start);
        copyMem(output, &m_buffer[m_start], copied);
        m_start += copied;
        return copied;
    }
    
    size_t peek(ubyte* output, size_t length, size_t offset = 0)
    {
        const size_t left = m_end - m_start;
        if (offset >= left) return 0;
        size_t copied = std.algorithm.min(length, left - offset);
        copyMem(output, &m_buffer[m_start + offset], copied);
        return copied;
    }
    
    size_t size() const { return (m_end - m_start); }
    @property size_t length() const { return size(); }
private:
    SecureQueueNode m_next;
    SecureVector!ubyte m_buffer;
    size_t m_start, m_end;
}