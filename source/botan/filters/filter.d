/**
* Filter
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
* (C) 2013 Joel Low
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.filters.filter;

import memutils.vector;
import botan.utils.types;
import botan.filters.secqueue;
import botan.utils.exceptn;

interface Filterable {
public:
    /**
    * Returns: descriptive name for this filter
    */
    @property string name() const;
    
    /**
    * Write a portion of a message to this filter.
    *
    * Params:
    *  input = the input as a ubyte array
    *  length = the length of the ubyte array input
    */
    void write(const(ubyte)* input, size_t length);
    
    /**
    * Start a new message. Must be closed by endMsg() before another
    * message can be started.
    */
    void startMsg();
    
    /**
    * Notify that the current message is finished; flush buffers and
    * do end-of-message processing (if any).
    */
    void endMsg();
    
    /**
    * Check whether this filter is an attachable filter.
    * Returns: true if this filter is attachable, false otherwise
    */
    bool attachable();

    /**
    * Params:
    *  filters = the filters to set
    *  count = number of items in filters
    */
    void setNext(Filter* filters, size_t size);

}

/**
* This class represents general abstract filter objects.
*/
abstract class Filter : Filterable
{
public:
    /**
    * Write a portion of a message to this filter.
    *
    * Params:
    *  input = the input as a ubyte array
    */
    final void write(const(ubyte)[] input) { write(input.ptr, input.length); }

    abstract void write(const(ubyte)* input, size_t length);

    /**
    * Params:
    *  input = some input for the filter
    *  length = the length of in
    */
    void send(const(ubyte)* input, size_t length)
    {
        if (!length)
            return;
        
        bool nothing_attached = true;
        foreach (size_t j; 0 .. totalPorts())
            if (m_next[j])
        {
            if (m_write_queue.length)
                m_next[j].write(m_write_queue.ptr, m_write_queue.length);
            m_next[j].write(input, length);
            nothing_attached = false;
        }
        
        if (nothing_attached)
            m_write_queue ~= input[0 .. length];
        else
            m_write_queue.clear();
    }


    /**
    * Params:
    *  input = some input for the filter
    */
    final void send(ubyte input) { send(&input, 1); }

    /**
    * Params:
    *  input = some input for the filter
    */
    final void send(ALLOC)(auto const ref Vector!(ubyte, ALLOC) input) { send(input.ptr, input.length); }

    /**
    * Params:
    *  input = some input for the filter
    */
    final void send(ALLOC)(auto const ref RefCounted!(Vector!(ubyte, ALLOC), ALLOC) input) { send(input.ptr, input.length); }

    /**
    * Params:
    *  input = some input for the filter
    *  length = the number of bytes of in to send
    */
    final void send(ALLOC)(auto const ref Vector!(ubyte, ALLOC) input, size_t length)
    {
        send(input.ptr, length);
    }

    /**
    * Params:
    *  input = some input for the filter
    *  length = the number of bytes of in to send
    */
    final void send(ALLOC)(auto const ref RefCounted!(Vector!(ubyte, ALLOC), ALLOC) input, size_t length)
    {
        send(input.ptr, length);
    }

    /*
    * Filter Constructor
    */
    this()
    {
        m_next.resize(1);
        m_port_num = 0;
        m_filter_owns = 0;
        m_owned = false;
    }

    /**
    * Start a new message in this and all following filters. Only for
    * internal use, not intended for use in client applications.
    */
    void newMsg()
    {
        startMsg();
        foreach (size_t j; 0 .. totalPorts())
            if (m_next[j])
                m_next[j].newMsg();
    }

    /**
    * End a new message in this and all following filters. Only for
    * internal use, not intended for use in client applications.
    */
    void finishMsg()
    {
        endMsg();
        foreach (size_t j; 0 .. totalPorts())
            if (m_next[j])
                m_next[j].finishMsg();
    }

    /*
    * Return the total number of ports
    */
    size_t totalPorts() const
    {
        return m_next.length;
    }

    size_t currentPort() const { return m_port_num; }

    /**
    * Set the active port
    * Params:
    *  new_port = the new value
    */
    void setPort(size_t new_port)
    {
        if (new_port >= totalPorts())
            throw new InvalidArgument("Filter: Invalid port number");
        m_port_num = new_port;
    }

    size_t owns() const { return m_filter_owns; }

    /**
    * Attach another filter to this one
    * Params:
    *  f = filter to attach
    */
    void attach(Filter new_filter)
    {
        if (new_filter)
        {
            Filter last = this;
            while (last.getNext())
                last = last.getNext();
            last.m_next[last.currentPort()] = new_filter;
        }
    }

    /**
    * Params:
    *  filters = the filters to set
    *  count = number of items in filters
    */
    override void setNext(Filter* filters, size_t size)
    {
        m_next.clear();
        
        m_port_num = 0;
        m_filter_owns = 0;
        
        while (size && filters && (filters[size-1] is null))
            --size;
        
        if (filters && size)
            m_next[] = filters[0 .. size];
    }


    /*
    * Return the next Filter in the logical chain
    */
    Filter getNext() const
    {
        if (m_port_num < m_next.length)
            return m_next[m_port_num];
        return null;
    }

    abstract bool attachable() { return true; }
    abstract void startMsg() {}
    abstract void endMsg() {}
    abstract @property string name() const;

    SecureVector!ubyte m_write_queue;
    Vector!Filter m_next;
    size_t m_port_num, m_filter_owns;

    // true if filter belongs to a pipe -. prohibit filter sharing!
    bool m_owned;
}

/**
* This is the abstract FanoutFilter base class.
**/
class FanoutFilter : Filter, Filterable
{
protected:
    /**
    * Increment the number of filters past us that we own
    */
    void incrOwns() { ++m_filter_owns; }

    void setNext(Filter f, size_t n) { super.setNext(&f, 1); }

    override void setPort(size_t n) { setPort(n); }

    override void setNext(Filter* f, size_t n) { super.setNext(f, n); }

    override void attach(Filter f) { attach(f); }

}

/**
* The type of checking to be performed by decoders:
* NONE - no checks, IGNORE_WS - perform checks, but ignore
* whitespaces, FULL_CHECK - perform checks, also complain
* about white spaces.
*/
alias DecoderChecking = ubyte;
enum : DecoderChecking { NONE, IGNORE_WS, FULL_CHECK }
