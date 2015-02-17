/**
* Pipe
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*     2012 Markus Wanner
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.filters.pipe;

import botan.constants;
import botan.filters.data_src;
import botan.filters.filter;
import botan.utils.exceptn;
//static if (BOTAN_HAS_PIPE_UNIXFD_IO && false)
 //   import botan.fd_unix;

import botan.filters.out_buf;
import botan.filters.secqueue;
import botan.utils.parsing;
import botan.utils.types;
import std.conv : to;
import std.array : Appender;


/**
* This class represents pipe objects.
* A set of filters can be placed into a pipe, and information flows
* through the pipe until it reaches the end, where the output is
* collected for retrieval.  If you're familiar with the Unix shell
* environment, this design will sound quite familiar.
*/
struct Pipe
{
public:

    /**
    * An opaque type that identifies a message in this Pipe
    */
    alias message_id = size_t;

    /**
    * Exception if you use an invalid message as an argument to
    * read, remaining, etc
    */
    class InvalidMessageNumber : InvalidArgument
    {
        /**
        * Params:
        *  where = the error occured
        *  msg = the invalid message id that was used
        */
        this(in string where, message_id msg) {
            super("Pipe:" ~ where ~ ": Invalid message number " ~ to!string(msg));
        }
    }

    /**
    * A meta-id for whatever the last message is
    */
    static const message_id LAST_MESSAGE = cast(message_id)(-2);

    /**
    * A meta-id for the default message (set with set_defaultMsg)
    */
    static const message_id DEFAULT_MESSAGE = cast(message_id)(-1);

    /**
    * Write input to the pipe, i.e. to its first filter.
    *
    * Params:
    *  input = the ubyte array to write
    *  length = the length of the ubyte array in
    */
    void write(const(ubyte)* input, size_t length)
    {
        if (!m_inside_msg)
            throw new InvalidState("Cannot write to a Pipe while it is not processing");
        m_pipe_to.write(input, length);
    }

    /**
    * Write input to the pipe, i.e. to its first filter.
    *
    * Params:
    *  input = the SecureVector containing the data to write
    */
    void write(T, ALLOC)(auto const ref RefCounted!(Vector!(T, ALLOC), ALLOC) input)
    { write(input.ptr, input.length); }

    /**
    * Write input to the pipe, i.e. to its first filter.
    *
    * Params:
    *  input = the std::vector containing the data to write
    */
    void write(T, ALLOC)(auto const ref Vector!(T, ALLOC) input)
    { write(input.ptr, input.length); }

    /**
    * Write input to the pipe, i.e. to its first filter.
    *
    * Params:
    *  input = the string containing the data to write
    */
    void write(string input)
    {
        write(cast(const(ubyte)*)input.ptr, input.length);
    }

    /**
    * Write input to the pipe, i.e. to its first filter.
    *
    * Params:
    *  input = the DataSource to read the data from
    */
    void write(DataSource source)
    {
        SecureVector!ubyte buffer = SecureVector!ubyte(DEFAULT_BUFFERSIZE);
        while (!source.endOfData())
        {
            size_t got = source.read(buffer.ptr, buffer.length);
            write(buffer.ptr, got);
        }
    }

    /**
    * Write input to the pipe, i.e. to its first filter.
    *
    * Params:
    *  input = a single ubyte to be written
    */
    void write(ubyte input)
    {
        write(&input, 1);
    }

    /**
    * Write input to the pipe, i.e. to its first filter.
    *
    * Params:
    *  input = a ubyte array to be written
    */
    void write(ubyte[] input)
    {
        write(cast(const(ubyte)*)input.ptr, input.length);
    }

    /**
    * Perform startMsg(), write() and endMsg() sequentially.
    *
    * Params:
    *  input = the ubyte array containing the data to write
    *  length = the length of the ubyte array to write
    */
    void processMsg(const(ubyte)* input, size_t length)
    {
        startMsg();
        write(input, length);
        endMsg();
    }

    /**
    * Perform startMsg(), write() and endMsg() sequentially.
    *
    * Params:
    *  input = the SecureVector containing the data to write
    */
    void processMsg(ALLOC)(auto const ref Vector!(ubyte, ALLOC) input)
    {
        processMsg(input.ptr, input.length);
    }

    /**
    * Perform startMsg(), write() and endMsg() sequentially.
    *
    * Params:
    *  input = the SecureVector containing the data to write
    */
    void processMsg(ALLOC)(auto const ref RefCounted!(Vector!(ubyte, ALLOC), ALLOC) input)
    {
        processMsg(input.ptr, input.length);
    }

    /**
    * Perform startMsg(), write() and endMsg() sequentially.
    *
    * Params:
    *  input = the string containing the data to write
    */
    void processMsg(string input)
    {
        processMsg(cast(const(ubyte)*)(input.ptr), input.length);
    }

    /**
    * Perform startMsg(), write() and endMsg() sequentially.
    *
    * Params:
    *  input = the DataSource providing the data to write
    */
    void processMsg(DataSource input)
    {
        startMsg();
        write(input);
        endMsg();
    }

    /**
    * Find out how many bytes are ready to read.
    *
    * Params:
    *  msg = the number identifying the message
    * for which the information is desired
    * Returns: number of bytes that can still be read
    */
    size_t remaining(message_id msg = DEFAULT_MESSAGE) const
    {
        return m_outputs.remaining(getMessageNo("remaining", msg));
    }

    /**
    * Read the default message from the pipe. Moves the internal
    * offset so that every call to read will return a new portion of
    * the message.
    *
    * Params:
    *  output = the ubyte array to write the read bytes to
    *  length = the length of the ubyte array output
    * Returns: number of bytes actually read into output
    */
    size_t read(ubyte* output, size_t length)
    {
        return read(output, length, DEFAULT_MESSAGE);
    }

    /**
    * Read a specified message from the pipe. Moves the internal
    * offset so that every call to read will return a new portion of
    * the message.
    *
    * Params:
    *  output = the ubyte array to write the read bytes to
    *  length = the length of the ubyte array output
    *  msg = the number identifying the message to read from
    * Returns: number of bytes actually read into output
    */
    size_t read(ubyte* output, size_t length, message_id msg)
    {
        return m_outputs.read(output, length, getMessageNo("read", msg));
    }

    /**
    * Read a specified message from the pipe. Moves the internal
    * offset so that every call to read will return a new portion of
    * the message.
    *
    * Params:
    *  output = the ubyte array to write the read bytes to
    *  msg = the number identifying the message to read from
    * Returns: number of bytes actually read into output
    */
    size_t read(ref ubyte[] output, message_id msg = DEFAULT_MESSAGE)
    {
        return m_outputs.read(output.ptr, output.length, getMessageNo("read", msg));
    }

    /**
    * Read a single ubyte from the pipe. Moves the internal offset so
    * that every call to read will return a new portion of the
    * message.
    *
    * Params:
    *  output = the ubyte to write the result to
    *  msg = the message to read from
    * Returns: number of bytes actually read into output
    */
    size_t read(ref ubyte output, message_id msg = DEFAULT_MESSAGE)
    {
        return read(&output, 1, msg);
    }

    /**
    * Read the full contents of the pipe.
    *
    * Params:
    *  msg = the number identifying the message to read from
    * Returns: SecureVector holding the contents of the pipe
    */
    SecureVector!ubyte readAll(message_id msg = DEFAULT_MESSAGE)
    {
        msg = ((msg != DEFAULT_MESSAGE) ? msg : defaultMsg());
        SecureArray!ubyte buffer = SecureVector!ubyte(remaining(msg));
        size_t got = read(buffer.ptr, buffer.length, msg);
        buffer.resize(got);
        return buffer.move();
    }

    /**
    * Read the full contents of the pipe.
    *
    * Params:
    *  msg = the number identifying the message to read from
    * Returns: string holding the contents of the pipe
    */
    string toString(message_id msg = DEFAULT_MESSAGE)
    {
        msg = ((msg != DEFAULT_MESSAGE) ? msg : defaultMsg());
        SecureVector!ubyte buffer = SecureVector!ubyte(DEFAULT_BUFFERSIZE);
        Appender!string str;
        str.reserve(remaining(msg));
        
        while (true)
        {
            size_t got = read(buffer.ptr, buffer.length, msg);
            if (got == 0)
                break;
            str ~= buffer.ptr[0 .. got];
        }
        
        return str.data;
    }

    /** Read from the default message but do not modify the internal
    * offset. Consecutive calls to peek() will return portions of
    * the message starting at the same position.
    *
    * Params:
    *  output = the ubyte array to write the peeked message part to
    *  length = the length of the ubyte array output
    *  offset = the offset from the current position in message
    * Returns: number of bytes actually peeked and written into output
    */
    size_t peek(ubyte* output, size_t length, size_t offset, message_id msg = DEFAULT_MESSAGE) const
    {
        return m_outputs.peek(output, length, offset, getMessageNo("peek", msg));
    }

    /** Read from the specified message but do not modify the
    * internal offset. Consecutive calls to peek() will return
    * portions of the message starting at the same position.
    *
    * Params:
    *  output = the ubyte array to write the peeked message part to
    *  length = the length of the ubyte array output
    *  offset = the offset from the current position in message
    *  msg = the number identifying the message to peek from
    * Returns: number of bytes actually peeked and written into output
    */
    size_t peek(ref ubyte[] output, size_t offset, message_id msg = DEFAULT_MESSAGE) const
    {
        return peek(output.ptr, output.length, offset, DEFAULT_MESSAGE);
    }

    /** Read a single ubyte from the specified message but do not
    * modify the internal offset. Consecutive calls to peek() will
    * return portions of the message starting at the same position.
    *
    * Params:
    *  output = the ubyte to write the peeked message ubyte to
    *  offset = the offset from the current position in message
    *  msg = the number identifying the message to peek from
    * Returns: number of bytes actually peeked and written into output
    */
    size_t peek(ref ubyte output, size_t offset, message_id msg = DEFAULT_MESSAGE) const
    {
        return peek(&output, 1, offset, msg);
    }

    /**
    * Read one ubyte.
    *
    * Params:
    *  output = the ubyte to read to
    * Returns: length in bytes that was actually read and put
    * into out
    */
    size_t readByte(ref ubyte output)
    {
        return read(&output, 1);
    }
    
    
    /**
    * Peek at one ubyte.
    *
    * Params:
    *  output = an output ubyte
    * Returns: length in bytes that was actually read and put
    * into out
    */
    size_t peekByte(ref ubyte output) const
    {
        return peek(&output, 1, 0);
    }
    
    
    /**
    * Discard the next N bytes of the data
    * Params:
    *  N = the number of bytes to discard
    * Returns: number of bytes actually discarded
    */
    size_t discardNext(size_t n)
    {
        size_t discarded = 0;
        ubyte dummy;
        foreach (size_t j; 0 .. n)
            discarded += readByte(dummy);
        return discarded;
    }

    /**
    * Returns: the number of bytes read from the default message.
    */
    size_t getBytesRead() const
    {
        return m_outputs.getBytesRead(DEFAULT_MESSAGE);
    }

    /**
    * Returns: the number of bytes read from the specified message.
    */
    size_t getBytesRead(message_id msg = DEFAULT_MESSAGE) const
    {
        return m_outputs.getBytesRead(msg);
    }

    /**
    * Returns: currently set default message
    */
    size_t defaultMsg() const { return m_default_read; }

    /**
    * Set the default message
    * Params:
    *  msg = the number identifying the message which is going to
    * be the new default message
    */
    void setDefaultMsg(message_id msg)
    {
        if (msg >= messageCount())
            throw new InvalidArgument("Pipe::setDefaultMsg: msg number is too high");
        m_default_read = msg;
    }

    /**
    * Get the number of messages the are in this pipe.
    * Returns: number of messages the are in this pipe
    */
    message_id messageCount() const
    {
        return m_outputs.messageCount();
    }


    /**
    * Test whether this pipe has any data that can be read from.
    * Returns: true if there is more data to read, false otherwise
    */
    bool endOfData() const
    {
        return (remaining() == 0);
    }

    /**
    * Start a new message in the pipe. A potential other message in this pipe
    * must be closed with endMsg() before this function may be called.
    */
    void startMsg()
    {
        if (m_inside_msg)
            throw new InvalidState("Pipe::startMsg: Message was already started");
        if (!m_pipe_to)
            m_pipe_to = new NullFilter;
        findEndpoints(m_pipe_to);
        m_pipe_to.newMsg();
        m_inside_msg = true;
    }

    /**
    * End the current message.
    */
    void endMsg()
    {
        if (!m_inside_msg)
            throw new InvalidState("Pipe::endMsg: Message was already ended");
        m_pipe_to.finishMsg();
        clearEndpoints(m_pipe_to);
        if (cast(NullFilter)(m_pipe_to))
        {
            destroy(m_pipe_to);
            m_pipe_to = null;
        }
        m_inside_msg = false;
        
        m_outputs.retire();
    }

    /**
    * Insert a new filter at the front of the pipe
    * Params:
    *  filt = the new filter to insert
    */
    void prepend(Filter filter)
    {
        if (m_inside_msg)
            throw new InvalidState("Cannot prepend to a Pipe while it is processing");
        if (!filter)
            return;
        if (cast(SecureQueue)(filter))
            throw new InvalidArgument("Pipe::prepend: SecureQueue cannot be used");
        if (filter.m_owned)
            throw new InvalidArgument("Filters cannot be shared among multiple Pipes");
        
        filter.m_owned = true;
        
        if (m_pipe_to) filter.attach(m_pipe_to);
        m_pipe_to = filter;
    }

    /**
    * Insert a new filter at the back of the pipe
    * Params:
    *  filt = the new filter to insert
    */
    void append(Filter filter)
    {
        if (m_inside_msg)
            throw new InvalidState("Cannot append to a Pipe while it is processing");
        if (!filter)
            return;
        if (cast(SecureQueue)(filter))
            throw new InvalidArgument("Pipe::append: SecureQueue cannot be used");
        if (filter.m_owned)
            throw new InvalidArgument("Filters cannot be shared among multiple Pipes");
        
        filter.m_owned = true;
        
        if (!m_pipe_to) m_pipe_to = filter;
        else        m_pipe_to.attach(filter);
    }


    /**
    * Remove the first filter at the front of the pipe.
    */
    void pop()
    {
        if (m_inside_msg)
            throw new InvalidState("Cannot pop off a Pipe while it is processing");
        
        if (!m_pipe_to)
            return;
        
        if (m_pipe_to.totalPorts() > 1)
            throw new InvalidState("Cannot pop off a Filter with multiple ports");
        
        Filter f = m_pipe_to;
        size_t owns = f.owns();
        m_pipe_to = m_pipe_to.m_next[0];
        destroy(f);
        
        while (owns--)
        {
            f = m_pipe_to;
            m_pipe_to = m_pipe_to.m_next[0];
            destroy(f);
        }
    }


    /**
    * Reset this pipe to an empty pipe.
    */
    void reset()
    {
        destruct(m_pipe_to);
        m_pipe_to = null;
        m_inside_msg = false;
    }


    /**
    * Construct a Pipe of up to four filters. The filters are set up
    * in the same order as the arguments.
    */
    this(Filter f1 = null, Filter f2 = null, Filter f3 = null, Filter f4 = null)
    {
        init();
        append(f1);
        append(f2);
        append(f3);
        append(f4);
    }

    /**
    * Construct a Pipe from a list of filters
    * Params:
    *  filters = the set of filters to use
    */
    this(Filter[] filters)
    {
        init();
        
        foreach (filter; filters)
            append(filter);
    }

    ~this()
    {
        destruct(m_pipe_to);
    }

private:
    /*
    * Initialize the Pipe
    */
    void init()
    {
        m_pipe_to = null;
        m_default_read = 0;
        m_inside_msg = false;
    }

    /*
    * Destroy the Pipe
    */
    void destruct(Filter to_kill)
    {
        if (!to_kill || cast(SecureQueue)(to_kill))
            return;
        for (size_t j = 0; j != to_kill.totalPorts(); ++j)
            if (to_kill.m_next[j]) destruct(to_kill.m_next[j]);
        destroy(to_kill);
    }

    /*
    * Find the endpoints of the Pipe
    */
    void findEndpoints(Filter f)
    {
        for (size_t j = 0; j != f.totalPorts(); ++j)
            if (f.m_next[j] && !cast(SecureQueue)(f.m_next[j]))
                findEndpoints(f.m_next[j]);
            else
        {
            SecureQueue q = new SecureQueue;
            f.m_next[j] = q;
            m_outputs.add(q);
        }
    }

    /*
    * Remove the SecureQueues attached to the Filter
    */
    void clearEndpoints(Filter f)
    {
        if (!f) return;
        for (size_t j = 0; j != f.totalPorts(); ++j)
        {
            if (f.m_next[j] && cast(SecureQueue)(f.m_next[j]))
                f.m_next[j] = null;
            clearEndpoints(f.m_next[j]);
        }
    }

    /*
    * Look up the canonical ID for a queue
    */
    message_id getMessageNo(in string func_name,
                              message_id msg) const
    {
        if (msg == DEFAULT_MESSAGE)
            msg = defaultMsg();
        else if (msg == LAST_MESSAGE)
            msg = messageCount() - 1;
        
        if (msg >= messageCount())
            throw new InvalidMessageNumber(func_name, msg);
        
        return msg;
    }

    Filter m_pipe_to;
    OutputBuffers m_outputs;
    message_id m_default_read;
    bool m_inside_msg;

}

/*
* A Filter that does nothing
*/
final class NullFilter : Filter, Filterable
{
public:
    override void write(const(ubyte)* input, size_t length)
    { send(input, length); }
    
    override @property string name() const { return "Null"; }

    // Interface fallthrough
    override bool attachable() { return super.attachable(); }
    override void startMsg() { super.startMsg(); }
    override void endMsg() { super.endMsg(); }
    override void setNext(Filter* filters, size_t sz) { super.setNext(filters, sz); }
}