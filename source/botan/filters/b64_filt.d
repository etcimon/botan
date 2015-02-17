/**
* Base64 Encoder/Decoder
* 
* Copyright:
* (C) 1999-2010 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.filters.b64_filt;

import botan.filters.filter;
import botan.codec.base64;
import botan.utils.charset;
import botan.utils.exceptn;
import botan.utils.types;
import botan.utils.mem_ops;
import std.algorithm;

/**
* This class represents a Base64 encoder.
*/
final class Base64Encoder : Filter, Filterable
{
public:
    override @property string name() const { return "Base64Encoder"; }

    /**
    * Input a part of a message to the encoder.
    *
    * Params:
    *  input = the message to input as a ubyte array
    *  length = the length of the ubyte array input
    */
    override void write(const(ubyte)* input, size_t length)
    {
        bufferInsert(m_input, m_position, input, length);
        if (m_position + length >= m_input.length)
        {
            encodeAndSend(m_input.ptr, m_input.length);
            input += (m_input.length - m_position);
            length -= (m_input.length - m_position);
            while (length >= m_input.length)
            {
                encodeAndSend(input, m_input.length);
                input += m_input.length;
                length -= m_input.length;
            }
            copyMem(m_input.ptr, input, length);
            m_position = 0;
        }
        m_position += length;
    }


    /**
    * Inform the Encoder that the current message shall be closed.
    */
    override void endMsg()
    {
        encodeAndSend(m_input.ptr, m_position, true);
        
        if (m_trailing_newline || (m_out_position && m_line_length))
            send('\n');
        
        m_out_position = m_position = 0;
    }

    /**
    * Create a base64 encoder.
    *
    * Params:
    *  breaks = whether to use line breaks in the output
    *  length = the length of the lines of the output
    *  t_n = whether to use a trailing newline
    */
    this(bool breaks = false, size_t length = 72, bool t_n = false) 
    {
        m_line_length = breaks ? length : 0;
        m_trailing_newline = t_n && breaks;
        m_input = 48;
        m_output = 64;
        m_position = 0;
        m_out_position = 0;
    }

    // Interface fallthrough
    override bool attachable() { return super.attachable(); }
    override void startMsg() { super.startMsg(); }
    override void setNext(Filter* filters, size_t sz) { super.setNext(filters, sz); }

private:
    /*
    * Encode and send a block
    */
    void encodeAndSend(const(ubyte)* input, size_t length,
                         bool final_inputs = false)
    {
        while (length)
        {
            const size_t proc = std.algorithm.min(length, m_input.length);
            
            size_t consumed = 0;
            size_t produced = base64Encode(cast(char*)(m_output.ptr), input,
                                            proc, consumed, final_inputs);
            
            doOutput(m_output.ptr, produced);
            
            // FIXME: s/proc/consumed/?
            input += proc;
            length -= proc;
        }
    }

    /*
    * Handle the output
    */
    void doOutput(const(ubyte)* input, size_t length)
    {
        if (m_line_length == 0)
            send(input, length);
        else
        {
            size_t remaining = length, offset = 0;
            while (remaining)
            {
                size_t sent = std.algorithm.min(m_line_length - m_out_position, remaining);
                send(input + offset, sent);
                m_out_position += sent;
                remaining -= sent;
                offset += sent;
                if (m_out_position == m_line_length)
                {
                    send('\n');
                    m_out_position = 0;
                }
            }
        }
    }


    const size_t m_line_length;
    const bool m_trailing_newline;
    Vector!ubyte m_input, m_output;
    size_t m_position, m_out_position;
}

/**
* This object represents a Base64 decoder.
*/
final class Base64Decoder : Filter, Filterable
{
public:
    override @property string name() const { return "Base64Decoder"; }

    /**
    * Input a part of a message to the decoder.
    *
    * Params:
    *  input = the message to input as a ubyte array
    *  length = the length of the ubyte array input
    */
    override void write(const(ubyte)* input, size_t length)
    {
        while (length)
        {
            size_t to_copy = std.algorithm.min(length, m_input.length - m_position);
            copyMem(&m_input[m_position], input, to_copy);
            m_position += to_copy;
            
            size_t consumed = 0;
            size_t written = base64Decode(m_output.ptr,
                                           cast(const(char)*)(m_input.ptr),
                                           m_position,
                                           consumed,
                                           false,
                                           m_checking != FULL_CHECK);
            
            send(m_output, written);
            
            if (consumed != m_position)
            {
                copyMem(m_input.ptr, &m_input[consumed], m_position - consumed);
                m_position = m_position - consumed;
            }
            else
                m_position = 0;
            
            length -= to_copy;
            input += to_copy;
        }
    }

    /**
    * Finish up the current message
    */
    override void endMsg()
    {
        size_t consumed = 0;
        size_t written = base64Decode(m_output.ptr,
                                       cast(const(char)*)(m_input.ptr),
                                       m_position,
                                       consumed,
                                       true,
                                       m_checking != FULL_CHECK);
        
        send(m_output, written);
        
        const bool not_full_bytes = consumed != m_position;
        
        m_position = 0;
        
        if (not_full_bytes)
            throw new InvalidArgument("Base64Decoder: Input not full bytes");
    }

    /**
    * Create a base64 decoder.
    *
    * Params:
    *  checking = the type of checking that shall be performed by
    * the decoder
    */
    this(DecoderChecking c = NONE)
    {
        m_checking = c;
        m_input = 64;
        m_output = 48;
        m_position = 0;
    }

    // Interface fallthrough
    override bool attachable() { return super.attachable(); }
    override void startMsg() { super.startMsg(); }
    override void setNext(Filter* filters, size_t sz) { super.setNext(filters, sz); }
private:
    const DecoderChecking m_checking;
    Vector!ubyte m_input, m_output;
    size_t m_position;
}