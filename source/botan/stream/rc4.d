/**
* RC4
* 
* Copyright:
* (C) 1999-2008 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.stream.rc4;

import botan.constants;
static if (BOTAN_HAS_RC4):

import botan.stream.stream_cipher;
import botan.utils.types;
import botan.utils.xor_buf;
import botan.utils.rounding;
import botan.utils.mem_ops;
import std.conv : to;

/**
* RC4 stream cipher
*/
final class RC4 : StreamCipher, SymmetricAlgorithm
{
public:
    /*
    * Combine cipher stream with message
    */
    override void cipher(const(ubyte)* input, ubyte* output, size_t length)
    {
        while (length >= m_buffer.length - m_position)
        {
            xorBuf(output, input, &m_buffer[m_position], m_buffer.length - m_position);
            length -= (m_buffer.length - m_position);
            input += (m_buffer.length - m_position);
            output += (m_buffer.length - m_position);
            generate();
        }
        xorBuf(output, input, &m_buffer[m_position], length);
        m_position += length;
    }

    /*
    * Clear memory of sensitive data
    */
    void clear()
    {
        zap(m_state);
        zap(m_buffer);
        m_position = m_X = m_Y = 0;
    }

    /*
    * Return the name of this type
    */
    @property string name() const
    {
        if (m_SKIP == 0)    return "RC4";
        if (m_SKIP == 256)  return "MARK-4";
        else                return "RC4_skip(" ~ to!string(m_SKIP) ~ ")";
    }

    override RC4 clone() const { return new RC4(m_SKIP); }

    KeyLengthSpecification keySpec() const
    {
        return KeyLengthSpecification(1, 256);
    }

    /**
    * Params:
    *  skip = skip this many initial bytes in the keystream
    */
    this(size_t s = 0) { m_SKIP = s; }

    override bool validIvLength(size_t iv_len) const
    { return (iv_len == 0); }

    override void setIv(const(ubyte)*, size_t iv_len) 
    { 
        if (iv_len) 
            throw new InvalidArgument("The stream cipher " ~ name ~ " does not support resyncronization"); 
    }

    ~this() { clear(); }
protected:
    /*
    * RC4 Key Schedule
    */
    override void keySchedule(const(ubyte)* key, size_t length)
    {
        m_state.resize(256);
        m_buffer.resize(roundUp!size_t(DEFAULT_BUFFERSIZE, 4));
        
        m_position = m_X = m_Y = 0;
        
        foreach (size_t i; 0 .. 256)
            m_state[i] = cast(ubyte)(i);
        
        for (size_t i = 0, state_index = 0; i != 256; ++i)
        {
            state_index = (state_index + key[i % length] + m_state[i]) % 256;
            std.algorithm.swap(m_state[i], m_state[state_index]);
        }
        
        for (size_t i = 0; i <= m_SKIP; i += m_buffer.length)
            generate();
        
        m_position += (m_SKIP % m_buffer.length);
    }


    /*
    * Generate cipher stream
    */
    void generate()
    {
        ubyte SX, SY;
        for (size_t i = 0; i != m_buffer.length; i += 4)
        {
            SX = m_state[m_X+1]; m_Y = (m_Y + SX) % 256; SY = m_state[m_Y];
            m_state[m_X+1] = SY; m_state[m_Y] = SX;
            m_buffer[i] = m_state[(SX + SY) % 256];
            
            SX = m_state[m_X+2]; m_Y = (m_Y + SX) % 256; SY = m_state[m_Y];
            m_state[m_X+2] = SY; m_state[m_Y] = SX;
            m_buffer[i+1] = m_state[(SX + SY) % 256];
            
            SX = m_state[m_X+3]; m_Y = (m_Y + SX) % 256; SY = m_state[m_Y];
            m_state[m_X+3] = SY; m_state[m_Y] = SX;
            m_buffer[i+2] = m_state[(SX + SY) % 256];
            
            m_X = (m_X + 4) % 256;
            SX = m_state[m_X]; m_Y = (m_Y + SX) % 256; SY = m_state[m_Y];
            m_state[m_X] = SY; m_state[m_Y] = SX;
            m_buffer[i+3] = m_state[(SX + SY) % 256];
        }
        m_position = 0;
    }

    const size_t m_SKIP;

    ubyte m_X, m_Y;
    SecureVector!ubyte m_state;

    SecureVector!ubyte m_buffer;
    size_t m_position;
}
