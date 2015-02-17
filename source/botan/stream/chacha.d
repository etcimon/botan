/**
* ChaCha20
* 
* Copyright:
* (C) 2014 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.stream.chacha;

import botan.constants;
static if (BOTAN_HAS_CHACHA):

import botan.stream.stream_cipher;
import botan.utils.loadstor;
import botan.utils.rotate;
import botan.utils.xor_buf;
import botan.utils.types;
import botan.utils.mem_ops;

/**
* DJB's ChaCha (http://cr.yp.to/chacha.html)
*/
final class ChaCha : StreamCipher, SymmetricAlgorithm
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
            chacha(*cast(ubyte[64]*) m_buffer.ptr, *cast(uint[16]*) m_state.ptr);
            
            ++m_state[12];
            m_state[13] += (m_state[12] == 0);
            
            m_position = 0;
        }
        
        xorBuf(output, input, &m_buffer[m_position], length);
        
        m_position += length;
    }

    /*
    * Return the name of this type
    */
    override void setIv(const(ubyte)* iv, size_t length)
    {
        if (!validIvLength(length))
            throw new InvalidIVLength(name, length);
        
        m_state[12] = 0;
        m_state[13] = 0;
        
        m_state[14] = loadLittleEndian!uint(iv, 0);
        m_state[15] = loadLittleEndian!uint(iv, 1);
        
        chacha(*cast(ubyte[64]*) m_buffer.ptr, *cast(uint[16]*) m_state.ptr);
        ++m_state[12];
        m_state[13] += (m_state[12] == 0);
        
        m_position = 0;
    }

    override bool validIvLength(size_t iv_len) const
    { return (iv_len == 8); }

    KeyLengthSpecification keySpec() const
    {
        return KeyLengthSpecification(16, 32, 16);
    }

    /*
    * Clear memory of sensitive data
    */
    void clear()
    {
        zap(m_state);
        zap(m_buffer);
        m_position = 0;
    }

    /*
    * Return the name of this type
    */
    @property string name() const
    {
        return "ChaCha";
    }

    override StreamCipher clone() const { return new ChaCha; }
protected:

    void chacha(ref ubyte[64] output, in uint[16] input)
    {
        uint x00 = input[ 0], x01 = input[ 1], x02 = input[ 2], x03 = input[ 3],
            x04 = input[ 4], x05 = input[ 5], x06 = input[ 6], x07 = input[ 7],
            x08 = input[ 8], x09 = input[ 9], x10 = input[10], x11 = input[11],
            x12 = input[12], x13 = input[13], x14 = input[14], x15 = input[15];
        
        
        foreach (size_t i; 0 .. 10)
        {
            mixin(CHACHA_QUARTER_ROUND!(x00, x04, x08, x12)() ~
                  CHACHA_QUARTER_ROUND!(x01, x05, x09, x13)() ~
                  CHACHA_QUARTER_ROUND!(x02, x06, x10, x14)() ~
                  CHACHA_QUARTER_ROUND!(x03, x07, x11, x15)() ~
                  
                  CHACHA_QUARTER_ROUND!(x00, x05, x10, x15)() ~
                  CHACHA_QUARTER_ROUND!(x01, x06, x11, x12)() ~
                  CHACHA_QUARTER_ROUND!(x02, x07, x08, x13)() ~
                  CHACHA_QUARTER_ROUND!(x03, x04, x09, x14)()
                  );
        }
        
        storeLittleEndian(x00 + input[ 0], output.ptr + 4 *  0);
        storeLittleEndian(x01 + input[ 1], output.ptr + 4 *  1);
        storeLittleEndian(x02 + input[ 2], output.ptr + 4 *  2);
        storeLittleEndian(x03 + input[ 3], output.ptr + 4 *  3);
        storeLittleEndian(x04 + input[ 4], output.ptr + 4 *  4);
        storeLittleEndian(x05 + input[ 5], output.ptr + 4 *  5);
        storeLittleEndian(x06 + input[ 6], output.ptr + 4 *  6);
        storeLittleEndian(x07 + input[ 7], output.ptr + 4 *  7);
        storeLittleEndian(x08 + input[ 8], output.ptr + 4 *  8);
        storeLittleEndian(x09 + input[ 9], output.ptr + 4 *  9);
        storeLittleEndian(x10 + input[10], output.ptr + 4 * 10);
        storeLittleEndian(x11 + input[11], output.ptr + 4 * 11);
        storeLittleEndian(x12 + input[12], output.ptr + 4 * 12);
        storeLittleEndian(x13 + input[13], output.ptr + 4 * 13);
        storeLittleEndian(x14 + input[14], output.ptr + 4 * 14);
        storeLittleEndian(x15 + input[15], output.ptr + 4 * 15);
    }

protected:
    /*
    * ChaCha Key Schedule
    */
    override void keySchedule(const(ubyte)* key, size_t length)
    {
        __gshared immutable uint[] TAU =    [ 0x61707865, 0x3120646e, 0x79622d36, 0x6b206574 ];
        
        __gshared immutable uint[] SIGMA = [ 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 ];
        
        const uint[] CONSTANTS = (length == 16) ? TAU : SIGMA;
        
        m_state.resize(16);
        m_buffer.resize(64);
        
        m_state[0] = CONSTANTS[0];
        m_state[1] = CONSTANTS[1];
        m_state[2] = CONSTANTS[2];
        m_state[3] = CONSTANTS[3];
        
        m_state[4] = loadLittleEndian!uint(key, 0);
        m_state[5] = loadLittleEndian!uint(key, 1);
        m_state[6] = loadLittleEndian!uint(key, 2);
        m_state[7] = loadLittleEndian!uint(key, 3);
        
        if (length == 32)
            key += 16;
        
        m_state[8] = loadLittleEndian!uint(key, 0);
        m_state[9] = loadLittleEndian!uint(key, 1);
        m_state[10] = loadLittleEndian!uint(key, 2);
        m_state[11] = loadLittleEndian!uint(key, 3);
        
        m_position = 0;
        
        const ubyte[8] ZERO;
        setIv(ZERO.ptr, ZERO.length);
    }


    SecureVector!uint m_state;
    SecureVector!ubyte m_buffer;
    size_t m_position = 0;
}

string CHACHA_QUARTER_ROUND(alias _a, alias _b, alias _c, alias _d)()
{
    enum a = __traits(identifier, _a);
    enum b = __traits(identifier, _b);
    enum c = __traits(identifier, _c);
    enum d = __traits(identifier, _d);

    return a ~ ` += ` ~ b ~ `; ` ~ d ~ ` ^= ` ~ a ~ `; ` ~ d ~ ` = rotateLeft(` ~ d ~ `, 16);
                ` ~ c ~ ` += ` ~ d ~ `; ` ~ b ~ ` ^= ` ~ c ~ `; ` ~ b ~ ` = rotateLeft(` ~ b ~ `, 12);
                ` ~ a ~ ` += ` ~ b ~ `; ` ~ d ~ ` ^= ` ~ a ~ `; ` ~ d ~ ` = rotateLeft(` ~ d ~ `, 8);
                ` ~ c ~ ` += ` ~ d ~ `; ` ~ b ~ ` ^= ` ~ c ~ `; ` ~ b ~ ` = rotateLeft(` ~ b ~ `, 7);`;
}
