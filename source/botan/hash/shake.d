/*
* SHAKE hash functions
* (C) 2010,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
module botan.hash.shake;

import botan.constants;
static if (BOTAN_HAS_SHAKE):

import botan.hash.hash;
import memutils.vector;
import botan.utils.loadstor;
import botan.utils.exceptn;
import botan.utils.mem_ops;
import botan.utils.get_byte;
import botan.hash.sha3;
import std.conv : to;

enum SHAKE_128_BITRATE = 1600 - 256;
enum SHAKE_256_BITRATE = 1600 - 512;

final class SHAKE128 : HashFunction
{
public:

    /**
    * Params:
    *  output_bits = the desired output size in bits must be a multiple of 8
    */
    this(size_t output_bits)
    {
        m_output_bits = output_bits;
        m_S = 25;
        m_S_pos = 0;

        if(output_bits % 8 != 0)
            throw new InvalidArgument("SHAKE128: Invalid output length " ~ to!string(output_bits));
    }

    override @property size_t hashBlockSize() const { return SHAKE_128_BITRATE / 8; }
    override @property size_t outputLength() const { return m_output_bits / 8; }

    override HashFunction clone() const
    {
        return new SHAKE128(m_output_bits);
    }

    override @property string name() const
    {
        return "SHAKE-128(" ~ to!string(m_output_bits) ~ ")";
    }

    override void clear()
    {
        zeroise(m_S);
        m_S_pos = 0;
    }

protected:
    override void addData(const(ubyte)* input, size_t length)
    {
        m_S_pos = SHA3.absorb(SHAKE_128_BITRATE, m_S, m_S_pos, input, length);
    }

    override void finalResult(ubyte* output)
    {
        SHA3.finish(SHAKE_128_BITRATE, m_S, m_S_pos, 0x1F, 0x80);
        SHA3.expand(SHAKE_128_BITRATE, m_S, output, outputLength());

        clear();
    }

    size_t m_output_bits, m_bitrate;
    SecureVector!ulong m_S;
    size_t m_S_pos;
}

final class SHAKE256 : HashFunction
{
public:

    /**
    * Params:
    *  output_bits = the desired output size in bits must be a multiple of 8
    */
    this(size_t output_bits)
    {
        m_output_bits = output_bits;
        m_S = 25;
        m_S_pos = 0;

        if(output_bits % 8 != 0)
            throw new InvalidArgument("SHAKE256: Invalid output length " ~ to!string(output_bits));
    }

    override @property size_t hashBlockSize() const { return SHAKE_256_BITRATE / 8; }
    override @property size_t outputLength() const { return m_output_bits / 8; }

    override HashFunction clone() const
    {
        return new SHAKE256(m_output_bits);
    }

    override @property string name() const
    {
        return "SHAKE-256(" ~ to!string(m_output_bits) ~ ")";
    }

    override void clear()
    {
        zeroise(m_S);
        m_S_pos = 0;
    }

protected:
    override void addData(const(ubyte)* input, size_t length)
    {
        m_S_pos = SHA3.absorb(SHAKE_256_BITRATE, m_S, m_S_pos, input, length);
    }

    override void finalResult(ubyte* output)
    {
        SHA3.finish(SHAKE_256_BITRATE, m_S, m_S_pos, 0x1F, 0x80);
        SHA3.expand(SHAKE_256_BITRATE, m_S, output, outputLength());

        clear();
    }

    size_t m_output_bits, m_bitrate;
    SecureVector!ulong m_S;
    size_t m_S_pos;
}
