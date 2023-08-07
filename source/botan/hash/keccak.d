/**
* Keccak
* 
* Copyright:
* (C) 2010,2016 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.hash.keccak;

import botan.constants;
static if (BOTAN_HAS_KECCAK):

import botan.hash.hash;
import memutils.vector;
import botan.utils.loadstor;
import botan.utils.exceptn;
import botan.utils.mem_ops;
import botan.utils.get_byte;
import botan.hash.sha3;
import std.conv : to;

/**
* Keccak[1600], a SHA-3 candidate
*/
final class Keccak1600 : HashFunction
{
public:

    /**
    * Params:
    *  output_bits = the size of the hash output; must be one of
    *                          224, 256, 384, or 512
    */
    this(size_t output_bits = 512) 
    {
        m_output_bits = output_bits;
        m_bitrate = 1600 - 2*output_bits;
        m_S = 25;
        m_S_pos = 0;
        
        // We only support the parameters for the SHA-3 proposal
        
        if (output_bits != 224 && output_bits != 256 &&
            output_bits != 384 && output_bits != 512)
            throw new InvalidArgument("Keccak_1600: Invalid output length " ~ to!string(output_bits));
    }

    override @property size_t hashBlockSize() const { return m_bitrate / 8; }
    override @property size_t outputLength() const { return m_output_bits / 8; }

    override HashFunction clone() const
    {
        return new Keccak1600(m_output_bits);
    }

    override @property string name() const
    {
        return "Keccak-1600(" ~ to!string(m_output_bits) ~ ")";
    }

    override void clear()
    {
        zeroise(m_S);
        m_S_pos = 0;
    }

protected:
    override void addData(const(ubyte)* input, size_t length)
    {
        m_S_pos = SHA3.absorb(m_bitrate, m_S, m_S_pos, input, length);
    }

    override void finalResult(ubyte* output)
    {
        SHA3.finish(m_bitrate, m_S, m_S_pos, 0x01, 0x80);

        /*
        * We never have to run the permutation again because we only support
        * limited output lengths
        */
        foreach (size_t i; 0 .. m_output_bits/8)
            output[i] = get_byte(7 - (i % 8), m_S[i/8]);

        clear();
    }

    size_t m_output_bits, m_bitrate;
    SecureVector!ulong m_S;
    size_t m_S_pos;
}
