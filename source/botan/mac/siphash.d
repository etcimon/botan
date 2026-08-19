/**
* SipHash
*
* Copyright:
* (C) 2014,2015 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.mac.siphash;

import botan.constants;
static if (BOTAN_HAS_SIPHASH):

import botan.mac.mac;
import botan.utils.types;
import botan.utils.loadstor;
import botan.utils.rotate;
import botan.utils.mem_ops;
import botan.utils.exceptn;
import std.conv : to;

/**
* SipHash. SCAN: "SipHash" or "SipHash(2,4)".
*/
final class SipHash : MessageAuthenticationCode, BufferedComputation, SymmetricAlgorithm
{
public:
    /**
    * Params:
    *  c = compression rounds (default 2)
    *  d = finalization rounds (default 4)
    */
    this(size_t c = 2, size_t d = 4)
    {
        if (c == 0 || c > 64 || d == 0 || d > 64)
            throw new InvalidArgument("SipHash C/D parameter out of range");
        m_C = c;
        m_D = d;
    }

    override @property string name() const
    {
        return "SipHash(" ~ to!string(m_C) ~ "," ~ to!string(m_D) ~ ")";
    }

    override @property size_t outputLength() const { return 8; }

    override MessageAuthenticationCode clone() const { return new SipHash(m_C, m_D); }

    override void clear()
    {
        zap(m_K);
        zap(m_V);
        m_mbuf = 0;
        m_mbuf_pos = 0;
        m_words = 0;
    }

    override KeyLengthSpecification keySpec() const { return KeyLengthSpecification(16); }

protected:
    override void keySchedule(const(ubyte)* key, size_t)
    {
        m_K = SecureVector!ulong(2);
        m_K[0] = loadLittleEndian!ulong(key, 0);
        m_K[1] = loadLittleEndian!ulong(key, 1);
        m_V = SecureVector!ulong(4);
        resetMsg();
    }

    override void addData(const(ubyte)* input, size_t length)
    {
        m_words += cast(ubyte) length;

        if (m_mbuf_pos > 0)
        {
            while (length && m_mbuf_pos != 8)
            {
                m_mbuf = (m_mbuf >> 8) | (cast(ulong)(*input) << 56);
                ++m_mbuf_pos;
                ++input;
                --length;
            }
            if (m_mbuf_pos == 8)
            {
                sipRounds(m_mbuf, m_C);
                m_mbuf_pos = 0;
                m_mbuf = 0;
            }
        }

        while (length >= 8)
        {
            sipRounds(loadLittleEndian!ulong(input, 0), m_C);
            input += 8;
            length -= 8;
        }

        while (length)
        {
            m_mbuf = (m_mbuf >> 8) | (cast(ulong)(*input) << 56);
            ++m_mbuf_pos;
            ++input;
            --length;
        }
    }

    override void finalResult(ubyte* mac)
    {
        if (m_mbuf_pos == 0)
            m_mbuf = (cast(ulong) m_words) << 56;
        else if (m_mbuf_pos < 8)
            m_mbuf = (m_mbuf >> (64 - m_mbuf_pos * 8)) | ((cast(ulong) m_words) << 56);

        sipRounds(m_mbuf, m_C);
        m_V[2] ^= 0xFF;
        sipRounds(0, m_D);

        const ulong x = m_V[0] ^ m_V[1] ^ m_V[2] ^ m_V[3];
        storeLittleEndian(x, mac);
        resetMsg();
    }

private:
    void resetMsg()
    {
        m_V[0] = m_K[0] ^ 0x736F6D6570736575;
        m_V[1] = m_K[1] ^ 0x646F72616E646F6D;
        m_V[2] = m_K[0] ^ 0x6C7967656E657261;
        m_V[3] = m_K[1] ^ 0x7465646279746573;
        m_mbuf = 0;
        m_mbuf_pos = 0;
        m_words = 0;
    }

    void sipRounds(ulong M, size_t r)
    {
        ulong V0 = m_V[0], V1 = m_V[1], V2 = m_V[2], V3 = m_V[3];
        V3 ^= M;
        foreach (i; 0 .. r)
        {
            V0 += V1; V2 += V3;
            V1 = rotateLeft(V1, 13);
            V3 = rotateLeft(V3, 16);
            V1 ^= V0; V3 ^= V2;
            V0 = rotateLeft(V0, 32);
            V2 += V1; V0 += V3;
            V1 = rotateLeft(V1, 17);
            V3 = rotateLeft(V3, 21);
            V1 ^= V2; V3 ^= V0;
            V2 = rotateLeft(V2, 32);
        }
        V0 ^= M;
        m_V[0] = V0; m_V[1] = V1; m_V[2] = V2; m_V[3] = V3;
    }

    const size_t m_C, m_D;
    SecureVector!ulong m_K, m_V;
    ulong m_mbuf;
    size_t m_mbuf_pos;
    ubyte m_words;
}
