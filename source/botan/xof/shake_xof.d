/**
* SHAKE-128 and SHAKE-256 as XOFs
*
* Copyright:
* (C) 2016-2023 Jack Lloyd
* (C) 2022-2023 Fabian Albert, Michael Boric, René Meusel - Rohde & Schwarz Cybersecurity
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.xof.shake_xof;

import botan.constants;
static if (BOTAN_HAS_SHAKE_XOF && BOTAN_HAS_SHA3):

import botan.xof.xof;
import botan.hash.sha3;
import botan.utils.exceptn;
import botan.utils.mem_ops;
import botan.utils.types;
import memutils.vector;

/**
* SHAKE sponge used as an XOF. Capacity is 256 (SHAKE-128) or 512 (SHAKE-256).
* SCAN: "SHAKE-128" / "SHAKE-256" with no output-length argument.
*/
abstract class SHAKE_XOF : XOF
{
protected:
    /**
    * Params:
    *  capacity = sponge capacity in bits (256 for SHAKE-128, 512 for SHAKE-256)
    */
    this(size_t capacity)
    {
        if (capacity != 256 && capacity != 512)
            throw new InvalidArgument("SHAKE_XOF: capacity must be 256 or 512");
        m_bitrate = 1600 - capacity;
        m_S = SecureVector!ulong(25);
        m_S_pos = 0;
        m_output_generated = false;
    }

    void copySpongeTo(SHAKE_XOF dst) const
    {
        dst.m_S = SecureVector!ulong(m_S.length);
        foreach (i; 0 .. m_S.length)
            dst.m_S[i] = m_S[i];
        dst.m_S_pos = m_S_pos;
        dst.m_output_generated = m_output_generated;
        copyStartedTo(dst);
    }

public:
    override @property size_t blockSize() const { return m_bitrate / 8; }
    override bool acceptsInput() const { return !m_output_generated; }

protected:
    override void addData(const(ubyte)* input, size_t length)
    {
        if (m_output_generated)
            throw new InvalidState(name ~ " cannot absorb after output");
        m_S_pos = SHA3.absorb(m_bitrate, m_S, m_S_pos, input, length);
    }

    override void generateBytes(ubyte* output, size_t length)
    {
        if (!m_output_generated)
        {
            SHA3.finish(m_bitrate, m_S, m_S_pos, 0x1F, 0x80);
            m_S_pos = 0;
            m_output_generated = true;
        }
        m_S_pos = SHA3.squeeze(m_bitrate, m_S, m_S_pos, output, length);
    }

    override void reset()
    {
        zeroise(m_S);
        m_S_pos = 0;
        m_output_generated = false;
    }

    size_t m_bitrate;
    SecureVector!ulong m_S;
    size_t m_S_pos;
    bool m_output_generated;
}

/// SHAKE-128 (FIPS 202 §6.2). SCAN: "SHAKE-128".
final class SHAKE_128_XOF : SHAKE_XOF
{
    /// Empty XOF (capacity 256).
    this() { super(256); }
    override @property string name() const { return "SHAKE-128"; }
    override XOF copyState() const
    {
        auto x = new SHAKE_128_XOF;
        copySpongeTo(x);
        return x;
    }
    override XOF newObject() const { return new SHAKE_128_XOF; }
}

/// SHAKE-256 (FIPS 202 §6.2). SCAN: "SHAKE-256".
final class SHAKE_256_XOF : SHAKE_XOF
{
    /// Empty XOF (capacity 512).
    this() { super(512); }
    override @property string name() const { return "SHAKE-256"; }
    override XOF copyState() const
    {
        auto x = new SHAKE_256_XOF;
        copySpongeTo(x);
        return x;
    }
    override XOF newObject() const { return new SHAKE_256_XOF; }
}
