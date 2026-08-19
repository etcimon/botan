/**
* Ascon-XOF128 (NIST SP.800-232 §5.2)
*
* Copyright:
* (C) 2025 Jack Lloyd
* (C) 2025 René Meusel
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.xof.ascon_xof128;

import botan.constants;
static if (BOTAN_HAS_ASCON_XOF128):

import botan.xof.xof;
import botan.hash.ascon_p;
import botan.utils.exceptn;
import botan.utils.types;

/**
* Ascon-XOF128. SCAN: "Ascon-XOF128".
*/
final class AsconXOF128 : XOF
{
public:
    /// Empty XOF (IV for Ascon-XOF128).
    this()
    {
        m_p = AsconP(12, 12, 64, INIT);
        m_output_generated = false;
    }

    override @property string name() const { return "Ascon-XOF128"; }
    override @property size_t blockSize() const { return 8; }
    override bool acceptsInput() const { return !m_output_generated; }

    override XOF copyState() const
    {
        auto x = new AsconXOF128;
        x.m_p = m_p;
        x.m_output_generated = m_output_generated;
        copyStartedTo(x);
        return x;
    }

    override XOF newObject() const { return new AsconXOF128; }

protected:
    override void addData(const(ubyte)* input, size_t length)
    {
        if (m_output_generated)
            throw new InvalidState(name ~ " cannot absorb after output");
        m_p.absorb(input, length);
    }

    override void generateBytes(ubyte* output, size_t length)
    {
        if (!m_output_generated)
        {
            m_p.finish();
            m_output_generated = true;
        }
        m_p.squeeze(output, length);
    }

    override void reset()
    {
        m_p.reset(INIT);
        m_output_generated = false;
    }

private:
    // NIST SP.800-232 Appendix A Table 12
    enum ulong[5] INIT = [
        0xda82ce768d9447eb,
        0xcc7ce6c75f1ef969,
        0xe7508fd780085631,
        0x0ee0ea53416b58cc,
        0xe0547524db6f0bde
    ];
    AsconP m_p;
    bool m_output_generated;
}
