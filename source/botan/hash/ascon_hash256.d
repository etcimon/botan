/**
* Ascon-Hash256 (NIST SP.800-232 §5.1)
*
* Copyright:
* (C) 2025 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.hash.ascon_hash256;

import botan.constants;
static if (BOTAN_HAS_ASCON_HASH256):

import botan.hash.hash;
import botan.hash.ascon_p;
import botan.utils.types;

/**
* Ascon-Hash256. SCAN: "Ascon-Hash256".
*/
final class AsconHash256 : HashFunction
{
public:
    /// Empty digest (IV for Ascon-Hash256).
    this()
    {
        m_p = AsconP(12, 12, 64, INIT);
    }

    override @property size_t hashBlockSize() const { return 8; }
    override @property size_t outputLength() const { return 32; }
    override HashFunction clone() const
    {
        auto h = new AsconHash256;
        h.m_p = m_p;
        return h;
    }
    override @property string name() const { return "Ascon-Hash256"; }

    override void clear()
    {
        m_p.reset(INIT);
    }

protected:
    override void addData(const(ubyte)* input, size_t length)
    {
        m_p.absorb(input, length);
    }

    override void finalResult(ubyte* output)
    {
        m_p.finish();
        m_p.squeeze(output, 32);
        clear();
    }

private:
    enum ulong[5] INIT = [
        0x9b1e5494e934d681,
        0x4bc3a01e333751d2,
        0xae65396c6b34b81a,
        0x3c7fd4a4d56a4db3,
        0x1a5c464906c5976d
    ];
    AsconP m_p;
}
