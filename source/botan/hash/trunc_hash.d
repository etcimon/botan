/**
* Truncated hash wrapper
*
* Copyright:
* (C) 2015 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.hash.trunc_hash;

import botan.constants;
static if (BOTAN_HAS_TRUNCATED_HASH):

import botan.hash.hash;
import botan.utils.types;
import botan.utils.exceptn;
import botan.utils.mem_ops;
import std.conv : to;

/**
* Truncate another hash to a bit length. SCAN: "Truncated(SHA-256,192)".
*/
final class TruncatedHash : HashFunction
{
public:
    this(HashFunction hash, size_t bits)
    {
        if (!hash)
            throw new InvalidArgument("Truncated hash requires an underlying hash");
        if (bits == 0)
            throw new InvalidArgument("Truncating a hash to 0 does not make sense");
        if (hash.outputLength() * 8 < bits)
            throw new InvalidArgument("Underlying hash function does not produce enough bytes for truncation");
        m_hash = hash;
        m_output_bits = bits;
    }

    override @property size_t hashBlockSize() const { return m_hash.hashBlockSize(); }
    override @property size_t outputLength() const { return (m_output_bits + 7) / 8; }
    override HashFunction clone() const
    {
        return new TruncatedHash(m_hash.clone(), m_output_bits);
    }
    override @property string name() const
    {
        return "Truncated(" ~ m_hash.name ~ "," ~ to!string(m_output_bits) ~ ")";
    }

    override void clear() { m_hash.clear(); }

protected:
    override void addData(const(ubyte)* input, size_t length)
    {
        m_hash.update(input, length);
    }

    override void finalResult(ubyte* output)
    {
        auto full = m_hash.finished();
        const size_t n = outputLength();
        copyMem(output, full.ptr, n);
        const ubyte bits_in_last = cast(ubyte)(((m_output_bits - 1) % 8) + 1);
        const ubyte bitmask = cast(ubyte)(~((1 << (8 - bits_in_last)) - 1));
        output[n - 1] &= bitmask;
    }

private:
    Unique!HashFunction m_hash;
    const size_t m_output_bits;
}
