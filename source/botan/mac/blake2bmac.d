/**
* BLAKE2b MAC
*
* Copyright:
* (C) 1999-2007,2014 Jack Lloyd
* (C) 2020           Tom Crowley
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.mac.blake2bmac;

import botan.constants;
static if (BOTAN_HAS_BLAKE2BMAC && BOTAN_HAS_BLAKE2B):

import botan.mac.mac;
import botan.hash.blake2b;
import botan.utils.types;
import botan.utils.exceptn;
import botan.utils.mem_ops;

/**
* Keyed BLAKE2b used as a MAC. SCAN: "BLAKE2b" or "BLAKE2b(256)".
* Same name as the hash; retrieved via retrieveMac, not retrieveHash.
*/
final class Blake2bMAC : MessageAuthenticationCode, BufferedComputation, SymmetricAlgorithm
{
public:
    this(size_t output_bits = 512)
    {
        m_blake = new Blake2b(output_bits);
    }

    override @property string name() const { return m_blake.name; }
    override @property size_t outputLength() const { return m_blake.outputLength(); }
    override MessageAuthenticationCode clone() const
    {
        return new Blake2bMAC(m_blake.outputLength() * 8);
    }
    override KeyLengthSpecification keySpec() const { return m_blake.keySpec(); }

    override void clear()
    {
        m_blake.clear();
        m_keyed = false;
    }

protected:
    override void keySchedule(const(ubyte)* key, size_t length)
    {
        m_blake.setKey(key, length);
        m_keyed = true;
    }

    override void addData(const(ubyte)* input, size_t length)
    {
        if (!m_keyed)
            throw new InvalidState("BLAKE2b MAC used without a key");
        m_blake.update(input, length);
    }

    override void finalResult(ubyte* output)
    {
        if (!m_keyed)
            throw new InvalidState("BLAKE2b MAC used without a key");
        auto h = m_blake.finished();
        copyMem(output, h.ptr, outputLength());
    }

private:
    Unique!Blake2b m_blake;
    bool m_keyed;
}
