/**
* SHAKE-128 and SHAKE-256 as stream ciphers
*
* Copyright:
* (C) 2016 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.stream.shake_cipher;

import botan.constants;
static if (BOTAN_HAS_SHAKE_CIPHER):

static assert(BOTAN_HAS_SHAKE_XOF, "SHAKE_Cipher requires SHAKE_XOF");

import botan.stream.stream_cipher;
import botan.xof.xof;
import botan.xof.shake_xof;
import botan.algo_base.key_spec;
import botan.utils.exceptn;
import botan.utils.xor_buf;
import botan.utils.types;
import std.algorithm : min;

/**
* SHAKE XOF presented as a stream cipher. SCAN: "SHAKE-128" / "SHAKE-256"
* (no args; aliases "SHAKE-128-XOF" / "SHAKE-256-XOF"). No IV. Key 1..160 bytes.
*/
final class SHAKE_Cipher : StreamCipher, SymmetricAlgorithm
{
public:
    this(XOF xof, string nm)
    {
        m_xof = xof;
        m_name = nm;
    }

    override void cipher(const(ubyte)* input, ubyte* output, size_t length)
    {
        if (!m_keyed)
            throw new InvalidState(m_name ~ " key not set");
        ubyte[64] ks;
        while (length)
        {
            const size_t n = min(length, ks.length);
            m_xof.output(ks.ptr, n);
            xorBuf(output, input, ks.ptr, n);
            input += n;
            output += n;
            length -= n;
        }
    }

    override void setIv(const(ubyte)*, size_t iv_len)
    {
        if (iv_len)
            throw new InvalidIVLength(m_name, iv_len);
    }

    override bool validIvLength(size_t iv_len) const { return iv_len == 0; }

    override void seek(ulong offset)
    {
        if (offset)
            throw new InvalidArgument(m_name ~ " does not support seek");
    }

    override StreamCipher clone() const { return new SHAKE_Cipher(m_xof.newObject(), m_name); }

    override void clear()
    {
        m_xof.clear();
        m_keyed = false;
    }

    override @property string name() const { return m_name; }

    override KeyLengthSpecification keySpec() const { return KeyLengthSpecification(1, 160); }

protected:
    override void keySchedule(const(ubyte)* key, size_t length)
    {
        m_xof.clear();
        m_xof.update(key, length);
        m_keyed = true;
    }

private:
    XOF m_xof;
    string m_name;
    bool m_keyed;
}

SHAKE_Cipher makeSHAKE128Cipher() { return new SHAKE_Cipher(new SHAKE_128_XOF, "SHAKE-128"); }
SHAKE_Cipher makeSHAKE256Cipher() { return new SHAKE_Cipher(new SHAKE_256_XOF, "SHAKE-256"); }
