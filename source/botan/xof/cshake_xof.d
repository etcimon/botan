/**
* cSHAKE-128 and cSHAKE-256 as XOFs (NIST SP 800-185)
*
* Copyright:
* (C) 2016-2023 Jack Lloyd
* (C) 2022-2023 René Meusel - Rohde & Schwarz Cybersecurity
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.xof.cshake_xof;

import botan.constants;
static if (BOTAN_HAS_CSHAKE_XOF && BOTAN_HAS_SHA3):

import botan.xof.xof;
import botan.hash.sha3;
import botan.utils.exceptn;
import botan.utils.mem_ops;
import botan.utils.types;
import memutils.vector;

/**
* cSHAKE sponge. Function name N is a constructor argument; salt S is
* `start`. Not exposed as a public SCAN name (C++ keeps it internal).
*/
abstract class CSHAKE_XOF : XOF
{
protected:
    this(size_t capacity, const(ubyte)[] function_name)
    {
        if (capacity != 256 && capacity != 512)
            throw new InvalidArgument("cSHAKE: capacity must be 256 or 512");
        m_bitrate = 1600 - capacity;
        m_S = SecureVector!ulong(25);
        m_S_pos = 0;
        m_output_generated = false;
        m_function_name = function_name.dup;
    }

    const(ubyte)[] functionName() const { return m_function_name; }

    void copySpongeTo(CSHAKE_XOF dst) const
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

    override bool validSaltLength(size_t salt_len) const
    {
        // NIST SP 800-185 §3.2: empty N and S would fall back to SHAKE.
        // We do not implement that fallback, so at least one must be set.
        return m_function_name.length + salt_len > 0;
    }

protected:
    override void startMsg(const(ubyte)* salt, size_t salt_len,
                           const(ubyte)* key, size_t key_len)
    {
        if (m_output_generated)
            throw new InvalidState(name ~ " cannot start after output");
        if (key_len)
            throw new InvalidArgument(name ~ " does not take a key");
        auto ns = Vector!ubyte();
        encodeString(ns, m_function_name.ptr, m_function_name.length);
        encodeString(ns, salt, salt_len);
        auto padded = Vector!ubyte();
        bytepad(padded, ns, m_bitrate / 8);
        m_S_pos = SHA3.absorb(m_bitrate, m_S, m_S_pos, padded.ptr, padded.length);
    }

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
            SHA3.finish(m_bitrate, m_S, m_S_pos, 0x04, 0x80);
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
    ubyte[] m_function_name;
}

/// cSHAKE-128. Tests construct via getXof("cSHAKE-128", name).
final class CSHAKE_128_XOF : CSHAKE_XOF
{
    this(const(ubyte)[] function_name) { super(256, function_name); }
    override @property string name() const { return "cSHAKE-128"; }
    override XOF copyState() const
    {
        auto x = new CSHAKE_128_XOF(functionName());
        copySpongeTo(x);
        return x;
    }
    override XOF newObject() const { return new CSHAKE_128_XOF(functionName()); }
}

/// cSHAKE-256. Tests construct via getXof("cSHAKE-256", name).
final class CSHAKE_256_XOF : CSHAKE_XOF
{
    this(const(ubyte)[] function_name) { super(512, function_name); }
    override @property string name() const { return "cSHAKE-256"; }
    override XOF copyState() const
    {
        auto x = new CSHAKE_256_XOF(functionName());
        copySpongeTo(x);
        return x;
    }
    override XOF newObject() const { return new CSHAKE_256_XOF(functionName()); }
}

private:

void leftEncode(ref Vector!ubyte dest, ulong x)
{
    size_t n = 1;
    for (ulong v = x >> 8; v; v >>= 8)
        ++n;
    dest ~= cast(ubyte) n;
    foreach_reverse (i; 0 .. n)
        dest ~= cast(ubyte)(x >> (8 * i));
}

void encodeString(ref Vector!ubyte dest, const(ubyte)* s, size_t n)
{
    leftEncode(dest, 8UL * n);
    if (n)
        dest ~= s[0 .. n];
}

void bytepad(ref Vector!ubyte dest, const ref Vector!ubyte x, size_t w)
{
    dest.clear();
    leftEncode(dest, w);
    dest ~= x[];
    while (dest.length % w)
        dest ~= 0;
}
