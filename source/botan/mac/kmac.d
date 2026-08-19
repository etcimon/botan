/**
* KMAC (NIST SP 800-185)
*
* Copyright:
* (C) 2023 Jack Lloyd
* (C) 2023 Falko Strenzke
* (C) 2023 René Meusel - Rohde & Schwarz Cybersecurity
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.mac.kmac;

import botan.constants;
static if (BOTAN_HAS_KMAC && BOTAN_HAS_SHA3):

import botan.mac.mac;
import botan.hash.sha3;
import botan.utils.types;
import botan.utils.exceptn;
import botan.utils.mem_ops;
import std.conv : to;

/**
* KMAC-128. SCAN: "KMAC-128" or "KMAC-128(256)".
* Optional `start(S)` sets the SP 800-185 customization string.
*/
final class KMAC128 : KMAC
{
    /**
    * Params:
    *  output_bits = MAC length in bits (default 256)
    */
    this(size_t output_bits = 256) { super(1344, output_bits); }
    override @property string name() const { return "KMAC-128(" ~ to!string(outputLength * 8) ~ ")"; }
    override MessageAuthenticationCode clone() const { return new KMAC128(outputLength * 8); }
}

/**
* KMAC-256. SCAN: "KMAC-256" or "KMAC-256(512)".
*/
final class KMAC256 : KMAC
{
    /**
    * Params:
    *  output_bits = MAC length in bits (default 512)
    */
    this(size_t output_bits = 512) { super(1088, output_bits); }
    override @property string name() const { return "KMAC-256(" ~ to!string(outputLength * 8) ~ ")"; }
    override MessageAuthenticationCode clone() const { return new KMAC256(outputLength * 8); }
}

class KMAC : MessageAuthenticationCode, BufferedComputation, SymmetricAlgorithm, MacStart
{
public:
    override abstract @property string name() const;
    override abstract MessageAuthenticationCode clone() const;
    override @property size_t outputLength() const { return m_output_bits / 8; }
    override KeyLengthSpecification keySpec() const { return KeyLengthSpecification(0, 192); }

    override void clear()
    {
        zap(m_encoded_key);
        m_started = false;
        zeroise(m_S);
        m_S_pos = 0;
    }

    override void start(const(ubyte)* nonce, size_t nonce_len)
    {
        beginMsg(nonce, nonce_len);
    }

protected:
    this(size_t bitrate, size_t output_bits)
    {
        if (output_bits == 0 || output_bits % 8 != 0)
            throw new InvalidArgument("KMAC output length must be a positive multiple of 8");
        m_bitrate = bitrate;
        m_output_bits = output_bits;
        m_S = SecureVector!ulong(25);
    }

    override void keySchedule(const(ubyte)* key, size_t length)
    {
        clear();
        auto enc = Vector!ubyte();
        encodeString(enc, key, length);
        bytepad(m_encoded_key, enc, m_bitrate / 8);
    }

    override void addData(const(ubyte)* input, size_t length)
    {
        if (!m_started)
            beginMsg(null, 0);
        if (length)
            m_S_pos = SHA3.absorb(m_bitrate, m_S, m_S_pos, input, length);
    }

    override void finalResult(ubyte* output)
    {
        if (!m_started)
            beginMsg(null, 0);
        auto enc_len = Vector!ubyte();
        rightEncode(enc_len, m_output_bits);
        m_S_pos = SHA3.absorb(m_bitrate, m_S, m_S_pos, enc_len.ptr, enc_len.length);
        SHA3.finish(m_bitrate, m_S, m_S_pos, 0x04, 0x80);
        SHA3.expand(m_bitrate, m_S, output, outputLength());
        zeroise(m_S);
        m_S_pos = 0;
        m_started = false;
    }

private:
    void beginMsg(const(ubyte)* custom, size_t custom_len)
    {
        zeroise(m_S);
        m_S_pos = 0;
        auto ns = Vector!ubyte();
        encodeString(ns, cast(const(ubyte)*)"KMAC".ptr, 4);
        encodeString(ns, custom, custom_len);
        auto padded = Vector!ubyte();
        bytepad(padded, ns, m_bitrate / 8);
        m_S_pos = SHA3.absorb(m_bitrate, m_S, m_S_pos, padded.ptr, padded.length);
        if (m_encoded_key.length)
            m_S_pos = SHA3.absorb(m_bitrate, m_S, m_S_pos, m_encoded_key.ptr, m_encoded_key.length);
        m_started = true;
    }

    const size_t m_bitrate;
    const size_t m_output_bits;
    SecureVector!ulong m_S;
    size_t m_S_pos;
    SecureVector!ubyte m_encoded_key;
    bool m_started;
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

void rightEncode(ref Vector!ubyte dest, ulong x)
{
    size_t n = 1;
    for (ulong v = x >> 8; v; v >>= 8)
        ++n;
    foreach_reverse (i; 0 .. n)
        dest ~= cast(ubyte)(x >> (8 * i));
    dest ~= cast(ubyte) n;
}

void encodeString(ref Vector!ubyte dest, const(ubyte)* s, size_t n)
{
    leftEncode(dest, 8UL * n);
    if (n)
        dest ~= s[0 .. n];
}

void bytepad(ref SecureVector!ubyte dest, const ref Vector!ubyte x, size_t w)
{
    dest.clear();
    auto tmp = Vector!ubyte();
    leftEncode(tmp, w);
    tmp ~= x[];
    while (tmp.length % w)
        tmp ~= 0;
    dest ~= tmp[];
}

void bytepad(ref Vector!ubyte dest, const ref Vector!ubyte x, size_t w)
{
    dest.clear();
    leftEncode(dest, w);
    dest ~= x[];
    while (dest.length % w)
        dest ~= 0;
}
