/**
* NIST SP 800-108 KDFs (Counter, Feedback, Pipeline)
*
* Copyright:
* (C) 2016 Kai Michaelis
* (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
* (C) 2025 René Meusel, Amos Treiber, Rohde & Schwarz Cybersecurity
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.kdf.sp800_108;

import botan.constants;
static if (BOTAN_HAS_SP800_108):

import botan.kdf.kdf;
import botan.mac.mac;
import botan.utils.exceptn;
import botan.utils.types;
import std.algorithm : min;
import std.conv : to;

private:

void validateBitLengths(size_t counter_bits, size_t output_length_bits)
{
    if (counter_bits == 0 || counter_bits % 8 != 0 || counter_bits > 32)
        throw new InvalidArgument("SP.800-108 counter length may be one of {8, 16, 24, 32} only");
    if (output_length_bits == 0 || output_length_bits % 8 != 0 || output_length_bits > 32)
        throw new InvalidArgument("SP.800-108 output length encoding may be one of {8, 16, 24, 32} only");
}

uint blocksRequired(size_t output_bytes, size_t output_length_bits,
                    size_t counter_bits, size_t prf_output_bytes)
{
    if (cast(ulong) output_bytes * 8 > uint.max)
        throw new InvalidArgument("SP.800-108 output size in bits does not fit into 32-bits");
    const uint output_bits = cast(uint)(output_bytes * 8);
    const ulong max_output_bits = (1UL << output_length_bits) - 1;
    if (output_bits > max_output_bits)
        throw new InvalidArgument("SP.800-108 output size does not fit into the requested field length");

    const ulong blocks = (output_bytes + prf_output_bytes - 1) / prf_output_bytes;
    const ulong max_blocks = (1UL << counter_bits) - 1;
    if (blocks > max_blocks)
        throw new InvalidArgument("SP.800-108 output size too large");
    return cast(uint) blocks;
}

void encodeBeField(ubyte[] dest, uint value)
{
    foreach (i; 0 .. dest.length)
        dest[i] = cast(ubyte)(value >> (8 * (dest.length - 1 - i)));
}

string name108(string mode, string prf, size_t r, size_t L)
{
    if (r == 32 && L == 32)
        return "SP800-108-" ~ mode ~ "(" ~ prf ~ ")";
    return "SP800-108-" ~ mode ~ "(" ~ prf ~ "," ~ to!string(r) ~ "," ~ to!string(L) ~ ")";
}

public:

/// NIST SP 800-108 §5.1 Counter mode. SCAN: "SP800-108-Counter(HMAC(SHA-256))"
final class SP800_108_Counter : KDF
{
    this(MessageAuthenticationCode mac, size_t r = 32, size_t L = 32)
    {
        validateBitLengths(r, L);
        m_prf = mac;
        m_r = r;
        m_L = L;
    }

    override @property string name() const { return name108("Counter", m_prf.name, m_r, m_L); }
    override KDF clone() const { return new SP800_108_Counter(m_prf.clone(), m_r, m_L); }

    override SecureVector!ubyte derive(size_t key_len,
                                       const(ubyte)* secret, size_t secret_len,
                                       const(ubyte)* salt, size_t salt_len) const
    {
        return derive(key_len, secret, secret_len, salt, salt_len, null, 0);
    }

    override SecureVector!ubyte derive(size_t key_len,
                                       const(ubyte)* secret, size_t secret_len,
                                       const(ubyte)* salt, size_t salt_len,
                                       const(ubyte)* label, size_t label_len) const
    {
        SecureVector!ubyte key;
        if (key_len == 0)
            return key;

        auto prf = cast(MessageAuthenticationCode)*m_prf;
        const size_t prf_len = prf.outputLength();
        const uint nblocks = blocksRequired(key_len, m_L, m_r, prf_len);
        const uint output_bits = cast(uint)(key_len * 8);
        const ubyte delim = 0;

        ubyte[4] ctr_be, len_be;
        encodeBeField(len_be[0 .. m_L / 8], output_bits);

        prf.setKey(secret, secret_len);
        key.reserve(key_len);

        foreach (uint counter; 1 .. nblocks + 1)
        {
            encodeBeField(ctr_be[0 .. m_r / 8], counter);
            prf.update(ctr_be.ptr, m_r / 8);
            if (label_len)
                prf.update(label, label_len);
            prf.update(delim);
            if (salt_len)
                prf.update(salt, salt_len);
            prf.update(len_be.ptr, m_L / 8);
            auto h = prf.finished();
            const size_t take = min(h.length, key_len - key.length);
            key ~= h.ptr[0 .. take];
        }
        return key;
    }

private:
    Unique!MessageAuthenticationCode m_prf;
    size_t m_r, m_L;
}

/// NIST SP 800-108 §5.2 Feedback mode. SCAN: "SP800-108-Feedback(HMAC(SHA-256))"
final class SP800_108_Feedback : KDF
{
    this(MessageAuthenticationCode mac, size_t r = 32, size_t L = 32)
    {
        validateBitLengths(r, L);
        m_prf = mac;
        m_r = r;
        m_L = L;
    }

    override @property string name() const { return name108("Feedback", m_prf.name, m_r, m_L); }
    override KDF clone() const { return new SP800_108_Feedback(m_prf.clone(), m_r, m_L); }

    override SecureVector!ubyte derive(size_t key_len,
                                       const(ubyte)* secret, size_t secret_len,
                                       const(ubyte)* salt, size_t salt_len) const
    {
        return derive(key_len, secret, secret_len, salt, salt_len, null, 0);
    }

    override SecureVector!ubyte derive(size_t key_len,
                                       const(ubyte)* secret, size_t secret_len,
                                       const(ubyte)* salt, size_t salt_len,
                                       const(ubyte)* label, size_t label_len) const
    {
        SecureVector!ubyte key;
        if (key_len == 0)
            return key;

        auto prf = cast(MessageAuthenticationCode)*m_prf;
        const size_t prf_len = prf.outputLength();
        const size_t iv_len = (salt_len >= prf_len) ? prf_len : 0;
        const uint nblocks = blocksRequired(key_len, m_L, m_r, prf_len);
        const uint output_bits = cast(uint)(key_len * 8);
        const ubyte delim = 0;

        SecureVector!ubyte prev;
        if (iv_len)
            prev ~= salt[0 .. iv_len];
        const(ubyte)* ctx = salt + iv_len;
        const size_t ctx_len = salt_len - iv_len;

        ubyte[4] ctr_be, len_be;
        encodeBeField(len_be[0 .. m_L / 8], output_bits);

        prf.setKey(secret, secret_len);
        key.reserve(key_len);

        foreach (uint counter; 1 .. nblocks + 1)
        {
            encodeBeField(ctr_be[0 .. m_r / 8], counter);
            if (prev.length)
                prf.update(prev.ptr, prev.length);
            prf.update(ctr_be.ptr, m_r / 8);
            if (label_len)
                prf.update(label, label_len);
            prf.update(delim);
            if (ctx_len)
                prf.update(ctx, ctx_len);
            prf.update(len_be.ptr, m_L / 8);
            prev = prf.finished();
            const size_t take = min(prev.length, key_len - key.length);
            key ~= prev.ptr[0 .. take];
        }
        return key;
    }

private:
    Unique!MessageAuthenticationCode m_prf;
    size_t m_r, m_L;
}

/// NIST SP 800-108 §5.3 Double-Pipeline mode. SCAN: "SP800-108-Pipeline(HMAC(SHA-256))"
final class SP800_108_Pipeline : KDF
{
    this(MessageAuthenticationCode mac, size_t r = 32, size_t L = 32)
    {
        validateBitLengths(r, L);
        m_prf = mac;
        m_r = r;
        m_L = L;
    }

    override @property string name() const { return name108("Pipeline", m_prf.name, m_r, m_L); }
    override KDF clone() const { return new SP800_108_Pipeline(m_prf.clone(), m_r, m_L); }

    override SecureVector!ubyte derive(size_t key_len,
                                       const(ubyte)* secret, size_t secret_len,
                                       const(ubyte)* salt, size_t salt_len) const
    {
        return derive(key_len, secret, secret_len, salt, salt_len, null, 0);
    }

    override SecureVector!ubyte derive(size_t key_len,
                                       const(ubyte)* secret, size_t secret_len,
                                       const(ubyte)* salt, size_t salt_len,
                                       const(ubyte)* label, size_t label_len) const
    {
        SecureVector!ubyte key;
        if (key_len == 0)
            return key;

        auto prf = cast(MessageAuthenticationCode)*m_prf;
        const size_t prf_len = prf.outputLength();
        const uint nblocks = blocksRequired(key_len, m_L, m_r, prf_len);
        const uint output_bits = cast(uint)(key_len * 8);
        const ubyte delim = 0;

        ubyte[4] ctr_be, len_be;
        encodeBeField(len_be[0 .. m_L / 8], output_bits);

        void constantInput()
        {
            if (label_len)
                prf.update(label, label_len);
            prf.update(delim);
            if (salt_len)
                prf.update(salt, salt_len);
            prf.update(len_be.ptr, m_L / 8);
        }

        prf.setKey(secret, secret_len);
        key.reserve(key_len);
        SecureVector!ubyte ai;

        foreach (uint counter; 1 .. nblocks + 1)
        {
            encodeBeField(ctr_be[0 .. m_r / 8], counter);
            if (ai.length == 0)
            {
                constantInput();
                ai = prf.finished();
            }
            else
            {
                prf.update(ai.ptr, ai.length);
                ai = prf.finished();
            }

            prf.update(ai.ptr, ai.length);
            prf.update(ctr_be.ptr, m_r / 8);
            constantInput();
            auto h = prf.finished();
            const size_t take = min(h.length, key_len - key.length);
            key ~= h.ptr[0 .. take];
        }
        return key;
    }

private:
    Unique!MessageAuthenticationCode m_prf;
    size_t m_r, m_L;
}
