/**
* KDF1 from ISO 18033-2
*
* Copyright:
* (C) 2016 Philipp Weber
* (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.kdf.kdf1_iso18033;

import botan.constants;
static if (BOTAN_HAS_KDF1_18033):

import botan.kdf.kdf;
import botan.hash.hash;
import botan.utils.exceptn;
import botan.utils.types;
import std.algorithm : min;

/**
* KDF1 (ISO 18033-2). Distinct from IEEE 1363 KDF1.
* SCAN: "KDF1-18033(SHA-256)"
*
* Hash(secret || counter_be32 || label || salt), counter from 0.
*/
final class KDF1_18033 : KDF
{
public:
    this(HashFunction hash) { m_hash = hash; }

    override @property string name() const { return "KDF1-18033(" ~ m_hash.name ~ ")"; }
    override KDF clone() const { return new KDF1_18033(m_hash.clone()); }

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
        SecureVector!ubyte output;
        if (key_len == 0)
            return output;

        auto hash = cast(HashFunction)*m_hash;
        const size_t hlen = hash.outputLength();
        const ulong blocks = (key_len + hlen - 1) / hlen;
        if (blocks > 0xFFFFFFFF)
            throw new InvalidArgument("KDF1-18033 maximum output length exceeded");

        output.reserve(key_len);
        foreach (uint counter; 0 .. cast(uint) blocks)
        {
            hash.update(secret, secret_len);
            hash.updateBigEndian(counter);
            if (label_len)
                hash.update(label, label_len);
            if (salt_len)
                hash.update(salt, salt_len);
            auto h = hash.finished();
            const size_t take = min(h.length, key_len - output.length);
            output ~= h.ptr[0 .. take];
        }
        return output;
    }

private:
    Unique!HashFunction m_hash;
}
