/**
* NIST SP 800-56A r2 / SP 800-56C r2 One-Step KDF
*
* Copyright:
* (C) 2017 Ribose Inc. Written by Krzysztof Kwiatkowski.
* (C) 2024 Fabian Albert - Rohde & Schwarz Cybersecurity
* (C) 2024 René Meusel - Rohde & Schwarz Cybersecurity
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.kdf.sp800_56a;

import botan.constants;
static if (BOTAN_HAS_SP800_56A):

import botan.kdf.kdf;
import botan.hash.hash;
import botan.mac.mac;
import botan.utils.exceptn;
import botan.utils.types;
import std.algorithm : min;

private:

SecureVector!ubyte kdmHash(HashFunction hash,
                           size_t key_len,
                           const(ubyte)* secret, size_t secret_len,
                           const(ubyte)* label, size_t label_len)
{
    SecureVector!ubyte key;
    if (key_len == 0)
        return key;
    const size_t hlen = hash.outputLength();
    const ulong reps = (key_len + hlen - 1) / hlen;
    if (reps > 0xFFFFFFFF)
        throw new InvalidArgument("Too large KDM output length");
    key.reserve(key_len);
    foreach (uint i; 1 .. cast(uint) reps + 1)
    {
        hash.clear();
        hash.updateBigEndian(i);
        if (secret_len)
            hash.update(secret, secret_len);
        if (label_len)
            hash.update(label, label_len);
        auto ki = hash.finished();
        const size_t take = min(ki.length, key_len - key.length);
        key ~= ki.ptr[0 .. take];
    }
    return key;
}

SecureVector!ubyte kdmMac(MessageAuthenticationCode mac,
                          void delegate(MessageAuthenticationCode) init,
                          size_t key_len,
                          const(ubyte)* secret, size_t secret_len,
                          const(ubyte)* label, size_t label_len)
{
    SecureVector!ubyte key;
    if (key_len == 0)
        return key;
    const size_t hlen = mac.outputLength();
    const ulong reps = (key_len + hlen - 1) / hlen;
    if (reps > 0xFFFFFFFF)
        throw new InvalidArgument("Too large KDM output length");
    key.reserve(key_len);
    foreach (uint i; 1 .. cast(uint) reps + 1)
    {
        mac.clear();
        if (init)
            init(mac);
        mac.updateBigEndian(i);
        if (secret_len)
            mac.update(secret, secret_len);
        if (label_len)
            mac.update(label, label_len);
        auto ki = mac.finished();
        const size_t take = min(ki.length, key_len - key.length);
        key ~= ki.ptr[0 .. take];
    }
    return key;
}

public:

/// One-step KDF with a hash. SCAN: "SP800-56A(SHA-256)". Salt must be empty.
final class SP800_56A_Hash : KDF
{
    this(HashFunction hash) { m_hash = hash; }

    override @property string name() const { return "SP800-56A(" ~ m_hash.name ~ ")"; }
    override KDF clone() const { return new SP800_56A_Hash(m_hash.clone()); }

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
        if (salt_len)
            throw new InvalidArgument("SP800-56C KDF with hash does not support using a salt parameter");
        return kdmHash(cast(HashFunction)*m_hash, key_len, secret, secret_len, label, label_len);
    }

private:
    Unique!HashFunction m_hash;
}

/// One-step KDF with HMAC. SCAN: "SP800-56A(HMAC(SHA-256))"
final class SP800_56A_HMAC : KDF
{
    this(MessageAuthenticationCode mac)
    {
        if (mac.name.length < 5 || mac.name[0 .. 5] != "HMAC(")
            throw new AlgorithmNotFound("Only HMAC can be used with SP800_56A_HMAC");
        m_mac = mac;
    }

    override @property string name() const { return "SP800-56A(" ~ m_mac.name ~ ")"; }
    override KDF clone() const { return new SP800_56A_HMAC(m_mac.clone()); }

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
        auto mac = cast(MessageAuthenticationCode)*m_mac;
        return kdmMac(mac, (MessageAuthenticationCode m) { m.setKey(salt, salt_len); },
                      key_len, secret, secret_len, label, label_len);
    }

private:
    Unique!MessageAuthenticationCode m_mac;
}

static if (BOTAN_HAS_KMAC):

import botan.mac.kmac;

/// One-step KDF with KMAC-128. SCAN: "SP800-56A(KMAC-128)"
final class SP800_56A_KMAC128 : KDF
{
    override @property string name() const { return "SP800-56A(KMAC-128)"; }
    override KDF clone() const { return new SP800_56A_KMAC128; }

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
        return kdmKmac(new KMAC128(key_len ? key_len * 8 : 8), 164,
                       key_len, secret, secret_len, salt, salt_len, label, label_len);
    }
}

/// One-step KDF with KMAC-256. SCAN: "SP800-56A(KMAC-256)"
final class SP800_56A_KMAC256 : KDF
{
    override @property string name() const { return "SP800-56A(KMAC-256)"; }
    override KDF clone() const { return new SP800_56A_KMAC256; }

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
        return kdmKmac(new KMAC256(key_len ? key_len * 8 : 8), 132,
                       key_len, secret, secret_len, salt, salt_len, label, label_len);
    }
}

private:

SecureVector!ubyte kdmKmac(MessageAuthenticationCode mac, size_t default_salt_len,
                           size_t key_len,
                           const(ubyte)* secret, size_t secret_len,
                           const(ubyte)* salt, size_t salt_len,
                           const(ubyte)* label, size_t label_len)
{
    if (key_len == 0)
        return SecureVector!ubyte();
    auto zeros = SecureVector!ubyte(default_salt_len);
    return kdmMac(mac, (MessageAuthenticationCode m) {
        if (salt_len == 0)
            m.setKey(zeros.ptr, zeros.length);
        else
            m.setKey(salt, salt_len);
        auto ms = cast(MacStart) m;
        if (ms)
            ms.start(cast(const(ubyte)*)"KDF".ptr, 3);
    }, key_len, secret, secret_len, label, label_len);
}
