/**
* PKCS#12 KDF (RFC 7292 Appendix B)
*
* Copyright:
* (C) 2018 Ribose Inc
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pbkdf.pkcs12_kdf;

import botan.constants;
static if (BOTAN_HAS_PKCS12_KDF):

import botan.pbkdf.pbkdf;
import botan.hash.hash;
import botan.utils.exceptn;
import botan.utils.mem_ops;
import botan.utils.types;
import botan.algo_base.symkey;
import std.datetime;
import std.algorithm : min;
import std.conv : to;

/**
* PKCS#12 key-derivation. SCAN: "PKCS12-KDF(SHA-256,1)"
* Second argument is purpose id: 1=key, 2=IV, 3=MAC.
* deriveKey iterations are the RFC 7292 iteration count.
*/
final class PKCS12_KDF : PBKDF
{
public:
    /**
    * Params:
    *  hash = hash used for RFC 7292 KDF
    *  id = purpose: 1=key, 2=IV, 3=MAC
    */
    this(HashFunction hash, ubyte id)
    {
        if (id < 1 || id > 3)
            throw new InvalidArgument("PKCS12-KDF: id must be 1 (key), 2 (IV), or 3 (MAC)");
        m_hash = hash;
        m_id = id;
    }

    override @property string name() const
    {
        return "PKCS12-KDF(" ~ m_hash.name ~ "," ~ to!string(m_id) ~ ")";
    }
    override PBKDF clone() const { return new PKCS12_KDF(m_hash.clone(), m_id); }

    override Pair!(size_t, OctetString)
        keyDerivation(size_t output_len,
                      in string passphrase,
                      const(ubyte)* salt, size_t salt_len,
                      size_t iterations,
                      Duration) const
    {
        if (iterations == 0)
            throw new InvalidArgument("PKCS12-KDF: Invalid iteration count");
        SecureVector!ubyte outbuf = SecureVector!ubyte(output_len);
        auto pwd = encodePassword(passphrase);
        pkcs12Kdf(outbuf.ptr, output_len, pwd.ptr, pwd.length,
                  salt, salt_len, iterations, m_id, cast(HashFunction)*m_hash);
        return makePair(iterations, OctetString(outbuf));
    }

private:
    Unique!HashFunction m_hash;
    ubyte m_id;
}

private:

SecureVector!ubyte encodePassword(in string password)
{
    if (password.length == 0)
    {
        auto empty = SecureVector!ubyte(2);
        empty[0] = 0;
        empty[1] = 0;
        return empty.move();
    }
    auto r = SecureVector!ubyte(password.length * 2 + 2);
    foreach (i, c; password)
    {
        if (c > 127)
            throw new InvalidArgument("PKCS12-KDF: non-ASCII passphrase not supported");
        r[2 * i] = 0;
        r[2 * i + 1] = cast(ubyte) c;
    }
    return r.move();
}

void copyRepeat(ubyte* buf, size_t buf_len, const(ubyte)* data, size_t data_len)
{
    if (data_len == 0)
    {
        setMem(buf, buf_len, 0);
        return;
    }
    size_t pos = 0;
    while (pos < buf_len)
    {
        const size_t n = min(data_len, buf_len - pos);
        copyMem(buf + pos, data, n);
        pos += n;
    }
}

void bigendianAddOne(ubyte* block, size_t len, const(ubyte)* addend)
{
    ushort carry = 1;
    foreach_reverse (k; 0 .. len)
    {
        carry += cast(ushort) block[k] + cast(ushort) addend[k];
        block[k] = cast(ubyte)(carry & 0xFF);
        carry >>= 8;
    }
}

/// RFC 7292 Appendix B KDF over already-encoded password bytes (OpenSSL empty-pwd uses length 0).
public void pkcs12Kdf(ubyte* outp, size_t out_len,
               const(ubyte)* pwd, size_t pwd_len,
               const(ubyte)* salt, size_t salt_len,
               size_t iterations, ubyte id, HashFunction hash)
{
    if (out_len == 0)
        return;
    const size_t v = hash.hashBlockSize();
    if (v == 0)
        throw new InvalidArgument("PKCS12-KDF does not support hash '" ~ hash.name ~ "'");
    const size_t hash_len = hash.outputLength();

    size_t roundUp(size_t len)
    {
        if (len == 0)
            return 0;
        return ((len + v - 1) / v) * v;
    }

    const size_t S_len = roundUp(salt_len);
    const size_t P_len = roundUp(pwd_len);
    const size_t I_len = S_len + P_len;

    auto D = SecureVector!ubyte(v);
    foreach (i; 0 .. v)
        D[i] = id;

    auto I = SecureVector!ubyte(I_len);
    if (S_len)
        copyRepeat(I.ptr, S_len, salt, salt_len);
    if (P_len)
        copyRepeat(I.ptr + S_len, P_len, pwd, pwd_len);

    auto A = SecureVector!ubyte(hash_len);
    auto B = SecureVector!ubyte(v);
    size_t off = 0;
    while (off < out_len)
    {
        hash.update(D.ptr, D.length);
        if (I_len)
            hash.update(I.ptr, I.length);
        {
            auto h = hash.finished();
            foreach (i; 0 .. A.length)
                A[i] = h[i];
        }
        foreach (iter; 1 .. iterations)
        {
            hash.update(A.ptr, A.length);
            auto h = hash.finished();
            foreach (i; 0 .. A.length)
                A[i] = h[i];
        }

        const size_t n = min(hash_len, out_len - off);
        copyMem(outp + off, A.ptr, n);
        off += n;

        copyRepeat(B.ptr, v, A.ptr, hash_len);
        for (size_t j = 0; j < I_len; j += v)
            bigendianAddOne(I.ptr + j, v, B.ptr);
    }
}
