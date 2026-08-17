/**
* OpenPGP S2K (RFC 4880 §3.7.1)
*
* Copyright:
* (C) 1999-2007,2017 Jack Lloyd
* (C) 2018 Ribose Inc
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pbkdf.pgp_s2k;

import botan.constants;
static if (BOTAN_HAS_PGP_S2K):

import botan.pbkdf.pbkdf;
import botan.hash.hash;
import botan.utils.exceptn;
import botan.utils.mem_ops;
import botan.utils.types;
import botan.algo_base.symkey;
import std.datetime;
import std.algorithm : min, max;

/**
* OpenPGP string-to-key. SCAN: "OpenPGP-S2K(SHA-1)".
* Iterations are the number of *bytes hashed*, not hash rounds.
* Empty salt + iterations==1 is simple S2K; salt + iterations==1 is
* salted; salt + iterations>1 is iterated.
*/
final class OpenPGP_S2K : PBKDF
{
public:
    this(HashFunction hash) { m_hash = hash; }

    override @property string name() const { return "OpenPGP-S2K(" ~ m_hash.name ~ ")"; }
    override PBKDF clone() const { return new OpenPGP_S2K(m_hash.clone()); }

    override Pair!(size_t, OctetString)
        keyDerivation(size_t output_len,
                      in string passphrase,
                      const(ubyte)* salt, size_t salt_len,
                      size_t iterations,
                      Duration) const
    {
        if (iterations == 0)
            throw new InvalidArgument("OpenPGP S2K: Invalid iteration count");
        SecureVector!ubyte outbuf = SecureVector!ubyte(output_len);
        pgpS2k(cast(HashFunction)*m_hash, outbuf.ptr, output_len,
               passphrase.ptr, passphrase.length, salt, salt_len, iterations);
        return makePair(iterations, OctetString(outbuf));
    }

private:
    Unique!HashFunction m_hash;
}

private:

void pgpS2k(HashFunction hash,
            ubyte* output, size_t output_len,
            const(char)* password, size_t password_size,
            const(ubyte)* salt, size_t salt_len,
            size_t iterations)
{
    if (iterations > 1 && salt_len == 0)
        throw new InvalidArgument("OpenPGP S2K requires a salt in iterated mode");

    const size_t input_len = salt_len + password_size;
    auto input_buf = SecureVector!ubyte(input_len);
    if (salt_len)
        copyMem(input_buf.ptr, salt, salt_len);
    if (password_size)
        copyMem(input_buf.ptr + salt_len, cast(const(ubyte)*) password, password_size);

    size_t pass = 0;
    size_t generated = 0;
    while (generated != output_len)
    {
        foreach (i; 0 .. pass)
        {
            ubyte z = 0;
            hash.update(z);
        }

        if (input_buf.length)
        {
            size_t left = max(iterations, input_buf.length);
            while (left > 0)
            {
                const size_t take = min(left, input_buf.length);
                hash.update(input_buf.ptr, take);
                left -= take;
            }
        }

        auto h = hash.finished();
        const size_t take = min(h.length, output_len - generated);
        copyMem(output + generated, h.ptr, take);
        generated += take;
        ++pass;
    }
}
