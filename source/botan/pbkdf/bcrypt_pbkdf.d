/**
* Bcrypt-PBKDF (OpenBSD bcrypt_pbkdf)
*
* Copyright:
* (C) 2018,2019 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pbkdf.bcrypt_pbkdf;

import botan.constants;
static if (BOTAN_HAS_PBKDF_BCRYPT && BOTAN_HAS_BLOWFISH && BOTAN_HAS_SHA2_64):

import botan.pbkdf.pbkdf;
import botan.block.blowfish;
import botan.hash.sha2_64;
import botan.utils.loadstor;
import botan.utils.xor_buf;
import botan.utils.mem_ops;
import botan.utils.exceptn;
import botan.utils.types;
import botan.algo_base.symkey;
import std.datetime;
import std.algorithm : min;

/**
* OpenBSD bcrypt_pbkdf. SCAN: "Bcrypt-PBKDF".
* deriveKey iterations are the bcrypt-PBKDF rounds.
*/
final class BcryptPBKDF : PBKDF
{
public:
    override @property string name() const { return "Bcrypt-PBKDF"; }
    override PBKDF clone() const { return new BcryptPBKDF; }

    override Pair!(size_t, OctetString)
        keyDerivation(size_t output_len,
                      in string passphrase,
                      const(ubyte)* salt, size_t salt_len,
                      size_t iterations,
                      Duration) const
    {
        if (iterations == 0)
            throw new InvalidArgument("Invalid Bcrypt-PBKDF iterations");
        if (output_len > 10 * 1024 * 1024)
            throw new InvalidArgument("Too much output for Bcrypt PBKDF");

        SecureVector!ubyte outbuf = SecureVector!ubyte(output_len);
        if (output_len)
            derive(outbuf.ptr, output_len,
                   cast(const(ubyte)*) passphrase.ptr, passphrase.length,
                   salt, salt_len, iterations);
        return makePair(iterations, OctetString(outbuf));
    }

private:
    enum size_t BLOCK = 32;

    static void bcryptRound(Blowfish blowfish,
                            const ref SecureVector!ubyte pass_hash,
                            const ref SecureVector!ubyte salt_hash,
                            ref SecureVector!ubyte outb,
                            ref SecureVector!ubyte tmp)
    {
        __gshared immutable ubyte[32] MAGIC = [
            0x4F, 0x78, 0x79, 0x63, 0x68, 0x72, 0x6F, 0x6D,
            0x61, 0x74, 0x69, 0x63, 0x42, 0x6C, 0x6F, 0x77,
            0x66, 0x69, 0x73, 0x68, 0x53, 0x77, 0x61, 0x74,
            0x44, 0x79, 0x6E, 0x61, 0x6D, 0x69, 0x74, 0x65
        ];

        blowfish.saltedSetKey(pass_hash.ptr, pass_hash.length,
                              salt_hash.ptr, salt_hash.length, 6, true);
        copyMem(tmp.ptr, MAGIC.ptr, BLOCK);
        foreach (i; 0 .. 64)
            blowfish.encryptN(tmp.ptr, tmp.ptr, 4);

        foreach (i; 0 .. 8)
        {
            const uint w = loadLittleEndian!uint(tmp.ptr, i);
            storeBigEndian(w, tmp.ptr + 4 * i);
        }
        xorBuf(outb.ptr, tmp.ptr, BLOCK);
    }

    static void derive(ubyte* output, size_t output_len,
                       const(ubyte)* password, size_t password_len,
                       const(ubyte)* salt, size_t salt_len,
                       size_t iterations)
    {
        const size_t blocks = (output_len + BLOCK - 1) / BLOCK;
        Unique!SHA512 sha = new SHA512;
        sha.update(password, password_len);
        auto pass_hash = sha.finished();

        auto salt_hash = SecureVector!ubyte(sha.outputLength);
        Unique!Blowfish blowfish = new Blowfish;
        auto outb = SecureVector!ubyte(BLOCK);
        auto tmp = SecureVector!ubyte(BLOCK);

        foreach (size_t block; 0 .. blocks)
        {
            zeroise(outb);
            sha.update(salt, salt_len);
            sha.updateBigEndian(cast(uint)(block + 1));
            {
                auto h = sha.finished();
                foreach (i; 0 .. salt_hash.length)
                    salt_hash[i] = h[i];
            }

            bcryptRound(blowfish, pass_hash, salt_hash, outb, tmp);

            foreach (size_t r; 1 .. iterations)
            {
                sha.update(tmp.ptr, tmp.length);
                {
                    auto h = sha.finished();
                    foreach (i; 0 .. salt_hash.length)
                        salt_hash[i] = h[i];
                }
                bcryptRound(blowfish, pass_hash, salt_hash, outb, tmp);
            }

            foreach (size_t i; 0 .. BLOCK)
            {
                const size_t dest = i * blocks + block;
                if (dest < output_len)
                    output[dest] = outb[i];
            }
        }
    }
}
