/**
* HKDF (RFC 5869) as a KDF, plus Extract/Expand
*
* Copyright:
* (C) 2013,2015,2017 Jack Lloyd
* (C) 2016 René Korthaus, Rohde & Schwarz Cybersecurity
* (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.prf.hkdf;

import botan.constants;
static if (BOTAN_HAS_HKDF):

static assert(BOTAN_HAS_TLS || BOTAN_HAS_PUBLIC_KEY_CRYPTO,
              "HKDF is a KDF and requires TLS or PUBKEY so getKdf exists");

import botan.kdf.kdf;
import botan.mac.mac;
import botan.hash.hash;
import botan.utils.types;
import botan.utils.mem_ops;
import botan.utils.exceptn;
import std.algorithm : min;

/// RFC 5869 HKDF-Extract. SCAN: "HKDF-Extract(SHA-256)" or "HKDF-Extract(HMAC(SHA-256))"
final class HKDF_Extract : KDF
{
public:
    /**
    * Params:
    *  prf = HMAC used as the extractor
    */
    this(MessageAuthenticationCode prf)
    {
        m_prf = prf;
    }

    override @property string name() const { return "HKDF-Extract(" ~ m_prf.name ~ ")"; }
    override KDF clone() const { return new HKDF_Extract(m_prf.clone()); }

    override SecureVector!ubyte derive(size_t key_len,
                                       const(ubyte)* secret, size_t secret_len,
                                       const(ubyte)* salt, size_t salt_len) const
    {
        return derive(key_len, secret, secret_len, salt, salt_len, null, 0);
    }

    override SecureVector!ubyte derive(size_t key_len,
                                       const(ubyte)* secret, size_t secret_len,
                                       const(ubyte)* salt, size_t salt_len,
                                       const(ubyte)*, size_t label_len) const
    {
        if (label_len)
            throw new InvalidArgument("HKDF-Extract does not support a label input");
        const size_t prf_len = m_prf.outputLength;
        if (key_len > prf_len)
            throw new InvalidArgument("HKDF-Extract maximum output length exceeded");
        if (key_len == 0)
            return SecureVector!ubyte();

        Unique!MessageAuthenticationCode prf = m_prf.clone();
        if (salt_len == 0)
        {
            auto zeros = SecureVector!ubyte(prf_len);
            prf.setKey(zeros.ptr, zeros.length);
        }
        else
            prf.setKey(salt, salt_len);
        prf.update(secret, secret_len);
        auto prk = prf.finished();
        if (key_len == prk.length)
            return prk.move();
        SecureVector!ubyte outp = SecureVector!ubyte(key_len);
        copyMem(outp.ptr, prk.ptr, key_len);
        return outp.move();
    }

private:
    Unique!MessageAuthenticationCode m_prf;
}

/// RFC 5869 HKDF-Expand. SCAN: "HKDF-Expand(SHA-256)". Info is label then salt.
final class HKDF_Expand : KDF
{
public:
    /**
    * Params:
    *  prf = HMAC used as the expander
    */
    this(MessageAuthenticationCode prf)
    {
        m_prf = prf;
    }

    override @property string name() const { return "HKDF-Expand(" ~ m_prf.name ~ ")"; }
    override KDF clone() const { return new HKDF_Expand(m_prf.clone()); }

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
        const size_t prf_len = m_prf.outputLength;
        if (key_len > prf_len * 255)
            throw new InvalidArgument("HKDF-Expand maximum output length exceeded");
        if (key_len == 0)
            return SecureVector!ubyte();

        Unique!MessageAuthenticationCode prf = m_prf.clone();
        prf.setKey(secret, secret_len);

        SecureVector!ubyte key = SecureVector!ubyte(key_len);
        SecureVector!ubyte T;
        size_t offset = 0;
        ubyte counter = 1;
        while (offset < key_len)
        {
            prf.update(T);
            if (label_len)
                prf.update(label, label_len);
            if (salt_len)
                prf.update(salt, salt_len);
            prf.update(counter++);
            T = prf.finished();
            const size_t take = min(T.length, key_len - offset);
            copyMem(key.ptr + offset, T.ptr, take);
            offset += take;
        }
        return key.move();
    }

private:
    Unique!MessageAuthenticationCode m_prf;
}

/**
* HKDF, see RFC 5869. SCAN: "HKDF(SHA-256)" / "HKDF(HMAC(SHA-256))".
* Salt is the HKDF salt; label is the info string.
* startExtract/extract/expand remain for incremental use.
*/
final class HKDF : KDF
{
public:
    this(MessageAuthenticationCode extractor,
         MessageAuthenticationCode prf)
    {
        m_extractor = extractor;
        m_prf = prf;
    }

    this(MessageAuthenticationCode prf)
    {
        m_extractor = prf;
        m_prf = m_extractor.clone();
    }

    override @property string name() const
    {
        return "HKDF(" ~ m_prf.name ~ ")";
    }

    override KDF clone() const { return new HKDF(m_prf.clone()); }

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
        Unique!HKDF_Extract extract = new HKDF_Extract(m_prf.clone());
        auto prk = extract.derive(m_prf.outputLength, secret, secret_len, salt, salt_len, null, 0);
        Unique!HKDF_Expand expand = new HKDF_Expand(m_prf.clone());
        return expand.derive(key_len, prk.ptr, prk.length, null, 0, label, label_len);
    }

    void startExtract(const(ubyte)* salt, size_t salt_len)
    {
        m_extractor.setKey(salt, salt_len);
    }

    void extract(const(ubyte)* input, size_t input_len)
    {
        m_extractor.update(input, input_len);
    }

    void finishExtract()
    {
        m_prf.setKey(m_extractor.finished());
    }

    /// Incremental expand after extract. Info-only (RFC 5869).
    void expand(ubyte* output, size_t output_len,
                const(ubyte)* info, size_t info_len)
    {
        if (output_len > m_prf.outputLength * 255)
            throw new InvalidArgument("HKDF requested output too large");

        ubyte counter = 1;
        SecureVector!ubyte T;
        while (output_len)
        {
            m_prf.update(T);
            m_prf.update(info, info_len);
            m_prf.update(counter++);
            T = m_prf.finished();

            const size_t to_write = min(T.length, output_len);
            copyMem(output, T.ptr, to_write);
            output += to_write;
            output_len -= to_write;
        }
    }

    void clear()
    {
        m_extractor.clear();
        m_prf.clear();
    }

private:
    Unique!MessageAuthenticationCode m_extractor;
    Unique!MessageAuthenticationCode m_prf;
}


static if (BOTAN_TEST):

import botan.test;
import botan.codec.hex;
import botan.libstate.libstate;
import botan.libstate.lookup;
import memutils.hashmap;

private shared size_t total_tests;

size_t hkdfTest(string algo, string ikm, string salt, string info, string okm, size_t L)
{
    import core.atomic;
    atomicOp!"+="(total_tests, 1);

    KDF kdf = getKdf(algo);
    if (cast(HKDF) kdf is null)
    {
        logTrace("getKdf(" ~ algo ~ ") did not return HKDF");
        return 1;
    }
    Unique!KDF owned = kdf;

    auto key = owned.deriveKey(L, hexDecodeLocked(ikm), hexDecode(salt), hexDecode(info));
    const string got = hexEncode(key);
    if (got != okm)
    {
        logTrace("HKDF got " ~ got ~ " expected " ~ okm);
        return 1;
    }
    return 0;
}

static if (BOTAN_HAS_TESTS && !SKIP_HKDF_TEST) unittest
{
    auto state = globalState();
    logDebug("Testing hkdf.d ...");

    {
        KDF full = getKdf("HKDF(SHA-256)");
        KDF ext = getKdf("HKDF-Extract(SHA-256)");
        KDF exp = getKdf("HKDF-Expand(HMAC(SHA-256))");
        assert(cast(HKDF) full !is null, "HKDF(SHA-256) must be castable to HKDF");
        assert(cast(HKDF_Extract) ext !is null, "HKDF-Extract(SHA-256) must be castable to HKDF_Extract");
        assert(cast(HKDF_Expand) exp !is null, "HKDF-Expand(HMAC(SHA-256)) must be castable to HKDF_Expand");
        Unique!KDF o1 = full;
        Unique!KDF o2 = ext;
        Unique!KDF o3 = exp;
    }

    File vec = File("test_data/hkdf.vec", "r");

    size_t fails = runTestsBb(vec, "HKDF", "OKM", true,
        (ref HashMap!(string, string) m)
        {
            return hkdfTest(m["HKDF"], m["IKM"], m.get("salt"), m.get("info"), m["OKM"], to!uint(m["L"]));
        });

    fails += checkMemutilsRepeat("hkdf factory", {
        Unique!KDF k = getKdf("HKDF(SHA-256)");
        ubyte[8] s = 1;
        auto outp = k.deriveKey(16, s.ptr, s.length, null, 0);
        if (outp.length != 16)
            throw new Exception("hkdf leak probe");
    });

    testReport("hkdf", total_tests, fails);
}
