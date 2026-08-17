/**
* ISO-9796-2 DS2 / DS3 signature padding (message recovery)
*
* Copyright:
* (C) 2016 Tobias Niemann, Hackmanit GmbH
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pk_pad.iso9796;

import botan.constants;
static if (BOTAN_HAS_ISO9796):

import botan.pk_pad.emsa;
import botan.pk_pad.hash_id;
import botan.pk_pad.mgf1;
import botan.hash.hash;
import botan.rng.rng;
import botan.utils.exceptn;
import botan.utils.types;
import botan.utils.mem_ops;
import botan.utils.bit_ops;
import std.algorithm : min;

private SecureVector!ubyte iso9796Hash(HashFunction hash,
                                       const(ubyte)* msg1, size_t msg1_len,
                                       const(ubyte)* hmsg2, size_t hmsg2_len,
                                       const(ubyte)* salt, size_t salt_len)
{
    hash.updateBigEndian(cast(ulong) msg1_len * 8);
    if (msg1_len)
        hash.update(msg1, msg1_len);
    if (hmsg2_len)
        hash.update(hmsg2, hmsg2_len);
    if (salt_len)
        hash.update(salt, salt_len);
    return hash.finished();
}

private SecureVector!ubyte iso9796Encoding(const(ubyte)* msg, size_t msg_len,
                                           size_t output_bits,
                                           HashFunction hash,
                                           size_t salt_len,
                                           bool implicit,
                                           RandomNumberGenerator rng)
{
    const size_t output_length = (output_bits + 7) / 8;
    const size_t trailer_len = implicit ? 1 : 2;
    const size_t hash_len = hash.outputLength;

    if (output_length <= hash_len + salt_len + trailer_len)
        throw new EncodingError("ISO9796-2::encodingOf: Output length is too small");

    const size_t capacity = output_length - hash_len - salt_len - trailer_len - 1;
    const size_t msg1_len = min(capacity, msg_len);
    const(ubyte)* msg1 = msg;
    const(ubyte)* msg2 = msg + msg1_len;
    const size_t msg2_len = msg_len - msg1_len;

    if (msg2_len)
        hash.update(msg2, msg2_len);
    auto hmsg2 = hash.finished();

    auto salt = rng.randomVec(salt_len);
    auto H = iso9796Hash(hash, msg1, msg1_len, hmsg2.ptr, hmsg2.length, salt.ptr, salt.length);

    SecureVector!ubyte EM = SecureVector!ubyte(output_length);
    const size_t prefix = output_length - (hash_len + salt_len + trailer_len + msg1_len + 1);
    EM[prefix] = 0x01;
    if (msg1_len)
        copyMem(EM.ptr + prefix + 1, msg1, msg1_len);
    if (salt_len)
        copyMem(EM.ptr + prefix + 1 + msg1_len, salt.ptr, salt_len);

    const size_t mgf1_bytes = EM.length - hash_len - trailer_len;
    mgf1Mask(hash, H.ptr, H.length, EM.ptr, mgf1_bytes);

    const size_t unused = 8 * output_length - output_bits;
    EM[0] &= cast(ubyte)(0xFF >> unused);

    copyMem(EM.ptr + mgf1_bytes, H.ptr, hash_len);
    if (implicit)
        EM[EM.length - 1] = 0xBC;
    else
    {
        const ubyte hash_id = ieee1363HashId(hash.name);
        if (hash_id == 0)
            throw new EncodingError("ISO-9796: no hash identifier for " ~ hash.name);
        EM[EM.length - 2] = hash_id;
        EM[EM.length - 1] = 0xCC;
    }
    return EM.move();
}

private bool iso9796Verification(const(ubyte)* repr, size_t repr_len,
                                 const(ubyte)* raw, size_t raw_len,
                                 size_t key_bits,
                                 HashFunction hash,
                                 size_t salt_len,
                                 bool implicit)
{
    const size_t key_bytes = (key_bits + 7) / 8;
    if (repr_len > key_bytes)
        return false;

    SecureVector!ubyte coded = SecureVector!ubyte(key_bytes);
    copyMem(coded.ptr + (key_bytes - repr_len), repr, repr_len);
    if (coded.empty)
        return false;

    const size_t trailer_len = implicit ? 1 : 2;
    const size_t hash_len = hash.outputLength;
    if (coded.length <= hash_len + trailer_len + salt_len)
        return false;

    if (implicit)
    {
        if (coded[coded.length - 1] != 0xBC)
            return false;
    }
    else
    {
        const ubyte hash_id = ieee1363HashId(hash.name);
        if (hash_id == 0)
            throw new DecodingError("ISO-9796: no hash identifier for " ~ hash.name);
        if (coded[coded.length - 2] != hash_id || coded[coded.length - 1] != 0xCC)
            return false;
    }

    const size_t top_bits = 8 * key_bytes - key_bits;
    if (top_bits > 8 - highBit(coded[0]))
        return false;

    ubyte* DB = coded.ptr;
    const size_t DB_size = coded.length - hash_len - trailer_len;
    const(ubyte)* H = coded.ptr + DB_size;

    mgf1Mask(hash, H, hash_len, DB, DB_size);
    DB[0] &= cast(ubyte)(0xFF >> top_bits);

    size_t msg1_offset = 0;
    bool seen_one = false;
    foreach (size_t j; 0 .. DB_size)
    {
        if (!seen_one)
        {
            if (DB[j] == 0x00)
                continue;
            if (DB[j] == 0x01)
            {
                seen_one = true;
                msg1_offset = j + 1;
                continue;
            }
            return false;
        }
    }
    if (!seen_one)
        return false;
    if (coded.length < trailer_len + hash_len + msg1_offset + salt_len)
        return false;

    const size_t msg1_len = coded.length - (trailer_len + hash_len + msg1_offset + salt_len);
    const(ubyte)* msg1 = coded.ptr + msg1_offset;
    const(ubyte)* salt = coded.ptr + msg1_offset + msg1_len;

    const size_t capacity = key_bytes - hash_len - salt_len - trailer_len - 1;
    const(ubyte)* msg1raw = raw;
    size_t msg1raw_len = raw_len;
    if (raw_len > capacity)
    {
        hash.update(raw + capacity, raw_len - capacity);
        msg1raw_len = capacity;
    }
    auto hmsg2 = hash.finished();
    auto H2 = iso9796Hash(hash, msg1, msg1_len, hmsg2.ptr, hmsg2.length, salt, salt_len);

    if (H2.length != hash_len || !sameMem(H, H2.ptr, hash_len))
        return false;
    if (msg1_len != msg1raw_len)
        return false;
    if (msg1_len && !sameMem(msg1, msg1raw, msg1_len))
        return false;
    return true;
}

/// ISO-9796-2 DS2 (probabilistic). SCAN: "ISO_9796_DS2(SHA-256)" / "(hash,imp|exp[,salt])"
final class ISO9796_DS2 : EMSA
{
public:
    this(HashFunction hash, bool implicit, size_t salt_len)
    {
        m_hash = hash;
        m_implicit = implicit;
        m_salt_len = salt_len;
    }

    override void update(const(ubyte)* input, size_t length)
    {
        if (length)
            m_msg ~= input[0 .. length];
    }

    override SecureVector!ubyte rawData()
    {
        auto buf = m_msg.clone;
        m_msg.clear();
        return buf.move();
    }

    override SecureVector!ubyte encodingOf(const ref SecureVector!ubyte msg,
                                           size_t output_bits,
                                           RandomNumberGenerator rng)
    {
        return iso9796Encoding(msg.ptr, msg.length, output_bits, m_hash, m_salt_len, m_implicit, rng);
    }

    override bool verify(const ref SecureVector!ubyte coded,
                         const ref SecureVector!ubyte raw,
                         size_t key_bits)
    {
        return iso9796Verification(coded.ptr, coded.length, raw.ptr, raw.length,
                                   key_bits, m_hash, m_salt_len, m_implicit);
    }

private:
    Unique!HashFunction m_hash;
    bool m_implicit;
    size_t m_salt_len;
    SecureVector!ubyte m_msg;
}

/// ISO-9796-2 DS3 (deterministic; DS2 with empty salt). SCAN: "ISO_9796_DS3(SHA-1,exp)"
final class ISO9796_DS3 : EMSA
{
public:
    this(HashFunction hash, bool implicit = false)
    {
        m_hash = hash;
        m_implicit = implicit;
    }

    override void update(const(ubyte)* input, size_t length)
    {
        if (length)
            m_msg ~= input[0 .. length];
    }

    override SecureVector!ubyte rawData()
    {
        auto outp = m_msg.clone;
        m_msg.clear();
        return outp.move();
    }

    override SecureVector!ubyte encodingOf(const ref SecureVector!ubyte msg,
                                           size_t output_bits,
                                           RandomNumberGenerator rng)
    {
        return iso9796Encoding(msg.ptr, msg.length, output_bits, m_hash, 0, m_implicit, rng);
    }

    override bool verify(const ref SecureVector!ubyte coded,
                         const ref SecureVector!ubyte raw,
                         size_t key_bits)
    {
        return iso9796Verification(coded.ptr, coded.length, raw.ptr, raw.length,
                                   key_bits, m_hash, 0, m_implicit);
    }

private:
    Unique!HashFunction m_hash;
    bool m_implicit;
    SecureVector!ubyte m_msg;
}

static if (BOTAN_TEST):

import botan.test;
import botan.pubkey.pubkey;
import botan.pubkey.algo.rsa;
import botan.pk_pad.factory;
import botan.libstate.global_state;
import botan.codec.hex;
import botan.math.bigint.bigint;
import memutils.hashmap;
import std.stdio : File;

static if (BOTAN_HAS_TESTS && !SKIP_ISO9796_TEST) unittest
{
    auto state = globalState();
    logDebug("Testing iso9796.d ...");

    {
        EMSA ds2 = getEmsa("ISO_9796_DS2(SHA-256)");
        EMSA ds3 = getEmsa("ISO_9796_DS3(SHA-1,imp)");
        assert(cast(ISO9796_DS2) ds2 !is null, "ISO_9796_DS2 must be castable to ISO9796_DS2");
        assert(cast(ISO9796_DS3) ds3 !is null, "ISO_9796_DS3 must be castable to ISO9796_DS3");
        Unique!EMSA o1 = ds2;
        Unique!EMSA o2 = ds3;
    }

    size_t fails = 0;
    static if (BOTAN_HAS_RSA) {
    File vec = File("test_data/pubkey/iso9796.vec", "r");
    fails += runTestsBb(vec, "ISO9796", "Signature", false,
        (ref HashMap!(string, string) m)
        {
            if (!("Signature" in m) || !("N" in m) || !("Padding" in m))
                return 0;
            auto e = BigInt(m["E"]);
            auto n = BigInt(m["N"]);
            auto key = RSAPublicKey(n.move(), e.move());
            PKVerifier verify = PKVerifier(key, m["Padding"]);
            auto msg = hexDecode(m.get("Msg"));
            auto sig = hexDecode(m["Signature"]);
            if (!verify.verifyMessage(msg, sig))
                return 1;
            return 0;
        });
    }

    assert(fails == 0);
}
