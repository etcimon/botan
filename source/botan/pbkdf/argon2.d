/**
* Argon2 password hash / PBKDF
*
* Copyright:
* (C) 2018,2019,2022 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pbkdf.argon2;

import botan.constants;
static if (BOTAN_HAS_ARGON2 && BOTAN_HAS_BLAKE2B):

import botan.pbkdf.pbkdf;
import botan.hash.hash;
import botan.libstate.libstate;
import botan.libstate.lookup;
import botan.utils.loadstor;
import botan.utils.rotate;
import botan.utils.mem_ops;
import botan.utils.exceptn;
import botan.utils.types;
import botan.algo_base.symkey;
import std.datetime;
import std.algorithm : min;
import std.conv : to;

enum size_t ARGON2_SYNC_POINTS = 4;

/**
* Argon2 (d / i / id) as a PBKDF.
*
* SCAN: "Argon2id", "Argon2i", "Argon2d", or "Argon2id(M,t,p)".
* deriveKey iterations map to the time cost t.
*/
final class Argon2 : PBKDF
{
public:
    /**
    * Params:
    *  family = 0 Argon2d, 1 Argon2i, 2 Argon2id
    *  M = memory in KiB (must be >= 8*p)
    *  t = time cost (iterations)
    *  p = parallelism
    */
    this(ubyte family, size_t M, size_t t, size_t p)
    {
        if (family > 2)
            throw new InvalidArgument("Argon2: unknown family");
        if (p == 0 || M < 8 * p)
            throw new InvalidArgument("Argon2: invalid memory/parallelism");
        if (t == 0)
            throw new InvalidArgument("Argon2: invalid time cost");
        m_family = family;
        m_M = M;
        m_t = t;
        m_p = p;
    }

    override @property string name() const
    {
        string fam = m_family == 0 ? "Argon2d" : (m_family == 1 ? "Argon2i" : "Argon2id");
        return fam ~ "(" ~ to!string(m_M) ~ "," ~ to!string(m_t) ~ "," ~ to!string(m_p) ~ ")";
    }

    override PBKDF clone() const
    {
        return new Argon2(m_family, m_M, m_t, m_p);
    }

    @property size_t memoryKiB() const { return m_M; }
    @property size_t timeCost() const { return m_t; }
    @property size_t parallelism() const { return m_p; }
    @property ubyte family() const { return m_family; }

    /// Full Argon2 with optional secret and associated data (RFC 9106).
    void derive(ubyte* output, size_t output_len,
                const(ubyte)* password, size_t password_len,
                const(ubyte)* salt, size_t salt_len,
                const(ubyte)* key, size_t key_len,
                const(ubyte)* ad, size_t ad_len,
                size_t t) const
    {
        argon2(output, output_len, password, password_len, salt, salt_len,
               key, key_len, ad, ad_len, t);
    }

    override Pair!(size_t, OctetString)
        keyDerivation(size_t output_len,
                      in string passphrase,
                      const(ubyte)* salt, size_t salt_len,
                      size_t iterations,
                      Duration loop_for) const
    {
        size_t t = iterations ? iterations : m_t;
        if (t == 0)
            t = 1;
        if (output_len < 4)
            throw new InvalidArgument("Argon2: output too short");

        if (iterations == 0 && loop_for > Duration.zero)
        {
            import std.datetime.stopwatch : StopWatch;
            StopWatch sw;
            sw.start();
            t = 1;
            SecureVector!ubyte scratch = SecureVector!ubyte(output_len);
            while (true)
            {
                argon2(scratch.ptr, output_len,
                       cast(const(ubyte)*) passphrase.ptr, passphrase.length,
                       salt, salt_len, null, 0, null, 0, t);
                if (sw.peek() >= loop_for)
                    break;
                ++t;
            }
            return makePair(t, OctetString(scratch));
        }

        SecureVector!ubyte outbuf = SecureVector!ubyte(output_len);
        argon2(outbuf.ptr, output_len,
               cast(const(ubyte)*) passphrase.ptr, passphrase.length,
               salt, salt_len, null, 0, null, 0, t);
        return makePair(t, OctetString(outbuf));
    }

private:
    void argon2(ubyte* output, size_t output_len,
                const(ubyte)* password, size_t password_len,
                const(ubyte)* salt, size_t salt_len,
                const(ubyte)* key, size_t key_len,
                const(ubyte)* ad, size_t ad_len,
                size_t t) const
    {
        if (output_len < 4)
            throw new InvalidArgument("Argon2: invalid output length");

        Unique!HashFunction blake2 = retrieveHash("BLAKE2b").clone();

        ubyte[64] H0;
        argon2H0(*blake2, H0, output_len, password, password_len,
                 salt, salt_len, key, key_len, ad, ad_len,
                 m_family, m_p, m_M, t);

        const size_t memory = (m_M / (ARGON2_SYNC_POINTS * m_p)) * (ARGON2_SYNC_POINTS * m_p);
        enum size_t M_scale = 1024 / 8;
        SecureVector!ulong B = SecureVector!ulong(memory * M_scale);

        initBlocks(B, *blake2, H0, memory, m_p);
        processBlocks(B, t, memory, m_p, m_family);

        zeroise(output[0 .. output_len]);
        extractKey(output, output_len, B, memory, m_p);
    }

    ubyte m_family;
    size_t m_M, m_t, m_p;
}

private:

void updateLe32(HashFunction h, uint v)
{
    ubyte[4] buf;
    storeLittleEndian(v, buf.ptr);
    h.update(buf.ptr, 4);
}

void argon2H0(HashFunction blake2b, ref ubyte[64] H0,
              size_t output_len,
              const(ubyte)* password, size_t password_len,
              const(ubyte)* salt, size_t salt_len,
              const(ubyte)* key, size_t key_len,
              const(ubyte)* ad, size_t ad_len,
              size_t y, size_t p, size_t M, size_t t)
{
    const ubyte v = 19;
    updateLe32(blake2b, cast(uint) p);
    updateLe32(blake2b, cast(uint) output_len);
    updateLe32(blake2b, cast(uint) M);
    updateLe32(blake2b, cast(uint) t);
    updateLe32(blake2b, cast(uint) v);
    updateLe32(blake2b, cast(uint) y);

    updateLe32(blake2b, cast(uint) password_len);
    if (password_len)
        blake2b.update(password, password_len);

    updateLe32(blake2b, cast(uint) salt_len);
    if (salt_len)
        blake2b.update(salt, salt_len);

    updateLe32(blake2b, cast(uint) key_len);
    if (key_len)
        blake2b.update(key, key_len);

    updateLe32(blake2b, cast(uint) ad_len);
    if (ad_len)
        blake2b.update(ad, ad_len);

    blake2b.flushInto(H0.ptr);
}

void extractKey(ubyte* output, size_t output_len,
                const ref SecureVector!ulong B, size_t memory, size_t threads)
{
    const size_t lanes = memory / threads;
    ulong[128] sum;
    sum[] = 0;

    foreach (lane; 0 .. threads)
    {
        const size_t start = 128 * (lane * lanes + lanes - 1);
        const size_t end = 128 * (lane * lanes + lanes);
        foreach (j; start .. end)
            sum[j % 128] ^= B[j];
    }

    if (output_len <= 64)
    {
        Unique!HashFunction blake2b = retrieveHash("BLAKE2b(" ~ to!string(output_len * 8) ~ ")").clone();
        updateLe32(*blake2b, cast(uint) output_len);
        foreach (i; 0 .. 128)
        {
            ubyte[8] w;
            storeLittleEndian(sum[i], w.ptr);
            blake2b.update(w.ptr, 8);
        }
        blake2b.flushInto(output);
    }
    else
    {
        SecureVector!ubyte T = SecureVector!ubyte(64);
        Unique!HashFunction blake2b = retrieveHash("BLAKE2b(512)").clone();
        updateLe32(*blake2b, cast(uint) output_len);
        foreach (i; 0 .. 128)
        {
            ubyte[8] w;
            storeLittleEndian(sum[i], w.ptr);
            blake2b.update(w.ptr, 8);
        }
        blake2b.flushInto(T.ptr);

        while (output_len > 64)
        {
            output[0 .. 32] = T.ptr[0 .. 32];
            output_len -= 32;
            output += 32;

            if (output_len > 64)
            {
                blake2b.update(T);
                blake2b.flushInto(T.ptr);
            }
        }

        if (output_len == 64)
        {
            blake2b.update(T);
            blake2b.flushInto(output);
        }
        else
        {
            Unique!HashFunction blake2b_f = retrieveHash("BLAKE2b(" ~ to!string(output_len * 8) ~ ")").clone();
            blake2b_f.update(T);
            blake2b_f.flushInto(output);
        }
    }
}

void initBlocks(ref SecureVector!ulong B, HashFunction blake2b,
                ref const ubyte[64] H0, size_t memory, size_t threads)
{
    foreach (i; 0 .. threads)
    {
        const size_t B_off = i * (memory / threads);
        foreach (j; 0 .. 2)
        {
            ubyte[64] T;
            updateLe32(blake2b, 1024);
            blake2b.update(H0.ptr, 64);
            updateLe32(blake2b, cast(uint) j);
            updateLe32(blake2b, cast(uint) i);
            blake2b.flushInto(T.ptr);

            foreach (k; 0 .. 30)
            {
                loadLittleEndian(B.ptr + 128 * (B_off + j) + 4 * k, T.ptr, 32 / 8);
                blake2b.update(T.ptr, 64);
                blake2b.flushInto(T.ptr);
            }
            loadLittleEndian(B.ptr + 128 * (B_off + j) + 4 * 30, T.ptr, 64 / 8);
        }
    }
}

void blamkaG(ref ulong A, ref ulong B, ref ulong C, ref ulong D)
{
    A += B + (cast(ulong) 2 * cast(uint) A) * cast(uint) B;
    D = rotateRight(A ^ D, 32);

    C += D + (cast(ulong) 2 * cast(uint) C) * cast(uint) D;
    B = rotateRight(B ^ C, 24);

    A += B + (cast(ulong) 2 * cast(uint) A) * cast(uint) B;
    D = rotateRight(A ^ D, 16);

    C += D + (cast(ulong) 2 * cast(uint) C) * cast(uint) D;
    B = rotateRight(B ^ C, 63);
}

void blamka(ulong* N, ulong* T)
{
    T[0 .. 128] = N[0 .. 128];

    for (size_t i = 0; i != 128; i += 16)
    {
        blamkaG(T[i + 0], T[i + 4], T[i + 8], T[i + 12]);
        blamkaG(T[i + 1], T[i + 5], T[i + 9], T[i + 13]);
        blamkaG(T[i + 2], T[i + 6], T[i + 10], T[i + 14]);
        blamkaG(T[i + 3], T[i + 7], T[i + 11], T[i + 15]);

        blamkaG(T[i + 0], T[i + 5], T[i + 10], T[i + 15]);
        blamkaG(T[i + 1], T[i + 6], T[i + 11], T[i + 12]);
        blamkaG(T[i + 2], T[i + 7], T[i + 8], T[i + 13]);
        blamkaG(T[i + 3], T[i + 4], T[i + 9], T[i + 14]);
    }

    for (size_t i = 0; i != 128 / 8; i += 2)
    {
        blamkaG(T[i + 0], T[i + 32], T[i + 64], T[i + 96]);
        blamkaG(T[i + 1], T[i + 33], T[i + 65], T[i + 97]);
        blamkaG(T[i + 16], T[i + 48], T[i + 80], T[i + 112]);
        blamkaG(T[i + 17], T[i + 49], T[i + 81], T[i + 113]);

        blamkaG(T[i + 0], T[i + 33], T[i + 80], T[i + 113]);
        blamkaG(T[i + 1], T[i + 48], T[i + 81], T[i + 96]);
        blamkaG(T[i + 16], T[i + 49], T[i + 64], T[i + 97]);
        blamkaG(T[i + 17], T[i + 32], T[i + 65], T[i + 112]);
    }

    foreach (i; 0 .. 128)
        N[i] ^= T[i];
}

void gen2iAddresses(ulong* T, ulong* B,
                    size_t n, size_t lane, size_t slice,
                    size_t memory, size_t time, size_t mode, size_t cnt)
{
    B[0 .. 128] = 0;
    B[0] = n;
    B[1] = lane;
    B[2] = slice;
    B[3] = memory;
    B[4] = time;
    B[5] = mode;
    B[6] = cnt;
    foreach (r; 0 .. 2)
        blamka(B, T);
}

size_t modThreads(uint random, size_t threads)
{
    if (threads && (threads & (threads - 1)) == 0)
        return random & (threads - 1);
    return random % threads;
}

size_t modLanes(ulong alpha, size_t lanes)
{
    if (lanes && (lanes & (lanes - 1)) == 0)
        return cast(size_t)(alpha & (lanes - 1));
    return cast(size_t)(alpha % lanes);
}

uint indexAlpha(ulong random, size_t lanes, size_t segments, size_t threads,
                size_t n, size_t slice, size_t lane, size_t index)
{
    size_t ref_lane = modThreads(cast(uint)(random >> 32), threads);
    if (n == 0 && slice == 0)
        ref_lane = lane;

    size_t m = 3 * segments;
    size_t s = ((slice + 1) % 4) * segments;

    if (lane == ref_lane)
        m += index;

    if (n == 0)
    {
        m = slice * segments;
        s = 0;
        if (slice == 0 || lane == ref_lane)
            m += index;
    }

    if (index == 0 || lane == ref_lane)
        m -= 1;

    ulong p = cast(uint) random;
    p = (p * p) >> 32;
    p = (p * m) >> 32;

    return cast(uint)(ref_lane * lanes + modLanes(s + m - (p + 1), lanes));
}

void processBlock(ref SecureVector!ulong B,
                  size_t n, size_t slice, size_t lane,
                  size_t lanes, size_t segments, size_t threads,
                  ubyte mode, size_t memory, size_t time)
{
    ulong[128] T;
    size_t index = 0;
    if (n == 0 && slice == 0)
        index = 2;

    const bool use_2i = mode == 1 || (mode == 2 && n == 0 && slice < ARGON2_SYNC_POINTS / 2);

    ulong[128] addresses;
    size_t address_counter = 1;

    if (use_2i)
        gen2iAddresses(T.ptr, addresses.ptr, n, lane, slice, memory, time, mode, address_counter);

    while (index < segments)
    {
        const size_t offset = lane * lanes + slice * segments + index;

        size_t prev = offset - 1;
        if (index == 0 && slice == 0)
            prev += lanes;

        if (use_2i && index > 0 && index % 128 == 0)
        {
            address_counter += 1;
            gen2iAddresses(T.ptr, addresses.ptr, n, lane, slice, memory, time, mode, address_counter);
        }

        const ulong random = use_2i ? addresses[index % 128] : B[128 * prev];
        const size_t new_offset = indexAlpha(random, lanes, segments, threads, n, slice, lane, index);

        ulong[128] N;
        foreach (i; 0 .. 128)
            N[i] = B[128 * prev + i] ^ B[128 * new_offset + i];

        blamka(N.ptr, T.ptr);

        foreach (i; 0 .. 128)
            B[128 * offset + i] ^= N[i];

        index += 1;
    }
}

void processBlocks(ref SecureVector!ulong B, size_t t, size_t memory, size_t threads, ubyte mode)
{
    const size_t lanes = memory / threads;
    const size_t segments = lanes / ARGON2_SYNC_POINTS;

    foreach (n; 0 .. t)
    {
        foreach (slice; 0 .. ARGON2_SYNC_POINTS)
        {
            foreach (lane; 0 .. threads)
                processBlock(B, n, slice, lane, lanes, segments, threads, mode, memory, t);
        }
    }
}

static if (BOTAN_HAS_TESTS && !SKIP_PBKDF_TEST) unittest
{
    import botan.test;
    import botan.codec.hex;
    import botan.libstate.global_state;
    import memutils.hashmap;
    import std.stdio : File;

    auto state = globalState();
    logDebug("Testing argon2.d ...");

    File vec = File("test_data/argon2.vec", "r");
    size_t fails = runTests(vec, "Algo", "Output", true,
        (ref HashMap!(string, string) m)
        {
            const string fam = m["Algo"];
            ubyte family = fam == "Argon2d" ? 0 : (fam == "Argon2i" ? 1 : 2);
            const size_t M = to!size_t(m["M"]);
            const size_t t = to!size_t(m["T"]);
            const size_t p = to!size_t(m["P"]);
            auto pass = hexDecode(m["Passphrase"]);
            auto salt = hexDecode(m["Salt"]);
            Vector!ubyte ad;
            Vector!ubyte secret;
            if (auto adp = "AD" in m)
                ad = hexDecode(*adp);
            if (auto secp = "Secret" in m)
                secret = hexDecode(*secp);
            const auto expected = hexDecode(m["Output"]);

            auto argon = new Argon2(family, M, t, p);
            SecureVector!ubyte got = SecureVector!ubyte(expected.length);
            argon.derive(got.ptr, got.length,
                         pass.ptr, pass.length,
                         salt.ptr, salt.length,
                         secret.length ? secret.ptr : null, secret.length,
                         ad.length ? ad.ptr : null, ad.length,
                         t);
            return hexEncode(got, false);
        });

    {
        Unique!PBKDF via_factory = getPbkdf("Argon2id(32,3,4)");
        if (via_factory.name != "Argon2id(32,3,4)")
            ++fails;
    }

    testReport("argon2", 0, fails);
}
