/**
* Scrypt key derivation function (RFC 7914)
*
* Copyright:
* (C) 2018 Jack Lloyd
* (C) 2018 Ribose Inc
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pbkdf.scrypt;

import botan.constants;
static if (BOTAN_HAS_SCRYPT && BOTAN_HAS_PBKDF2):

import botan.pbkdf.pbkdf;
import botan.libstate.lookup;
import botan.utils.loadstor;
import botan.utils.rotate;
import botan.utils.xor_buf;
import botan.utils.mem_ops;
import botan.utils.exceptn;
import botan.utils.types;
import botan.algo_base.symkey;
import std.datetime;
import std.conv : to;
import std.format : format;

enum size_t SCRYPT_MAX_N = 4194304;
enum size_t SCRYPT_MAX_MEMORY = (size_t.sizeof == 4)
    ? (2UL * 1024 * 1024 * 1024)
    : (8UL * 1024 * 1024 * 1024);

/**
* Scrypt (RFC 7914) as a PBKDF.
*
* SCAN: "Scrypt" or "Scrypt(N,r,p)". Defaults N=32768, r=8, p=1.
* deriveKey's iteration argument is reported back; parameters come from SCAN.
*/
final class Scrypt : PBKDF
{
public:
    /**
    * Params:
    *  N = CPU/memory cost (power of two)
    *  r = block size
    *  p = parallelism
    */
    this(size_t N, size_t r, size_t p)
    {
        if (N < 2 || (N & (N - 1)) != 0 || N > SCRYPT_MAX_N)
            throw new InvalidArgument("Scrypt N parameter must be a power of 2");
        if (p == 0 || p > 1024)
            throw new InvalidArgument("Invalid or unsupported scrypt p");
        if (r == 0 || r > 256)
            throw new InvalidArgument("Invalid or unsupported scrypt r");

        const size_t mem = scryptMemoryUsage(N, r, p);
        if (mem == 0 || mem > SCRYPT_MAX_MEMORY)
            throw new InvalidArgument("Scrypt parameters exceed maximum allowed memory limit");

        m_N = N;
        m_r = r;
        m_p = p;
    }

    override @property string name() const
    {
        return "Scrypt(" ~ to!string(m_N) ~ "," ~ to!string(m_r) ~ "," ~ to!string(m_p) ~ ")";
    }

    override PBKDF clone() const
    {
        return new Scrypt(m_N, m_r, m_p);
    }

    @property size_t N() const { return m_N; }
    @property size_t r() const { return m_r; }
    @property size_t p() const { return m_p; }

    void derive(ubyte* output, size_t output_len,
                const(ubyte)* password, size_t password_len,
                const(ubyte)* salt, size_t salt_len) const
    {
        if (output_len == 0)
            return;

        const size_t S = 128 * m_r;
        SecureVector!ubyte B = SecureVector!ubyte(m_p * S);
        SecureVector!ubyte V = SecureVector!ubyte((m_N + 1) * S);

        Unique!PBKDF pbkdf = getPbkdf("PBKDF2(SHA-256)");
        auto first = pbkdf.deriveKey(B.length,
                                     cast(string) password[0 .. password_len],
                                     salt, salt_len, 1);
        auto first_bits = first.bitsOf();
        B[] = first_bits[];

        foreach (i; 0 .. m_p)
            scryptROMmix(m_r, m_N, &B[128 * m_r * i], V);

        auto last = pbkdf.deriveKey(output_len,
                                    cast(string) password[0 .. password_len],
                                    B.ptr, B.length, 1);
        auto last_bits = last.bitsOf();
        output[0 .. output_len] = last_bits.ptr[0 .. output_len];
    }

    override Pair!(size_t, OctetString)
        keyDerivation(size_t output_len,
                      in string passphrase,
                      const(ubyte)* salt, size_t salt_len,
                      size_t iterations,
                      Duration) const
    {
        SecureVector!ubyte outbuf = SecureVector!ubyte(output_len);
        derive(outbuf.ptr, output_len,
               cast(const(ubyte)*) passphrase.ptr, passphrase.length,
               salt, salt_len);
        size_t reported = iterations ? iterations : m_N;
        return makePair(reported, OctetString(outbuf));
    }

private:
    size_t m_N, m_r, m_p;
}

/// 0 if the product overflows.
size_t scryptMemoryUsage(size_t N, size_t r, size_t p)
{
    if (r == 0)
        return 0;
    if (N > size_t.max - p)
        return 0;
    const size_t blocks = N + p;
    if (r > size_t.max / 128)
        return 0;
    const size_t block_size = 128 * r;
    if (blocks > 0 && block_size > size_t.max / blocks)
        return 0;
    return block_size * blocks;
}

private:

void salsa20_8(ubyte* output, const uint* input)
{
    uint x00 = input[0], x01 = input[1], x02 = input[2], x03 = input[3];
    uint x04 = input[4], x05 = input[5], x06 = input[6], x07 = input[7];
    uint x08 = input[8], x09 = input[9], x10 = input[10], x11 = input[11];
    uint x12 = input[12], x13 = input[13], x14 = input[14], x15 = input[15];

    foreach (i; 0 .. 4)
    {
        mixin(SALSA20_QR!(x00, x04, x08, x12) ~
              SALSA20_QR!(x05, x09, x13, x01) ~
              SALSA20_QR!(x10, x14, x02, x06) ~
              SALSA20_QR!(x15, x03, x07, x11) ~
              SALSA20_QR!(x00, x01, x02, x03) ~
              SALSA20_QR!(x05, x06, x07, x04) ~
              SALSA20_QR!(x10, x11, x08, x09) ~
              SALSA20_QR!(x15, x12, x13, x14));
    }

    storeLittleEndian(x00 + input[0], output + 4 * 0);
    storeLittleEndian(x01 + input[1], output + 4 * 1);
    storeLittleEndian(x02 + input[2], output + 4 * 2);
    storeLittleEndian(x03 + input[3], output + 4 * 3);
    storeLittleEndian(x04 + input[4], output + 4 * 4);
    storeLittleEndian(x05 + input[5], output + 4 * 5);
    storeLittleEndian(x06 + input[6], output + 4 * 6);
    storeLittleEndian(x07 + input[7], output + 4 * 7);
    storeLittleEndian(x08 + input[8], output + 4 * 8);
    storeLittleEndian(x09 + input[9], output + 4 * 9);
    storeLittleEndian(x10 + input[10], output + 4 * 10);
    storeLittleEndian(x11 + input[11], output + 4 * 11);
    storeLittleEndian(x12 + input[12], output + 4 * 12);
    storeLittleEndian(x13 + input[13], output + 4 * 13);
    storeLittleEndian(x14 + input[14], output + 4 * 14);
    storeLittleEndian(x15 + input[15], output + 4 * 15);
}

enum string SALSA20_QR(alias _x1, alias _x2, alias _x3, alias _x4) = q{
    %2$s ^= rotateLeft(%1$s + %4$s,  7);
    %3$s ^= rotateLeft(%2$s + %1$s,  9);
    %4$s ^= rotateLeft(%3$s + %2$s, 13);
    %1$s ^= rotateLeft(%4$s + %3$s, 18);
}.format(__traits(identifier, _x1), __traits(identifier, _x2),
         __traits(identifier, _x3), __traits(identifier, _x4));

void scryptBlockMix(size_t r, ubyte* B, ubyte* Y)
{
    uint[16] B32;
    ubyte[64] X;
    copyMem(X.ptr, &B[(2 * r - 1) * 64], 64);

    foreach (i; 0 .. 2 * r)
    {
        xorBuf(X.ptr, &B[64 * i], 64);
        loadLittleEndian(B32.ptr, X.ptr, 16);
        salsa20_8(X.ptr, B32.ptr);
        copyMem(&Y[64 * i], X.ptr, 64);
    }

    foreach (i; 0 .. r)
        copyMem(&B[i * 64], &Y[(i * 2) * 64], 64);
    foreach (i; 0 .. r)
        copyMem(&B[(i + r) * 64], &Y[(i * 2 + 1) * 64], 64);
}

void scryptROMmix(size_t r, size_t N, ubyte* B, ref SecureVector!ubyte V)
{
    const size_t S = 128 * r;
    foreach (i; 0 .. N)
    {
        copyMem(&V[S * i], B, S);
        scryptBlockMix(r, B, &V[N * S]);
    }
    foreach (i; 0 .. N)
    {
        const size_t j = loadLittleEndian!uint(&B[(2 * r - 1) * 64], 0) & (N - 1);
        xorBuf(B, &V[j * S], S);
        scryptBlockMix(r, B, &V[N * S]);
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
    logDebug("Testing scrypt.d ...");

    size_t fails = 0;
    size_t ran = 0;

    File vec = File("test_data/scrypt.vec", "r");
    fails += runTests(vec, "Algo", "Output", true,
        (ref HashMap!(string, string) m)
        {
            const size_t N = to!size_t(m["N"]);
            const size_t r = to!size_t(m["R"]);
            const size_t p = to!size_t(m["P"]);
            const string pass = ("Passphrase" in m) ? m["Passphrase"] : "";
            Vector!ubyte salt;
            if (auto sp = "Salt" in m)
            {
                if ((*sp).length)
                    salt = hexDecode(*sp);
            }
            const auto expected = hexDecode(m["Output"]);

            auto scrypt = new Scrypt(N, r, p);
            SecureVector!ubyte got = SecureVector!ubyte(expected.length);
            scrypt.derive(got.ptr, got.length,
                          cast(const(ubyte)*) pass.ptr, pass.length,
                          salt.ptr, salt.length);
            import std.algorithm : any;
            const bool lower = m["Output"].any!(c => c >= 'a' && c <= 'f');
            return hexEncode(got, !lower);
        });

    void expectThrow(string label, void delegate() dg)
    {
        ++ran;
        bool threw = false;
        try
            dg();
        catch (InvalidArgument)
            threw = true;
        if (!threw)
        {
            ++fails;
            logError("Scrypt: expected throw: " ~ label);
        }
    }

    expectThrow("N not power of 2", { auto x = new Scrypt(3, 8, 1); });
    expectThrow("N too small", { auto x = new Scrypt(1, 8, 1); });
    expectThrow("p zero", { auto x = new Scrypt(16, 8, 0); });
    expectThrow("r zero", { auto x = new Scrypt(16, 0, 1); });
    expectThrow("p too large", { auto x = new Scrypt(16, 8, 1025); });
    expectThrow("memory overflow", { auto x = new Scrypt(SCRYPT_MAX_N, 256, 1); });

    {
        Unique!PBKDF via = getPbkdf("Scrypt(16,1,1)");
        ++ran;
        if (via.name != "Scrypt(16,1,1)")
        {
            ++fails;
            logError("Scrypt factory name " ~ via.name);
        }
        auto empty_salt = Vector!ubyte();
        auto key = via.deriveKey(64, "", empty_salt, 1);
        ++ran;
        if (hexEncode(key.bitsOf()) !=
            "77D6576238657B203B19CA42C18A0497F16B4844E3074AE8DFDFFA3FEDE21442FCD0069DED0948F8326A753A0FC81F17E8D3E0FB2E0D3628CF35E20C38D18906")
        {
            ++fails;
            logError("Scrypt factory RFC empty-password vector mismatch");
        }
    }

    testReport("scrypt", ran, fails);
    assert(fails == 0);
}
