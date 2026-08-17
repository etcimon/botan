/**
* Extendable Output Function
*
* Copyright:
* (C) 2023 Jack Lloyd
* (C) 2023 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.xof.xof;

import botan.constants;
static if (BOTAN_HAS_SHAKE_XOF || BOTAN_HAS_CSHAKE_XOF || BOTAN_HAS_ASCON_XOF128 || BOTAN_HAS_AES_CTR_XOF):

import botan.algo_base.key_spec;
import botan.algo_base.scan_token;
import botan.utils.exceptn;
import botan.utils.types;
import memutils.vector;
import std.conv : to;

static if (BOTAN_HAS_SHAKE_XOF) import botan.xof.shake_xof;
static if (BOTAN_HAS_CSHAKE_XOF) import botan.xof.cshake_xof;
static if (BOTAN_HAS_ASCON_XOF128) import botan.xof.ascon_xof128;
static if (BOTAN_HAS_AES_CTR_XOF) import botan.xof.aes_ctr_xof;

/**
* Absorb-then-squeeze XOF. `update` is illegal after the first `output`.
* SCAN via `getXof`: "SHAKE-128", "SHAKE-256" (no args), "Ascon-XOF128".
* cSHAKE is constructed with a function name and is not a public SCAN alias.
*/
class XOF
{
public:
    abstract @property string name() const;
    abstract @property size_t blockSize() const;
    abstract bool acceptsInput() const;
    abstract XOF copyState() const;
    abstract XOF newObject() const;

    bool validSaltLength(size_t salt_len) const { return salt_len == 0; }
    KeyLengthSpecification keySpec() const { return KeyLengthSpecification(0); }

    final void clear()
    {
        m_started = false;
        reset();
    }

    final void start(const(ubyte)* salt = null, size_t salt_len = 0,
                     const(ubyte)* key = null, size_t key_len = 0)
    {
        if (!keySpec().validKeylength(key_len))
            throw new InvalidKeyLength(name, key_len);
        if (!validSaltLength(salt_len))
            throw new InvalidArgument(name ~ " cannot accept a salt length of " ~ to!string(salt_len));
        m_started = true;
        startMsg(salt, salt_len, key, key_len);
    }

    final void start(const(ubyte)[] salt, const(ubyte)[] key = null)
    {
        start(salt.ptr, salt.length, key.ptr, key.length);
    }

    final void update(const(ubyte)* input, size_t length)
    {
        if (!m_started)
            start();
        addData(input, length);
    }

    final void update(const(ubyte)[] input) { update(input.ptr, input.length); }

    final void output(ubyte* dest, size_t length) { generateBytes(dest, length); }

    final void output(ubyte[] dest) { generateBytes(dest.ptr, dest.length); }

    final Vector!ubyte output(size_t bytes)
    {
        auto dest = Vector!ubyte(bytes);
        generateBytes(dest.ptr, bytes);
        return dest.move();
    }

    final ubyte outputNextByte()
    {
        ubyte b;
        generateBytes(&b, 1);
        return b;
    }

protected:
    void startMsg(const(ubyte)*, size_t, const(ubyte)*, size_t) {}

    abstract void addData(const(ubyte)* input, size_t length);
    abstract void generateBytes(ubyte* output, size_t length);
    abstract void reset();

    final void copyStartedTo(XOF dst) const { dst.m_started = m_started; }

private:
    bool m_started;
}

/**
* Create an XOF from a SCAN name. `function_name` is only used by cSHAKE.
* Returns null if the algo/version is not compiled in.
*/
XOF getXof(in string algo_spec, const(ubyte)[] function_name = null)
{
    auto req = SCANToken(algo_spec);

    static if (BOTAN_HAS_SHAKE_XOF)
    {
        if (req.algoName == "SHAKE-128" && req.argCount() == 0)
            return new SHAKE_128_XOF;
        if (req.algoName == "SHAKE-256" && req.argCount() == 0)
            return new SHAKE_256_XOF;
    }

    static if (BOTAN_HAS_ASCON_XOF128)
    {
        if (req.algoName == "Ascon-XOF128" && req.argCount() == 0)
            return new AsconXOF128;
    }

    static if (BOTAN_HAS_CSHAKE_XOF)
    {
        if (req.algoName == "cSHAKE-128")
            return new CSHAKE_128_XOF(function_name);
        if (req.algoName == "cSHAKE-256")
            return new CSHAKE_256_XOF(function_name);
    }

    static if (BOTAN_HAS_AES_CTR_XOF)
    {
        if (algo_spec == "CTR-BE(AES-256)" ||
            (req.algoName == "CTR-BE" && req.argCount() == 1 && req.arg(0) == "AES-256"))
            return new AES_256_CTR_XOF;
    }

    return null;
}

static if (BOTAN_TEST):

import botan.test;
import botan.libstate.libstate;
import botan.codec.hex;
import botan.utils.mem_ops;
import botan.utils.types;
import memutils.hashmap;
import core.atomic;
import std.algorithm : min;

private shared size_t total_tests;

private string optHex(ref HashMap!(string, string) m, string key)
{
    if (auto p = key in m)
        return *p;
    return "";
}

private size_t xofTest(string algo, string in_hex, string out_hex,
                       string salt_hex, string key_hex, string name_hex)
{
    size_t fails = 0;
    auto name = hexDecode(name_hex);
    Unique!XOF proto = getXof(algo, name[]);
    atomicOp!"+="(total_tests, cast(size_t)1);
    if (!proto)
    {
        logTrace("Unknown XOF " ~ algo);
        return 0;
    }

    auto input = hexDecode(in_hex);
    auto expected = hexDecode(out_hex);
    auto salt = hexDecode(salt_hex);
    auto key = hexDecode(key_hex);

    size_t check(string tag, const(ubyte)* got, size_t n)
    {
        atomicOp!"+="(total_tests, cast(size_t)1);
        if (n != expected.length || !sameMem(got, expected.ptr, n))
        {
            logError(algo ~ " " ~ tag ~ " got " ~
                     hexEncode(got, n) ~ " != " ~ out_hex);
            return 1;
        }
        return 0;
    }

    proto.start(salt[], key[]);
    proto.update(input[]);
    {
        auto got = proto.output(expected.length);
        fails += check("bulk", got.ptr, got.length);
    }
    if (proto.acceptsInput())
    {
        logError(algo ~ " still accepts input after output");
        ++fails;
    }

    proto.clear();
    proto.start(salt[], key[]);
    proto.update(input[]);
    {
        auto junk = Vector!ubyte(expected.length);
        foreach (i; 0 .. junk.length)
            junk[i] = cast(ubyte)(0xA5 ^ i);
        proto.output(junk.ptr, junk.length);
        fails += check("overwrite", junk.ptr, junk.length);
    }

    if (salt.length == 0 && key.length == 0)
    {
        proto.clear();
        proto.update(input[]);
        auto got = proto.output(expected.length);
        fails += check("no-start", got.ptr, got.length);
    }

    proto.clear();
    proto.start(salt[], key[]);
    proto.update(input[]);
    {
        auto got = Vector!ubyte(expected.length);
        foreach (i; 0 .. got.length)
            got[i] = proto.outputNextByte();
        fails += check("bytewise", got.ptr, got.length);
    }

    void asBlocks(string id, size_t bs)
    {
        Unique!XOF x = proto.newObject();
        x.start(salt[], key[]);
        size_t off = 0;
        while (off < input.length)
        {
            const size_t n = min(bs, input.length - off);
            x.update(input.ptr + off, n);
            off += n;
        }
        auto got = Vector!ubyte(expected.length);
        off = 0;
        while (off < got.length)
        {
            const size_t n = min(bs, got.length - off);
            x.output(got.ptr + off, n);
            off += n;
        }
        fails += check("blocks" ~ id, got.ptr, got.length);
    }

    const size_t bs = proto.blockSize();
    if (bs > 1)
        asBlocks("-1", bs - 1);
    asBlocks("+0", bs);
    asBlocks("+1", bs + 1);

    proto.clear();
    proto.start(salt[], key[]);
    const size_t mid = input.length / 2;
    proto.update(input.ptr, mid);
    try
    {
        Unique!XOF cp = proto.copyState();
        proto.update(input.ptr + mid, input.length - mid);
        cp.update(input.ptr + mid, input.length - mid);
        {
            auto a = proto.output(expected.length);
            auto b1 = cp.output(expected.length / 2);
            Unique!XOF cp2 = cp.copyState();
            auto b2a = cp.output(expected.length - expected.length / 2);
            auto b2b = cp2.output(expected.length - expected.length / 2);
            fails += check("copy", a.ptr, a.length);
            auto concat_a = Vector!ubyte(expected.length);
            foreach (i; 0 .. b1.length)
                concat_a[i] = b1[i];
            foreach (i; 0 .. b2a.length)
                concat_a[b1.length + i] = b2a[i];
            fails += check("copy-A", concat_a.ptr, concat_a.length);
            auto concat_b = Vector!ubyte(expected.length);
            foreach (i; 0 .. b1.length)
                concat_b[i] = b1[i];
            foreach (i; 0 .. b2b.length)
                concat_b[b1.length + i] = b2b[i];
            fails += check("copy-B", concat_b.ptr, concat_b.length);
            if (cp2.acceptsInput())
            {
                logError(algo ~ " copied XOF accepted input after output");
                ++fails;
            }
        }
    }
    catch (InvalidState)
    {
        // AES-CTR XOF does not implement copy_state (C++ Not_Implemented).
    }

    return fails;
}

static if (BOTAN_HAS_TESTS && !SKIP_XOF_TEST) unittest
{
    logDebug("Testing xof.d ...");
    globalState();
    auto test = delegate(string input)
    {
        File vec = File(input, "r");
        return runTestsBb(vec, "XOF", "Out", true,
            (ref HashMap!(string, string) m) {
                return xofTest(m["XOF"], optHex(m, "In"), m["Out"],
                               optHex(m, "Salt"), optHex(m, "Key"), optHex(m, "Name"));
            });
    };

    size_t fails = runTestsInDir("test_data/xof", test);

    static if (BOTAN_HAS_CSHAKE_XOF)
    {
        foreach (algo; ["cSHAKE-128", "cSHAKE-256"])
        {
            Unique!XOF x = getXof(algo);
            atomicOp!"+="(total_tests, cast(size_t)1);
            if (!x.validSaltLength(0))
            {}
            else
            {
                logError(algo ~ " empty name accepted empty salt");
                ++fails;
            }
            atomicOp!"+="(total_tests, cast(size_t)1);
            if (!x.validSaltLength(1))
            {
                logError(algo ~ " empty name rejected 1-byte salt");
                ++fails;
            }
            atomicOp!"+="(total_tests, cast(size_t)1);
            bool threw = false;
            try { x.start(); } catch (Exception) { threw = true; }
            if (!threw)
            {
                logError(algo ~ " empty name start() did not throw");
                ++fails;
            }
        }
    }

    static if (BOTAN_HAS_AES_CTR_XOF)
    {
        {
            Unique!XOF aes = new AES_256_CTR_XOF;
            atomicOp!"+="(total_tests, cast(size_t)3);
            bool threw;
            threw = false;
            try { aes.start(); } catch (Exception) { threw = true; }
            if (!threw)
            {
                logError("AES-256/CTR XOF empty key did not throw");
                ++fails;
            }
            threw = false;
            try { ubyte[33] k; aes.start(cast(const(ubyte)[])null, k[]); } catch (Exception) { threw = true; }
            if (!threw)
            {
                logError("AES-256/CTR XOF 33-byte key did not throw");
                ++fails;
            }
            threw = false;
            try
            {
                ubyte[32] k;
                ubyte[17] iv;
                aes.start(iv[], k[]);
            }
            catch (Exception) { threw = true; }
            if (!threw)
            {
                logError("AES-256/CTR XOF 17-byte IV did not throw");
                ++fails;
            }
        }
    }

    static if (BOTAN_HAS_SHAKE_XOF)
    {
        fails += checkMemutilsRepeat("xof SHAKE-128", {
            Unique!XOF x = getXof("SHAKE-128");
            x.update(cast(const(ubyte)[])"abc");
            ubyte[16] outp;
            x.output(outp[]);
        });
    }

    testReport("xof", total_tests, fails);
}
