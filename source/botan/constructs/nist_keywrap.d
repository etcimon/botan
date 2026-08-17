/**
* NIST SP 800-38F key wrap (KW) and key wrap with padding (KWP)
*
* Copyright:
* (C) 2011,2017 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.constructs.nist_keywrap;

import botan.constants;
static if (BOTAN_HAS_NIST_KEYWRAP):

import botan.block.block_cipher;
import botan.utils.loadstor;
import botan.utils.exceptn;
import botan.utils.xor_buf;
import botan.utils.mem_ops;
import botan.utils.types;

private Vector!ubyte rawNistKeyWrap(const(ubyte)* input, size_t input_len,
                                    const BlockCipher bc, ulong icv)
{
    const size_t n = input_len / 8 + (input_len % 8 != 0 ? 1 : 0);
    SecureVector!ubyte R = SecureVector!ubyte(8 * (n + 1));
    SecureVector!ubyte A = SecureVector!ubyte(16);

    storeBigEndian(icv, A.ptr);
    copyMem(&R[8], input, input_len);

    foreach (size_t j; 0 .. 6)
    {
        foreach (size_t i; 1 .. n + 1)
        {
            const uint t = cast(uint)((n * j) + i);
            copyMem(&A[8], &R[8 * i], 8);
            (cast() bc).encrypt(A.ptr);
            copyMem(&R[8 * i], &A[8], 8);
            ubyte[4] t_buf;
            storeBigEndian(t, t_buf.ptr);
            xorBuf(&A[4], t_buf.ptr, 4);
        }
    }

    copyMem(R.ptr, A.ptr, 8);
    Vector!ubyte outbuf = Vector!ubyte(R.length);
    copyMem(outbuf.ptr, R.ptr, R.length);
    return outbuf.move();
}

private SecureVector!ubyte rawNistKeyUnwrap(const(ubyte)* input, size_t input_len,
                                            const BlockCipher bc, ref ulong icv_out)
{
    if (input_len < 16 || input_len % 8 != 0)
        throw new InvalidArgument("Bad input size for NIST key unwrap");

    const size_t n = (input_len - 8) / 8;
    SecureVector!ubyte R = SecureVector!ubyte(n * 8);
    SecureVector!ubyte A = SecureVector!ubyte(16);

    foreach (size_t i; 0 .. 8)
        A[i] = input[i];
    copyMem(R.ptr, input + 8, input_len - 8);

    foreach (size_t j; 0 .. 6)
    {
        for (size_t i = n; i != 0; --i)
        {
            const uint t = cast(uint)((5 - j) * n + i);
            ubyte[4] t_buf;
            storeBigEndian(t, t_buf.ptr);
            xorBuf(&A[4], t_buf.ptr, 4);
            copyMem(&A[8], &R[8 * (i - 1)], 8);
            (cast() bc).decrypt(A.ptr);
            copyMem(&R[8 * (i - 1)], &A[8], 8);
        }
    }

    icv_out = loadBigEndian!ulong(A.ptr, 0);
    return R;
}

/// RFC 3394 / NIST SP 800-38F KW. `input_len` must be a positive multiple of 8.
Vector!ubyte nistKeyWrap(const(ubyte)* input, size_t input_len, const BlockCipher bc)
{
    if (bc.blockSize() != 16)
        throw new InvalidArgument("NIST key wrap algorithm requires a 128-bit cipher");
    if (input_len == 0 || input_len % 8 != 0)
        throw new InvalidArgument("Bad input size for NIST key wrap");

    enum ulong ICV = 0xA6A6A6A6A6A6A6A6;
    if (input_len == 8)
    {
        Vector!ubyte block = Vector!ubyte(16);
        storeBigEndian(ICV, block.ptr);
        copyMem(block.ptr + 8, input, input_len);
        (cast() bc).encrypt(block.ptr);
        return block.move();
    }
    return rawNistKeyWrap(input, input_len, bc, ICV);
}

/// RFC 3394 / NIST SP 800-38F unwrap. Throws `IntegrityFailure` on ICV mismatch.
SecureVector!ubyte nistKeyUnwrap(const(ubyte)* input, size_t input_len, const BlockCipher bc)
{
    if (bc.blockSize() != 16)
        throw new InvalidArgument("NIST key wrap algorithm requires a 128-bit cipher");
    if (input_len < 16 || input_len % 8 != 0)
        throw new InvalidArgument("Bad input size for NIST key unwrap");

    enum ulong ICV = 0xA6A6A6A6A6A6A6A6;
    ulong icv_out = 0;
    SecureVector!ubyte R;

    if (input_len == 16)
    {
        SecureVector!ubyte block = SecureVector!ubyte(input[0 .. input_len]);
        (cast() bc).decrypt(block.ptr);
        icv_out = loadBigEndian!ulong(block.ptr, 0);
        R.resize(8);
        copyMem(R.ptr, block.ptr + 8, 8);
    }
    else
        R = rawNistKeyUnwrap(input, input_len, bc, icv_out);

    if (icv_out != ICV)
        throw new IntegrityFailure("NIST key unwrap failed");
    return R;
}

/// RFC 5649 / NIST SP 800-38F KWP. Input must be non-empty.
Vector!ubyte nistKeyWrapPadded(const(ubyte)* input, size_t input_len, const BlockCipher bc)
{
    if (bc.blockSize() != 16)
        throw new InvalidArgument("NIST key wrap algorithm requires a 128-bit cipher");
    if (input_len == 0)
        throw new InvalidArgument("NIST KWP cannot accept empty inputs");

    const ulong icv = 0xA65959A600000000 | cast(uint) input_len;
    if (input_len <= 8)
    {
        Vector!ubyte block = Vector!ubyte(16);
        storeBigEndian(icv, block.ptr);
        copyMem(block.ptr + 8, input, input_len);
        (cast() bc).encrypt(block.ptr);
        return block.move();
    }
    return rawNistKeyWrap(input, input_len, bc, icv);
}

/// RFC 5649 / NIST SP 800-38F KWP unwrap. Throws `IntegrityFailure` on bad padding/ICV.
SecureVector!ubyte nistKeyUnwrapPadded(const(ubyte)* input, size_t input_len, const BlockCipher bc)
{
    if (bc.blockSize() != 16)
        throw new InvalidArgument("NIST key wrap algorithm requires a 128-bit cipher");
    if (input_len < 16 || input_len % 8 != 0)
        throw new InvalidArgument("Bad input size for NIST key unwrap");

    ulong icv_out = 0;
    SecureVector!ubyte R;

    if (input_len == 16)
    {
        SecureVector!ubyte block = SecureVector!ubyte(input[0 .. input_len]);
        (cast() bc).decrypt(block.ptr);
        icv_out = loadBigEndian!ulong(block.ptr, 0);
        R.resize(8);
        copyMem(R.ptr, block.ptr + 8, 8);
    }
    else
        R = rawNistKeyUnwrap(input, input_len, bc, icv_out);

    const ulong expected_icv_max = 0xA65959A600000000 | cast(uint) R.length;
    const ulong padding = expected_icv_max - icv_out;
    if (padding > 7)
        throw new IntegrityFailure("NIST key unwrap failed");

    const ulong last_block = loadBigEndian!ulong(R.ptr + R.length - 8, 0);
    const ulong padding_mask = (1UL << (padding * 8)) - 1;
    if ((last_block & padding_mask) != 0)
        throw new IntegrityFailure("NIST key unwrap failed");

    R.resize(R.length - cast(size_t) padding);
    return R;
}

static if (BOTAN_TEST):

import botan.test;
import botan.libstate.global_state;
import botan.libstate.lookup;
import botan.codec.hex;
import botan.algo_base.symkey;
import memutils.hashmap;
import std.stdio : File;
import std.conv : to;

private Unique!BlockCipher keyedAes(const(ubyte)[] key)
{
    string name;
    if (key.length == 16) name = "AES-128";
    else if (key.length == 24) name = "AES-192";
    else if (key.length == 32) name = "AES-256";
    else throw new InvalidArgument("Bad KEK length for NIST keywrap");
    Unique!BlockCipher bc = retrieveBlockCipher(name).clone();
    bc.setKey(key.ptr, key.length);
    return bc;
}

static if (BOTAN_HAS_TESTS && !SKIP_NIST_KEYWRAP_TEST) unittest
{
    auto state = globalState();
    logDebug("Testing nist_keywrap.d ...");
    size_t fails = 0;

    File vec = File("test_data/keywrap/nist_key_wrap.vec", "r");
    fails += runTestsBb(vec, "Type", "Output", false,
        (ref HashMap!(string, string) m)
        {
            if (!("Output" in m) || !("Input" in m) || !("Key" in m))
                return 0;
            const string typ = m["Type"];
            auto input = hexDecode(m["Input"]);
            auto key = hexDecode(m["Key"]);
            auto exp = hexDecode(m["Output"]);
            auto bc = keyedAes(key[]);
            Vector!ubyte wrapped;
            if (typ == "KW")
                wrapped = nistKeyWrap(input.ptr, input.length, *bc);
            else if (typ == "KWP")
                wrapped = nistKeyWrapPadded(input.ptr, input.length, *bc);
            else
                return 1;
            if (wrapped[] != exp[])
                return 2;
            SecureVector!ubyte unwrapped;
            if (typ == "KW")
                unwrapped = nistKeyUnwrap(exp.ptr, exp.length, *bc);
            else
                unwrapped = nistKeyUnwrapPadded(exp.ptr, exp.length, *bc);
            if (unwrapped[] != input[])
                return 3;
            return 0;
        });

    File inv = File("test_data/keywrap/nist_key_wrap_invalid.vec", "r");
    fails += runTestsBb(inv, "Type", "Input", false,
        (ref HashMap!(string, string) m)
        {
            if (!("Input" in m) || !("Key" in m))
                return 0;
            const string typ = m["Type"];
            auto input = hexDecode(m["Input"]);
            auto key = hexDecode(m["Key"]);
            auto bc = keyedAes(key[]);
            try
            {
                if (typ == "KW")
                    nistKeyUnwrap(input.ptr, input.length, *bc);
                else if (typ == "KWP")
                    nistKeyUnwrapPadded(input.ptr, input.length, *bc);
                else
                    return 1;
                return 2;
            }
            catch (IntegrityFailure)
            {
                return 0;
            }
        });

    fails += checkMemutilsRepeat("nist_kw", {
        ubyte[16] kek, pt = 1;
        auto bc = keyedAes(kek[]);
        auto wrapped = nistKeyWrap(pt.ptr, pt.length, *bc);
        auto unwrapped = nistKeyUnwrap(wrapped.ptr, wrapped.length, *bc);
        if (unwrapped.length != pt.length)
            throw new Exception("kw leak probe");
    });

    testReport("nist_keywrap", 0, fails);
    assert(fails == 0);
}
