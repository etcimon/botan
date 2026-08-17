/**
* expand_message_xmd (RFC 9380 §5.3.1)
*
* Copyright:
* (C) 2019,2020,2021,2024 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.kdf.xmd;

import botan.constants;
static if (BOTAN_HAS_XMD):

import botan.hash.hash;
import botan.utils.exceptn;
import botan.utils.mem_ops;
import botan.utils.types;
import botan.utils.xor_buf;
import std.algorithm : min;

/**
* RFC 9380 expand_message_xmd. Internal helper for hash-to-curve;
* not a `getKdf` SCAN name. `hash` must be in its initial state.
* `domain` is the DST and must be non-empty and at most 255 bytes.
*/
void expandMessageXmd(HashFunction hash, ubyte* output, size_t output_len,
                      const(ubyte)* input, size_t input_len,
                      const(ubyte)* domain, size_t domain_len)
{
    if (domain_len > 0xFF)
        throw new InvalidArgument("XMD does not currently implement oversize DST handling");
    if (domain_len == 0)
        throw new InvalidArgument("expand_message_xmd requires a non-empty domain separation tag");

    const size_t block_size = hash.hashBlockSize();
    if (block_size == 0)
        throw new InvalidArgument("expand_message_xmd cannot be used with " ~ hash.name);
    const size_t hash_len = hash.outputLength();
    if (hash_len > block_size)
        throw new InvalidArgument("expand_message_xmd cannot be used with " ~ hash.name);
    if (output_len > 255 * hash_len || output_len > 0xFFFF)
        throw new InvalidArgument("expand_message_xmd requested output length too long");

    const ubyte dst_len = cast(ubyte) domain_len;

    // b_0 = H(Z_pad || msg || l_i_b_str || 0x00 || DST_prime)
    {
        auto zpad = SecureVector!ubyte(block_size);
        hash.update(zpad.ptr, zpad.length);
    }
    if (input_len)
        hash.update(input, input_len);
    hash.updateBigEndian(cast(ushort) output_len);
    hash.update(cast(ubyte) 0x00);
    hash.update(domain, domain_len);
    hash.update(dst_len);
    auto b0 = hash.finished();

    // b_1 = H(b_0 || 0x01 || DST_prime)
    hash.update(b0.ptr, b0.length);
    hash.update(cast(ubyte) 0x01);
    hash.update(domain, domain_len);
    hash.update(dst_len);
    auto bi = hash.finished();

    ubyte cnt = 2;
    size_t remaining = output_len;
    ubyte* outp = output;
    for (;;)
    {
        const size_t produced = min(remaining, hash_len);
        copyMem(outp, bi.ptr, produced);
        outp += produced;
        remaining -= produced;
        if (remaining == 0)
            break;

        xorBuf(bi.ptr, b0.ptr, bi.length);
        hash.update(bi.ptr, bi.length);
        hash.update(cnt);
        hash.update(domain, domain_len);
        hash.update(dst_len);
        auto next = hash.finished();
        foreach (i; 0 .. bi.length)
            bi[i] = next[i];
        ++cnt;
    }
}

static if (BOTAN_TEST):

import botan.test;
import botan.libstate.libstate;
import botan.libstate.lookup;
import botan.codec.hex;
import memutils.hashmap;
import core.atomic;

private shared size_t total_tests;

static if (BOTAN_HAS_TESTS && !SKIP_KDF_TEST) unittest
{
    logDebug("Testing xmd.d ...");
    globalState();
    auto test = delegate(string input)
    {
        File vec = File(input, "r");
        return runTestsBb(vec, "Hash", "Output", false,
            (ref HashMap!(string, string) m)
            {
                atomicOp!"+="(total_tests, cast(size_t)1);
                const string hash_name = m["Hash"];
                string domain;
                if (auto p = "Domain" in m)
                    domain = *p;
                string msg;
                if (auto p = "Input" in m)
                    msg = *p;
                auto expected = hexDecode(m["Output"]);

                Unique!HashFunction hash = retrieveHash(hash_name).clone();
                auto got = Vector!ubyte(expected.length);
                expandMessageXmd(hash, got.ptr, got.length,
                                 cast(const(ubyte)*) msg.ptr, msg.length,
                                 cast(const(ubyte)*) domain.ptr, domain.length);
                if (got.length != expected.length || !sameMem(got.ptr, expected.ptr, expected.length))
                {
                    logError("XMD " ~ hash_name ~ " got " ~ hexEncode(got) ~ " != " ~ hexEncode(expected));
                    return 1;
                }
                return 0;
            });
    };

    size_t fails = runTestsInDir("test_data/xmd", test);
    testReport("xmd", total_tests, fails);
}
