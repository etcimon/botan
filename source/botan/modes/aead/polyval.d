/**
* POLYVAL (RFC 8452)
*
* Copyright:
* (C) 2026 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.modes.aead.polyval;

import botan.constants;
static if (BOTAN_HAS_AEAD_GCM_SIV):

import botan.algo_base.sym_algo;
import botan.utils.types;
import botan.utils.exceptn;
import botan.utils.mem_ops;
import botan.utils.xor_buf;
import botan.utils.loadstor;

/**
* POLYVAL universal hash (RFC 8452 §3). Used by AES-GCM-SIV.
*/
final class Polyval : SymmetricAlgorithm
{
public:
    enum size_t BS = 16;

    override @property string name() const { return "POLYVAL"; }
    override KeyLengthSpecification keySpec() const { return KeyLengthSpecification(BS); }

    override void clear()
    {
        m_Hx[] = 0;
        m_state[] = 0;
        m_buf[] = 0;
        m_buf_pos = 0;
        m_keyed = false;
    }

    void update(const(ubyte)* input, size_t length)
    {
        if (!m_keyed)
            throw new InvalidState("POLYVAL used before setKey");

        if (m_buf_pos)
        {
            const size_t take = (BS - m_buf_pos) < length ? (BS - m_buf_pos) : length;
            m_buf[m_buf_pos .. m_buf_pos + take] = input[0 .. take];
            m_buf_pos += take;
            input += take;
            length -= take;
            if (m_buf_pos == BS)
            {
                absorb(m_buf.ptr);
                m_buf_pos = 0;
            }
        }

        while (length >= BS)
        {
            absorb(input);
            input += BS;
            length -= BS;
        }

        if (length)
        {
            m_buf[0 .. length] = input[0 .. length];
            m_buf_pos = length;
        }
    }

    /// Pad the current remainder with zeros to a full block (no-op if aligned).
    void zeroPad()
    {
        if (!m_keyed)
            throw new InvalidState("POLYVAL used before setKey");
        if (m_buf_pos)
        {
            m_buf[m_buf_pos .. BS] = 0;
            absorb(m_buf.ptr);
            m_buf_pos = 0;
        }
    }

    void finalResult(ubyte* output)
    {
        if (!m_keyed)
            throw new InvalidState("POLYVAL used before setKey");
        if (m_buf_pos)
            throw new InvalidState("POLYVAL final without zeroPad");
        // State is kept in GHASH byte order; reverse back to POLYVAL.
        foreach (i; 0 .. BS)
            output[i] = m_state[15 - i];
        m_state[] = 0;
        m_buf_pos = 0;
    }

protected:
    override void keySchedule(const(ubyte)* key, size_t length)
    {
        /*
        RFC 8452 §3: POLYVAL(H, X) = ByteReverse(GHASH(ByteReverse(H)*x,
        ByteReverse(X))). Transform H once; keep state in GHASH order.
        */
        ulong h0 = loadLittleEndian!ulong(key, 0);
        ulong h1 = loadLittleEndian!ulong(key, 1);
        {
            const ulong t = h0;
            h0 = h1;
            h1 = t;
        }
        const ulong R = 0xE100000000000000UL;
        const ulong carry = (h1 & 1) ? R : 0;
        h1 = (h1 >> 1) | (h0 << 63);
        h0 = (h0 >> 1) ^ carry;
        storeBigEndian(m_Hx.ptr, h0, h1);

        m_state[] = 0;
        m_buf[] = 0;
        m_buf_pos = 0;
        m_keyed = true;
    }

private:
    void absorb(const(ubyte)* block)
    {
        ubyte[BS] rev;
        foreach (i; 0 .. BS)
            rev[i] = block[15 - i];
        xorBuf(m_state.ptr, rev.ptr, BS);
        gcmMultiply();
    }

    void gcmMultiply()
    {
        const ulong R = 0xE100000000000000UL;
        ulong[2] H = [ loadBigEndian!ulong(m_Hx.ptr, 0), loadBigEndian!ulong(m_Hx.ptr, 1) ];
        ulong[2] Z = [ 0, 0 ];

        foreach (size_t i; 0 .. 2)
        {
            const ulong X = loadBigEndian!ulong(m_state.ptr, i);
            foreach (size_t j; 0 .. 64)
            {
                if ((X >> (63 - j)) & 1)
                {
                    Z[0] ^= H[0];
                    Z[1] ^= H[1];
                }
                const ulong r = (H[1] & 1) ? R : 0;
                H[1] = (H[0] << 63) | (H[1] >> 1);
                H[0] = (H[0] >> 1) ^ r;
            }
        }
        storeBigEndian(m_state.ptr, Z[0], Z[1]);
    }

    ubyte[BS] m_Hx;
    ubyte[BS] m_state;
    ubyte[BS] m_buf;
    size_t m_buf_pos;
    bool m_keyed;
}

static if (BOTAN_HAS_TESTS && !SKIP_AEAD_TEST) unittest
{
    import botan.test;
    import botan.codec.hex;
    import botan.libstate.global_state;
    import memutils.hashmap;
    import std.stdio : File;
    auto state = globalState();
    logDebug("Testing polyval.d ...");
    size_t fails = 0;

    File vec = File("test_data/polyval.vec", "r");
    fails += runTestsBb(vec, "POLYVAL", "Out", false,
        (ref HashMap!(string, string) m)
        {
            if (!("Key" in m) || !("In" in m) || !("Out" in m))
                return 0;
            Unique!Polyval p = new Polyval;
            auto key = hexDecode(m["Key"]);
            auto input = hexDecode(m["In"]);
            auto expect = hexDecode(m["Out"]);
            p.setKey(key.ptr, key.length);
            p.update(input.ptr, input.length);
            p.zeroPad();
            ubyte[16] got;
            p.finalResult(got.ptr);
            if (got[] != expect[])
            {
                logError("POLYVAL got ", hexEncode(got.ptr, got.length), " != ", m["Out"]);
                return 1;
            }
            return 0;
        });

    fails += checkMemutilsRepeat("polyval", {
        Unique!Polyval p = new Polyval;
        ubyte[16] key, input, outp;
        key[0] = 1;
        p.setKey(key.ptr, key.length);
        p.update(input.ptr, input.length);
        p.zeroPad();
        p.finalResult(outp.ptr);
    });

    if (fails)
        logError("polyval failures: ", fails);
    assert(fails == 0);
}
