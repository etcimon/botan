/**
* EME-Raw — encrypt inputs without padding
*
* Copyright:
* (C) 2015,2016,2024 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pk_pad.eme_raw;

import botan.constants;
static if (BOTAN_HAS_EME_RAW):

import botan.pk_pad.eme;
import botan.utils.exceptn;
import botan.utils.types;

/**
* EME-Raw. SCAN: "Raw". Copies the message; unpad strips leading zeros.
* Do not use unless you know what you are doing.
*/
final class EMERaw : EME
{
public:
    override size_t maximumInputSize(size_t keybits) const { return keybits / 8; }

protected:
    override SecureVector!ubyte pad(const(ubyte)* input, size_t in_length,
                                    size_t, RandomNumberGenerator) const
    {
        // Bit-length vs n is checked by PKEncryptorEME (maxInputBits = n.bits()-1).
        return SecureVector!ubyte(input[0 .. in_length]);
    }

    override SecureVector!ubyte unpad(const(ubyte)* input, size_t in_length, size_t) const
    {
        size_t lead = 0;
        while (lead < in_length && input[lead] == 0)
            ++lead;
        return SecureVector!ubyte(input[lead .. in_length]);
    }
}

static if (BOTAN_TEST):

import botan.test;
import botan.pk_pad.factory;
import botan.libstate.global_state;
import botan.codec.hex;
import botan.rng.auto_rng;
import botan.utils.types;
import memutils.scoped;
static if (BOTAN_HAS_RSA) {
    import botan.pubkey.algo.rsa;
    import botan.pubkey.pubkey;
    import botan.math.bigint.bigint;
}

static if (BOTAN_HAS_TESTS && !SKIP_EME_RAW_TEST) unittest
{
    auto state = globalState();
    logDebug("Testing eme_raw.d ...");
    size_t fails = 0;

    Unique!EME eme = getEme("Raw");
    if (!eme)
    {
        logError("getEme(Raw) returned null");
        ++fails;
    }
    else
    {
        if (eme.maximumInputSize(1024) != 128)
            ++fails;
        Unique!AutoSeededRNG rng = new AutoSeededRNG;
        const ubyte[4] msg = [0x00, 0x00, 0xAB, 0xCD];
        auto padded = eme.encode(msg.ptr, msg.length, 1024, *rng);
        if (padded.length != 4 || padded[2] != 0xAB)
            ++fails;
        const ubyte[6] coded = [0x00, 0x00, 0x00, 0x01, 0x02, 0x03];
        auto plain = eme.decode(coded.ptr, coded.length, 1024);
        if (plain.length != 3 || plain[0] != 1 || plain[2] != 3)
            ++fails;
        auto empty = eme.decode(cast(const(ubyte)*) null, 0, 1024);
        if (empty.length != 0)
            ++fails;
    }

    static if (BOTAN_HAS_RSA)
    {
        Unique!AutoSeededRNG rng = new AutoSeededRNG;
        auto p = BigInt("0xD987D71CC924C479D30CD88570A626E15F0862A9A138874F7016684216984215");
        auto q = BigInt("0xC5660F33AB35E41CB10A30D3A58354ADB5CC3243342C22E1A5BCCB79C391A533");
        auto e = BigInt("0x3ED19");
        auto priv = RSAPrivateKey(*rng, p.move(), q.move(), e.move());
        auto pub = RSAPublicKey(priv);
        auto enc = scoped!PKEncryptorEME(pub, "Raw");
        auto dec = scoped!PKDecryptorEME(priv, "Raw");
        foreach (ubyte i; 1 .. 9)
        {
            ubyte[16] input;
            input[$ - 1] = i;
            auto ct = enc.encrypt(input.ptr, input.length, *rng);
            auto pt = dec.decrypt(ct);
            // RSA decrypt is already compact; EME-Raw strips any leftover zeros.
            if (pt.length == 0 || pt[$ - 1] != i)
                ++fails;
            else
            {
                bool rest_zero = true;
                foreach (b; pt[0 .. $ - 1])
                    if (b != 0)
                        rest_zero = false;
                if (!rest_zero && pt.length != 16)
                    ++fails;
            }
        }
    }

    testReport("eme_raw", 0, fails);
    assert(fails == 0);
}
