/**
* Rabin-Williams
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.algo.rw;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO && BOTAN_HAS_RW):

public import botan.pubkey.pubkey;
import botan.pubkey.algo.if_algo;
import botan.pubkey.pk_ops;
import botan.math.numbertheory.reducer;
import botan.pubkey.blinding;
import botan.math.numbertheory.numthry;
import botan.pubkey.algo.keypair;
import botan.utils.parsing;
import botan.utils.types;
import memutils.helpers;
import std.algorithm;
import std.concurrency;

struct RWOptions {
    enum algoName = "RW";

    /*
    * Check Private Rabin-Williams Parameters
    */
    static bool checkKey(in IFSchemePrivateKey privkey, RandomNumberGenerator rng, bool strong)
    {
        if (!privkey.checkKeyImpl(rng, strong))
            return false;
        
        if (!strong)
            return true;
        
        if ((privkey.getE() * privkey.getD()) % (lcm(privkey.getP() - 1, privkey.getQ() - 1) / 2) != 1)
            return false;
        
        return signatureConsistencyCheck(rng, privkey, "EMSA2(SHA-1)");
    }
}
/**
* Rabin-Williams Public Key
*/
struct RWPublicKey
{
public:
    alias Options = RWOptions;
    __gshared immutable string algoName = Options.algoName;

    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits)
    {
        m_pub = new IFSchemePublicKey(Options(), alg_id, key_bits);
    }

    this(BigInt mod, BigInt exponent)
    {
        m_pub = new IFSchemePublicKey(Options(), mod.move(), exponent.move());
    }

    this(PrivateKey pkey) { m_pub = cast(IFSchemePublicKey) pkey; }
    this(PublicKey pkey) { m_pub = cast(IFSchemePublicKey) pkey; }

    mixin Embed!m_pub;

    IFSchemePublicKey m_pub;
}

/**
* Rabin-Williams Private Key
*/
struct RWPrivateKey
{
public:
    alias Options = RWOptions;
    __gshared immutable string algoName = Options.algoName;

    this(in AlgorithmIdentifier alg_id,
         const ref SecureVector!ubyte key_bits,
         RandomNumberGenerator rng) 
    {
        m_priv = new IFSchemePrivateKey(Options(), rng, alg_id, key_bits);
    }

    this(RandomNumberGenerator rng,
         BigInt p, BigInt q,
         BigInt e, BigInt d = 0,
         BigInt n = 0)
    {
        m_priv = new IFSchemePrivateKey(Options(), rng, p.move(), q.move(), e.move(), d.move(), n.move());
    }

    /*
    * Create a Rabin-Williams private key
    */
    this(RandomNumberGenerator rng, size_t bits, size_t exp = 2)
    {
        if (bits < 1024)
            throw new InvalidArgument(algoName ~ ": Can't make a key that is only " ~
                                       to!string(bits) ~ " bits long");
        if (exp < 2 || exp % 2 == 1)
            throw new InvalidArgument(algoName ~ ": Invalid encryption exponent");

        BigInt p, q, e, d, n, d1, d2;

        e = exp;
        
        do
        {
            p = randomPrime(rng, (bits + 1) / 2, e / 2, 3, 4);
            q = randomPrime(rng, bits - p.bits(), e / 2, ((p % 8 == 3) ? 7 : 3), 8);
            n = p * q;
        } while (n.bits() != bits);
        
        d = inverseMod(e, lcm(p - 1, q - 1) >> 1);

        m_priv = new IFSchemePrivateKey(Options(), rng, p.move(), q.move(), e.move(), d.move(), n.move());

        genCheck(rng);
    }

    mixin Embed!m_priv;

    this(PrivateKey pkey) { m_priv = cast(IFSchemePrivateKey) pkey; }

    IFSchemePrivateKey m_priv;
}

/**
* Rabin-Williams Signature Operation
*/
final class RWSignatureOperation : Signature
{
public:
    this(in RWPrivateKey pkey) {
        this(pkey.m_priv);
    }

    this(in PrivateKey pkey) {
        this(cast(IFSchemePrivateKey) pkey);
    }

    this(in IFSchemePrivateKey rw) 
    {
        assert(rw.algoName == RWPublicKey.algoName);
        m_n = &rw.getN();
        m_e = &rw.getE();
        m_q = &rw.getQ();
        m_c = &rw.getC();
        m_d1 = &rw.getD1();
        m_p = &rw.getP();
        m_powermod_d2_q = FixedExponentPowerMod(rw.getD2(), rw.getQ());
        m_mod_p = ModularReducer(rw.getP());
        m_blinder = Blinder.init;
    }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override size_t maxInputBits() const { return (m_n.bits() - 1); }

    override SecureVector!ubyte sign(const(ubyte)* msg, size_t msg_len, RandomNumberGenerator rng)
    {
        rng.addEntropy(msg, msg_len);

        if (!m_blinder.initialized()) { // initialize here because we need rng
            BigInt k = BigInt(rng, std.algorithm.min(160, m_n.bits() - 1));
            auto e = powerMod(k, *m_e, *m_n);
            m_blinder = Blinder(e, inverseMod(k, *m_n), *m_n);
        }

        BigInt i = BigInt(msg, msg_len);
        
        if (i >= *m_n || i % 16 != 12)
            throw new InvalidArgument("Rabin-Williams: invalid input");
        
        if (jacobi(i, *m_n) != 1)
            i >>= 1;
        
        i = m_blinder.blind(i);

        BigInt j1;

        auto tid = spawn((shared Tid tid, shared(const BigInt*) d1, shared(const BigInt*) p, shared(BigInt*) i2, shared(BigInt*) j1_2) 
            {
                import botan.libstate.libstate : modexpInit;
                modexpInit(); // enable quick path for powermod
                BigInt* ret = cast(BigInt*)j1_2;

                {
                    auto powermod_d1_p = FixedExponentPowerMod(*cast(const BigInt*)d1, *cast(const BigInt*)p);
                    *ret = (*powermod_d1_p)(*cast(BigInt*)i2);
                    send(cast(Tid) tid, true); // send j1 available signal
                }
                auto done = receiveOnly!bool; // can destroy j1
                destroy(*ret);
                send(cast(Tid)tid, true); // signal j1 destroyed
            }, 
            cast(shared)thisTid(), cast(shared)m_d1, cast(shared)m_p, cast(shared)&i, cast(shared)&j1
            );
        const BigInt j2 = (*m_powermod_d2_q)(i);
        bool done = receiveOnly!bool();        
        BigInt j3 = m_mod_p.reduce(subMul(j1, j2, *m_c));
        send(cast(Tid)tid, true);
        BigInt r = m_blinder.unblind(mulAdd(j3, *m_q, j2));
        
        BigInt cmp2 = *m_n - r;
        BigInt min_val = r.move();
        if (cmp2 < min_val)
            min_val = cmp2.move();
        auto ret = BigInt.encode1363(min_val, m_n.bytes());
        done = receiveOnly!bool(); // make sure j1 is destroyed
        return ret;
    }
private:
    const BigInt* m_n;
    const BigInt* m_e;
    const BigInt* m_q;
    const BigInt* m_c;
    const BigInt* m_d1;
    const BigInt* m_p;

    FixedExponentPowerMod m_powermod_d1_p, m_powermod_d2_q;
    ModularReducer m_mod_p;
    Blinder m_blinder;
}

/**
* Rabin-Williams Verification Operation
*/
final class RWVerificationOperation : Verification
{
public:
    this(in PublicKey pkey) {
        this(cast(IFSchemePublicKey) pkey);
    }

    this(in RWPublicKey pkey) {
        this(pkey.m_pub);
    }

    this(in IFSchemePublicKey rw)
    {
        assert(rw.algoName == RWPublicKey.algoName);
        m_n = &rw.getN();
        m_powermod_e_n = FixedExponentPowerMod(rw.getE(), rw.getN());
    }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override size_t maxInputBits() const { return (m_n.bits() - 1); }
    override bool withRecovery() const { return true; }

    override bool verify(const(ubyte)*, size_t, const(ubyte)*, size_t)
    {
        throw new InvalidState("Message recovery required");
    }

    override SecureVector!ubyte verifyMr(const(ubyte)* msg, size_t msg_len)
    {
        BigInt m = BigInt(msg, msg_len);
        
        if ((m > (*m_n >> 1)) || m.isNegative())
            throw new InvalidArgument("RW signature verification: m > n / 2 || m < 0");
        
        BigInt r = (*m_powermod_e_n)(m);
        if (r % 16 == 12)
            return BigInt.encodeLocked(r);
        if (r % 8 == 6)
            return BigInt.encodeLocked(r*2);
        
        r = (*m_n) - r;
        if (r % 16 == 12)
            return BigInt.encodeLocked(r);
        if (r % 8 == 6)
            return BigInt.encodeLocked(r*2);
        
        throw new InvalidArgument("RW signature verification: Invalid signature");
    }

private:
    const BigInt* m_n;
    FixedExponentPowerMod m_powermod_e_n;
}


static if (BOTAN_TEST):
import botan.test;
import botan.pubkey.test;
import botan.rng.auto_rng;
import botan.codec.hex;
import core.atomic;
import memutils.hashmap;

shared size_t total_tests;
__gshared immutable string padding = "EMSA2(SHA-1)";

size_t testPkKeygen(RandomNumberGenerator rng)
{
    atomicOp!"+="(total_tests, 1);
    size_t fails;
    auto rw1024 = RWPrivateKey(rng, 1024);
    rw1024.checkKey(rng, true);
    fails += validateSaveAndLoad(rw1024, rng);
    return fails;
}
size_t rwSigKat(string e,
                  string p,
                  string q,
                  string msg,
                  string signature)
{
    atomicOp!"+="(total_tests, 1);
    auto rng = AutoSeededRNG();
    
    auto privkey = RWPrivateKey(rng, BigInt(p), BigInt(q), BigInt(e));
    
    auto pubkey = RWPublicKey(privkey);
    
    PKVerifier verify = PKVerifier(pubkey, padding);
    PKSigner sign = PKSigner(privkey, padding);
    
    return validateSignature(verify, sign, "RW/" ~ padding, msg, rng, signature);
}

size_t rwSigVerify(string e,
                     string n,
                     string msg,
                     string signature)
{
    atomicOp!"+="(total_tests, 1);
    auto rng = AutoSeededRNG();
    
    BigInt e_bn = BigInt(e);
    BigInt n_bn = BigInt(n);
    
    auto key = RWPublicKey(n_bn.move(), e_bn.move());
    
    PKVerifier verify = PKVerifier(key, padding);
    
    if (!verify.verifyMessage(hexDecode(msg), hexDecode(signature)))
        return 1;
    return 0;
}

static if (!SKIP_RW_TEST) unittest
{
    logDebug("Testing rw.d ...");
    size_t fails = 0;
    
    auto rng = AutoSeededRNG();
    
    fails += testPkKeygen(rng);
    
    File rw_sig = File("../test_data/pubkey/rw_sig.vec", "r");
    File rw_verify = File("../test_data/pubkey/rw_verify.vec", "r");
    
    fails += runTestsBb(rw_sig, "RW Signature", "Signature", true,
        (ref HashMap!(string, string) m) {
            return rwSigKat(m["E"], m["P"], m["Q"], m["Msg"], m["Signature"]);
        });
    
    fails += runTestsBb(rw_verify, "RW Verify", "Signature", true,
        (ref HashMap!(string, string) m) {
            return rwSigVerify(m["E"], m["N"], m["Msg"], m["Signature"]);
        });

    testReport("rw", total_tests, fails);
}