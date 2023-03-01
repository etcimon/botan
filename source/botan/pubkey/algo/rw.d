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
import core.thread;

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
        
        auto p_minus_1 = privkey.getP() - 1;
        auto q_minus_1 = privkey.getQ() - 1;
        auto arg1 = (privkey.getE() * privkey.getD());
        auto arg2 = (lcm(&p_minus_1, &q_minus_1) >> 1);
        auto mod_res = arg1 % arg2;
        logTrace(mod_res.toString());
        import botan.math.bigint.divide;
        BigInt q, r;
        logTrace("Calling divide with arg1arg2:");
        logTrace(arg1.toString());
        logTrace(arg2.toString());
        divide(&arg1, &arg2, &q, &r, true);
        logTrace(r.toString());

        if (mod_res != 1)
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
		m_owned = true;
        m_pub = new IFSchemePublicKey(Options(), alg_id, key_bits);
    }

    this(BigInt mod, BigInt exponent)
    {
		m_owned = true;
        m_pub = new IFSchemePublicKey(Options(), mod.move(), exponent.move());
    }

    this(PrivateKey pkey) { m_pub = cast(IFSchemePublicKey) pkey; }
    this(PublicKey pkey) { m_pub = cast(IFSchemePublicKey) pkey; }

    mixin Embed!(m_pub, m_owned);

	bool m_owned;
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
		m_owned = true;
        m_priv = new IFSchemePrivateKey(Options(), rng, alg_id, key_bits);
    }

    this(RandomNumberGenerator rng,
         BigInt p, BigInt q,
         BigInt e, BigInt d = BigInt(0),
         BigInt n = BigInt(0))
    {
		m_owned = true;
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
        auto p_minus_1 = p-1;
        auto q_minus_1 = q-1;    
        auto d_0 = lcm(&p_minus_1, &q_minus_1);
        d_0 >>= 1;
        d = inverseMod(&e, &d_0);

		m_owned = true;
        m_priv = new IFSchemePrivateKey(Options(), rng, p.move(), q.move(), e.move(), d.move(), n.move());

        genCheck(rng);
    }

    mixin Embed!(m_priv, m_owned);

    this(PrivateKey pkey) { m_priv = cast(IFSchemePrivateKey) pkey; }
	bool m_owned;
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
        m_priv_key = rw;
        m_n = &m_priv_key.getN();
        m_e = &m_priv_key.getE();
        m_q = &m_priv_key.getQ();
        m_c = &m_priv_key.getC();
        m_d1 = &m_priv_key.getD1();
        m_p = &m_priv_key.getP();
        m_powermod_d1_p = FixedExponentPowerMod(m_d1, m_p);
        m_powermod_d2_q = FixedExponentPowerMod(&m_priv_key.getD2(), m_q);
        m_mod_p = ModularReducer(*m_p);
    }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override size_t maxInputBits() const { return (m_n.bits() - 1); }

    override SecureVector!ubyte sign(const(ubyte)* msg, size_t msg_len, RandomNumberGenerator rng)
    {
		import core.memory : GC; GC.disable(); scope(exit) GC.enable();
		import core.thread;
        rng.addEntropy(msg, msg_len);

        if (!m_blinder.initialized()) { // initialize here because we need rng
            BigInt k = BigInt(rng, std.algorithm.min(160, m_n.bits() - 1));
            auto e = powerMod(&k, m_e, m_n);
            m_blinder = Blinder(e, inverseMod(&k, m_n), *m_n);
        }

        BigInt i = BigInt(msg, msg_len);
        
        if (i >= *m_n || i % 16 != 12)
            throw new InvalidArgument("Rabin-Williams: invalid input");
        
        if (jacobi(&i, m_n) != 1)
            i >>= 1;        
        i = m_blinder.blind(i);
        const BigInt j1 = (cast(FixedExponentPowerModImpl)*m_powermod_d1_p)(cast(BigInt*)&i);
		const BigInt j2 = (cast(FixedExponentPowerModImpl)*m_powermod_d2_q)(cast(BigInt*)&i);		
		BigInt j3 = m_mod_p.reduce(subMul(&j1, &j2, m_c));
        BigInt r = m_blinder.unblind(mulAdd(&j3, m_q, &j2)); 
        BigInt cmp2 = *m_n - r;
        BigInt min_val = r.move();
        if (cmp2 < min_val)
            min_val = cmp2.move();
        auto ret = BigInt.encode1363(&min_val, m_n.bytes());
        return ret;
    }
private:
    const IFSchemePrivateKey m_priv_key;
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
        m_e = &rw.getE();
        m_powermod_e_n = FixedExponentPowerMod(m_e, m_n);
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
        m_powermod_e_n = FixedExponentPowerMod(m_e, m_n);
        BigInt r = (cast()*m_powermod_e_n)(cast(BigInt*)&m);
        if (r % 16 == 12)
            return BigInt.encodeLocked(&r);
        if (r % 8 == 6)
            return BigInt.encodeLocked(r*2);
        
        r = (*m_n) - r;
        if (r % 16 == 12)
            return BigInt.encodeLocked(&r);
        if (r % 8 == 6)
            return BigInt.encodeLocked(r*2);
        
        throw new InvalidArgument("RW signature verification: Invalid signature");
    }

private:
    const BigInt* m_n;
    const BigInt* m_e;
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
	Unique!AutoSeededRNG rng = new AutoSeededRNG;
    
    auto privkey = RWPrivateKey(*rng, BigInt(p), BigInt(q), BigInt(e));
    
    auto pubkey = RWPublicKey(privkey);
    
    PKVerifier verify = PKVerifier(pubkey, padding);
    PKSigner sign = PKSigner(privkey, padding);
    
    return validateSignature(verify, sign, "RW/" ~ padding, msg, *rng, signature);
}

size_t rwSigVerify(string e,
                     string n,
                     string msg,
                     string signature)
{
    atomicOp!"+="(total_tests, 1);

    BigInt e_bn = BigInt(e);
    BigInt n_bn = BigInt(n);
    
    auto key = RWPublicKey(n_bn.move(), e_bn.move());
    
    PKVerifier verify = PKVerifier(key, padding);
    
    if (!verify.verifyMessage(hexDecode(msg), hexDecode(signature)))
        return 1;
    return 0;
}

static if (BOTAN_HAS_TESTS && !SKIP_RW_TEST) unittest
{
	import core.thread : Thread;
	//Thread.sleep(10.seconds);
    logDebug("Testing rw.d ...");
    size_t fails = 0;
    
	Unique!AutoSeededRNG rng = new AutoSeededRNG;
    
    fails += testPkKeygen(*rng);
    
    File rw_sig = File("test_data/pubkey/rw_sig.vec", "r");
    File rw_verify = File("test_data/pubkey/rw_verify.vec", "r");
    
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