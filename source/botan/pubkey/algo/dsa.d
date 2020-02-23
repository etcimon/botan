/**
* DSA
* 
* Copyright:
* (C) 1999-2010 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.algo.dsa;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO && BOTAN_HAS_DSA):

public import botan.pubkey.algo.dl_algo;
public import botan.pubkey.pubkey;
import botan.pubkey.pk_ops;
import botan.math.numbertheory.reducer;
import botan.math.numbertheory.pow_mod;
import botan.math.numbertheory.numthry;
import botan.pubkey.algo.keypair;
import std.concurrency;
import core.thread;
import memutils.helpers : Embed;
import std.algorithm : max;

struct DSAOptions {
    enum algoName = "DSA";
    enum format = DLGroup.ANSI_X9_57;
    enum msgParts = 2;

    /*
    * Check Private DSA Parameters
    */
    static bool checkKey(in DLSchemePrivateKey privkey, RandomNumberGenerator rng, bool strong)
    {
        if (!privkey.checkKeyImpl(rng, strong) || privkey.m_x >= privkey.groupQ())
            return false;

        if (!strong)
            return true;

        return signatureConsistencyCheck(rng, privkey, "EMSA1(SHA-1)");
    }
}

/**
* DSA Public Key
*/
struct DSAPublicKey
{
public:
    alias Options = DSAOptions;
    __gshared immutable string algoName = Options.algoName;


    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits) 
    {
		m_owned = true;
        m_pub = new DLSchemePublicKey(Options(), alg_id, key_bits);
    }

    /*
    * DSAPublicKey Constructor
    */
    this(DLGroup grp, BigInt y1)
    {
		m_owned = true;
        m_pub = new DLSchemePublicKey(Options(), grp.move, y1.move);
    }

    this(PublicKey pkey) { m_pub = cast(DLSchemePublicKey) pkey; }
    this(PrivateKey pkey) { m_pub = cast(DLSchemePublicKey) pkey; }

    mixin Embed!(m_pub, m_owned);

	bool m_owned;
    DLSchemePublicKey m_pub;
}

/**
* DSA Private Key
*/
struct DSAPrivateKey
{
public:
    alias Options = DSAOptions;
    __gshared immutable string algoName = Options.algoName;
    
    /*
    * Create a DSA private key
    */
    this(RandomNumberGenerator rng, DLGroup dl_group, BigInt x_arg = 0)
    {
        bool x_arg_0;
        if (x_arg == 0) {
            x_arg_0 = true;
            auto bi = BigInt(2);
            x_arg = BigInt.randomInteger(rng, bi, dl_group.getQ() - 1);
        }
        BigInt y1 = powerMod(&dl_group.getG(), &x_arg, &dl_group.getP());
        
		m_owned = true;
        m_priv = new DLSchemePrivateKey(Options(), dl_group.move, y1.move, x_arg.move);

        if (x_arg_0)
            m_priv.genCheck(rng);
        else
            m_priv.loadCheck(rng);
    }

    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits, RandomNumberGenerator rng)
    {
		m_owned = true;
        m_priv = new DLSchemePrivateKey(Options(), alg_id, key_bits);
        m_priv.loadCheck(rng);
    }

    this(PrivateKey pkey) { m_priv = cast(DLSchemePrivateKey) pkey; }

    mixin Embed!(m_priv, m_owned);

	bool m_owned;
    DLSchemePrivateKey m_priv;
}

/**
* Object that can create a DSA signature
*/
final class DSASignatureOperation : Signature
{
public:
    this(in PrivateKey pkey) {
        this(cast(DLSchemePrivateKey) pkey);
    }

    this(in DSAPrivateKey pkey) {
        this(pkey.m_priv);
    }

    this(in DLSchemePrivateKey dsa)
    { 
        assert(dsa.algoName == DSAPublicKey.algoName);
        m_q = &dsa.groupQ();
        m_x = &dsa.getX();
        m_g = &dsa.groupG();
        m_p = &dsa.groupP();
        m_mod_q = ModularReducer(dsa.groupQ());
    }

    override size_t messageParts() const { return 2; }
    override size_t messagePartSize() const { return m_q.bytes(); }
    override size_t maxInputBits() const { return m_q.bits(); }

    override SecureVector!ubyte sign(const(ubyte)* msg, size_t msg_len, RandomNumberGenerator rng)
    {    
		//import core.memory : GC; GC.disable(); scope(exit) GC.enable();
        rng.addEntropy(msg, msg_len);
        
        BigInt i = BigInt(msg, msg_len);
        BigInt r = BigInt(0), s = BigInt(0);

        while (r == 0 || s == 0)
        {
            BigInt k;
            do
                k.randomize(rng, m_q.bits());
            while (k >= *m_q);

			import core.sync.mutex, core.sync.condition;
			Mutex mutex = ThreadMem.alloc!Mutex();
			scope(exit) {
				ThreadMem.free(mutex);
			}

            BigInt res;
			//logDebug("Expected: ", max(m_g.bytes() + m_g.bytes() % 128, m_x.bytes() + m_x.bytes % 128));
			res.reserve(4096);

			struct Handler {
				shared(Mutex) mtx;
				shared(ModularReducer*) mod_q;
				shared(const BigInt*) g;
				shared(const BigInt*) p;
				shared(BigInt*) k2;
				shared(BigInt*) res2;
				void run() { 	
					try {
						import botan.libstate.libstate : modexpInit;
						modexpInit(); // enable quick path for powermod
						BigInt* ret = cast(BigInt*) res2;
						{ import memutils.utils;
							auto powermod_g_p = scoped!FixedBasePowerModImpl(cast(const(BigInt)*)g, cast(const(BigInt)*)p);
							BigInt _res = (cast(ModularReducer)*mod_q).reduce(powermod_g_p(cast(BigInt*)k2));
							//logDebug("Got: ", _res.bytes());
							synchronized(cast()mtx) ret.load(&_res);
						}
					}
					catch (Exception e) { logDebug("Error: ", e.toString()); }
				}
			}
			
			auto handler = Handler(cast(shared) mutex, cast(shared)&m_mod_q, cast(shared)m_g, cast(shared)m_p, cast(shared)&k, cast(shared)&res);
			Unique!Thread thr = new Thread(&handler.run);
			thr.start();
            s = inverseMod(&k, m_q);
			thr.join();
			synchronized(mutex) r = res.dup;
			BigInt s_arg = mulAdd(m_x, &r, &i);
            s = m_mod_q.multiply(&s, &s_arg);
        }
        
        SecureVector!ubyte output = SecureVector!ubyte(2*m_q.bytes());
        r.binaryEncode(&output[output.length / 2 - r.bytes()]);
        s.binaryEncode(&output[output.length - s.bytes()]);
        return output.move;
    }
private:
    const BigInt* m_q;
    const BigInt* m_x;
    const BigInt* m_g;
    const BigInt* m_p;
    ModularReducer m_mod_q;
}

/**
* Object that can verify a DSA signature
*/
final class DSAVerificationOperation : Verification
{
public:
    this(in PublicKey pkey) {
        this(cast(DLSchemePublicKey) pkey);
    }

    this(in DSAPublicKey pkey) {
        this(pkey.m_pub);
    }

    this(in DLSchemePublicKey dsa) 
    {
        assert(dsa.algoName == DSAPublicKey.algoName);
        m_dsa = dsa;
        m_q = &m_dsa.groupQ();
        m_y = &m_dsa.getY();
        m_g = &m_dsa.groupG();
        m_p = &m_dsa.groupP();
        m_powermod_y_p = FixedBasePowerMod(m_y, m_p);
        m_mod_p = ModularReducer(*m_p);
        m_mod_q = ModularReducer(*m_q);
    }

    override size_t messageParts() const { return 2; }
    override size_t messagePartSize() const { return m_q.bytes(); }
    override size_t maxInputBits() const { return m_q.bits(); }

    override bool withRecovery() const { return false; }

    override SecureVector!ubyte verifyMr(const(ubyte)*, size_t) { throw new InvalidState("Message recovery not supported"); }
    override bool verify(const(ubyte)* msg, size_t msg_len, const(ubyte)* sig, size_t sig_len)
    {
		//import core.memory : GC; GC.disable(); scope(exit) GC.enable();
        const BigInt* q = &m_mod_q.getModulus();
        
        if (sig_len != 2*q.bytes() || msg_len > q.bytes())
            return false;
        
        BigInt r = BigInt(sig, q.bytes());
        BigInt s = BigInt(sig + q.bytes(), q.bytes());
        BigInt i = BigInt(msg, msg_len);
        if (r <= 0 || r >= *q || s <= 0 || s >= *q)
            return false;
        
        s = inverseMod(&s, q);

        BigInt s_i;
		s_i.reserve(max(m_g.bytes() + m_g.bytes() % 128, m_y.bytes() + m_y.bytes() % 128));
		import core.sync.mutex, core.sync.condition;
		Mutex mutex = ThreadMem.alloc!Mutex();
		scope(exit) {
			ThreadMem.free(mutex);
		}

		struct Handler {
			shared(Mutex) mtx;
			shared(ModularReducer*) mod_q;
			shared(const BigInt*)g2;
			shared(const BigInt*)p2;
			shared(BigInt*) s2;
			shared(BigInt*) i2;
			shared(BigInt*) s_i2;
			void run() { 	
				try {
					import botan.libstate.libstate : modexpInit, globalState;
					modexpInit(); // enable quick path for powermod
					globalState();
					BigInt* ret = cast(BigInt*) s_i2;
					{
						import memutils.utils;
						auto powermod_g_p = FixedBasePowerMod(cast(const(BigInt)*)g2, cast(const(BigInt)*)p2);
						auto mult = (cast(ModularReducer*)mod_q).multiply(cast(const(BigInt)*)s2, cast(const(BigInt)*)i2);
						BigInt _res = (cast(FixedBasePowerModImpl)powermod_g_p)(cast(BigInt*)&mult);
						synchronized(cast()mtx) ret.load(&_res);
					}
				} catch (Exception e) {
					logDebug("Got error: ", e.toString);
				}
			}
		}
		
		auto handler = Handler(cast(shared) mutex, cast(shared)&m_mod_q, cast(shared)m_g, cast(shared)m_p, cast(shared)&s, cast(shared)&i, cast(shared)&s_i);
		Unique!Thread thr = new Thread(&handler.run);
		thr.start();
        BigInt s_r_0 = (cast(ModularReducer)m_mod_q).multiply(&s, &r);
        FixedBasePowerModImpl powermod_y_p = cast(FixedBasePowerModImpl)m_powermod_y_p;
        BigInt s_r = powermod_y_p(&s_r_0);
		thr.join();
        synchronized(mutex) s = m_mod_p.multiply(cast(const(BigInt)*)&s_i, cast(const(BigInt)*)&s_r);
        auto r2 = m_mod_q.reduce(s.move);
        return (r2 == r);
    }

private:
    const DLSchemePublicKey m_dsa;
    const BigInt* m_q;
    const BigInt* m_y;
    const BigInt* m_g;
    const BigInt* m_p;

    FixedBasePowerMod m_powermod_y_p;
    ModularReducer m_mod_p, m_mod_q;
}


static if (BOTAN_TEST):

import botan.test;
import botan.pubkey.test;
import botan.rng.auto_rng;
import botan.pubkey.pubkey;
import botan.codec.hex;
import memutils.hashmap;

import core.atomic;
private shared size_t total_tests;

size_t testPkKeygen(RandomNumberGenerator rng) {
    size_t fails;
    string[] dsa_list = ["dsa/jce/1024", "dsa/botan/2048", "dsa/botan/3072"];
    foreach (dsa; dsa_list) {
        atomicOp!"+="(total_tests, 1);
        auto key = DSAPrivateKey(rng, DLGroup(dsa));
        key.checkKey(rng, true);
        fails += validateSaveAndLoad(key, rng);
    }
    
    return fails;
}

size_t dsaSigKat(string p,
                   string q,
                   string g,
                   string x,
                   string hash,
                   string msg,
                   string nonce,
                   string signature)
{
    atomicOp!"+="(total_tests, 1);
    
	Unique!AutoSeededRNG rng = new AutoSeededRNG;
    
    BigInt p_bn = BigInt(p);
    BigInt q_bn = BigInt(q);
    BigInt g_bn = BigInt(g);
    BigInt x_bn = BigInt(x);
    
    DLGroup group = DLGroup(p_bn, q_bn, g_bn);
    auto privkey = DSAPrivateKey(*rng, group.move(), x_bn.move());
    
    auto pubkey = DSAPublicKey(privkey);
    
    const string padding = "EMSA1(" ~ hash ~ ")";
    PKVerifier verify = PKVerifier(*pubkey, padding);
    PKSigner sign = PKSigner(*privkey, padding);
    return validateSignature(verify, sign, "DSA/" ~ hash, msg, *rng, nonce, signature);
}

static if (BOTAN_HAS_TESTS && !SKIP_DSA_TEST) unittest
{
    logDebug("Testing dsa.d ...");
    size_t fails;
    
    Unique!AutoSeededRNG rng = new AutoSeededRNG;
    
    File dsa_sig = File("test_data/pubkey/dsa.vec", "r");
    
    fails += runTestsBb(dsa_sig, "DSA Signature", "Signature", true,
        (ref HashMap!(string, string) m)
        {
            return dsaSigKat(m["P"], m["Q"], m["G"], m["X"], m["Hash"], m["Msg"], m["Nonce"], m["Signature"]);
        });

    fails += testPkKeygen(*rng);
    
    testReport("dsa", total_tests, fails);
}

