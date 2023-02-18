/**
* RSA
* 
* Copyright:
* (C) 1999-2008 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.algo.rsa;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO && BOTAN_HAS_RSA):

public import botan.pubkey.pubkey;
public import botan.pubkey.algo.if_algo;
import botan.pubkey.pk_ops;
import botan.math.numbertheory.reducer;
import botan.pubkey.blinding;
import botan.utils.parsing;
import botan.math.numbertheory.numthry;
import botan.pubkey.algo.keypair;
import botan.rng.rng;
import memutils.helpers : Embed;
import std.concurrency;
import core.thread;
import std.algorithm : max;

struct RSAOptions {
    enum algoName = "RSA";

    /*
    * Check Private RSA Parameters
    */
    static bool checkKey(in IFSchemePrivateKey privkey, RandomNumberGenerator rng, bool strong)
    {
        if (!privkey.checkKeyImpl(rng, strong))
            return false;

        if (!strong)
            return true;
        auto p_minus_1 = privkey.getP() - 1;
        auto q_minus_1 = privkey.getQ() - 1;
        if ((privkey.getE() * privkey.getD()) % lcm(&p_minus_1, &q_minus_1) != 1)
            return false;
        
        return signatureConsistencyCheck(rng, privkey, "EMSA4(SHA-1)");
    }
}

/**
* RSA Public Key
*/
struct RSAPublicKey
{
public:
    alias Options = RSAOptions;
    __gshared immutable string algoName = Options.algoName;

    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits) 
    {
		m_owned = true;
        m_pub = new IFSchemePublicKey(Options(), alg_id, key_bits);
    }

    /**
    * Create a RSAPublicKey
    * @arg n the modulus
    * @arg e the exponent
    */
    this(BigInt n, BigInt e)
    {
		m_owned = true;
        m_pub = new IFSchemePublicKey(Options(), n.move(), e.move());
    }

    this(PrivateKey pkey) { m_pub = cast(IFSchemePublicKey) pkey; }
    this(PublicKey pkey) { m_pub = cast(IFSchemePublicKey) pkey; }

    mixin Embed!(m_pub, m_owned);

	bool m_owned;
    IFSchemePublicKey m_pub;
}

/**
* RSA Private Key
*/
struct RSAPrivateKey
{
public:
    alias Options = RSAOptions;
    __gshared immutable string algoName = Options.algoName;

    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits, RandomNumberGenerator rng) 
    {
		m_owned = true;
        m_priv = new IFSchemePrivateKey(Options(), rng, alg_id, key_bits);
    }

    /**
    * Construct a private key from the specified parameters.
    *
    * Params:
    *  rng = a random number generator
    *  p = the first prime
    *  q = the second prime
    *  e = the exponent
    *  d = if specified, this has to be d with exp * d = 1 mod (p - 1, q - 1). Leave it as 0 if you wish 
    * the constructor to calculate it.
    *  n = if specified, this must be n = p * q. Leave it as 0
    * if you wish to the constructor to calculate it.
    */
    this(RandomNumberGenerator rng, BigInt p, BigInt q, BigInt e, BigInt d = BigInt(0), BigInt n = BigInt(0))
    {
		m_owned = true;
        m_priv = new IFSchemePrivateKey(Options(), rng, p.move(), q.move(), e.move(), d.move(), n.move());
    }

    /**
    * Create a new private key with the specified bit length
    * Params:
    *  rng = the random number generator to use
    *  bits = the desired bit length of the private key
    *  exp = the public exponent to be used
    */
    this(RandomNumberGenerator rng, size_t bits, size_t exp = 65537)
    {
        if (bits < 1024)
            throw new InvalidArgument(algoName ~ ": Can't make a key that is only " ~ to!string(bits) ~ " bits long");
        if (exp < 3 || exp % 2 == 0)
            throw new InvalidArgument(algoName ~ ": Invalid encryption exponent");
        BigInt e = exp;
        BigInt p, q, n, d, d1, d2, c;

        do
        {
            p = randomPrime(rng, (bits + 1) / 2, &e);
            q = randomPrime(rng, bits - p.bits(), &e);
            n = p * q;
        } while (n.bits() != bits);
		auto one = BigInt(1);
		auto p_1 = p - one;
		auto q_1 = q - one;
        auto d_0 = lcm(&p_1, &q_1);
        d = inverseMod(&e, &d_0);

		m_owned = true;
        m_priv = new IFSchemePrivateKey(Options(), rng, p.move(), q.move(), e.move(), d.move(), n.move());
        genCheck(rng);
    }

    this(PrivateKey pkey) { m_priv = cast(IFSchemePrivateKey) pkey; }

    mixin Embed!(m_priv, m_owned);

	bool m_owned;
    IFSchemePrivateKey m_priv;
}

/**
* RSA private (decrypt/sign) operation
*/
final class RSAPrivateOperation : Signature, Decryption
{
public:
    this(in PrivateKey pkey, RandomNumberGenerator rng) {
        this(cast(IFSchemePrivateKey) pkey, rng);
    }

    this(in RSAPrivateKey pkey, RandomNumberGenerator rng) {
        this(pkey.m_priv, rng);
    }

    this(in IFSchemePrivateKey rsa_, RandomNumberGenerator rng) 
    {
        rsa = rsa_;
        assert(rsa.algoName == RSAPublicKey.algoName);
        m_n = &rsa.getN();
        m_q = &rsa.getQ();
        m_c = &rsa.getC();
        m_d1 = &rsa.getD1();
        m_p = &rsa.getP();
        m_powermod_e_n = FixedExponentPowerMod(&rsa.getE(), &rsa.getN());
        m_powermod_d2_q = FixedExponentPowerMod(&rsa.getD2(), &rsa.getQ());
        m_mod_p = ModularReducer(rsa.getP());
        BigInt k = BigInt(rng, m_n.bits() - 1);
        auto e = (cast()*m_powermod_e_n)(cast()&k);
        m_blinder = Blinder(e, inverseMod(&k, m_n), *m_n);
    }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override size_t maxInputBits() const { return (m_n.bits() - 1); }

    override SecureVector!ubyte
        sign(const(ubyte)* msg, size_t msg_len, RandomNumberGenerator rng)
    {
        rng.addEntropy(msg, msg_len);
        
        /* We don't check signatures against powermod_e_n here because
            PKSigner checks verification consistency for all signature
            algorithms.
        */
        BigInt m = BigInt(msg, msg_len);
        m = m_blinder.blind(m.clone);
        m = privateOp(m);
        BigInt x = m_blinder.unblind(m);
        return BigInt.encode1363(x, m_n.bytes());
    }

    /*
    * RSA Decryption Operation
    */
    override SecureVector!ubyte decrypt(const(ubyte)* msg, size_t msg_len)
    {
        BigInt m = BigInt(msg, msg_len);
        BigInt x = m_blinder.unblind(privateOp(m_blinder.blind(m)));
        FixedExponentPowerModImpl powermod_e_n = cast(FixedExponentPowerModImpl) *m_powermod_e_n;
        assert(m == powermod_e_n.opCall(&x), "RSA decrypt passed consistency check");
        
        return BigInt.encodeLocked(x);
    }
private:
    BigInt privateOp()(auto const ref BigInt m) const
    {
		//import core.memory : GC; GC.disable(); scope(exit) GC.enable();
		import core.sync.condition;
		import core.sync.mutex;
		import core.atomic;
		import memutils.utils : ThreadMem;
		Mutex mutex = ThreadMem.alloc!Mutex();
		scope(exit) {
			ThreadMem.free(mutex);
		}
        if (m >= *m_n)
            throw new InvalidArgument("RSA private op - input is too large");
        BigInt j1;
		j1.reserve(max(m_q.bytes() + m_q.bytes() % 128, m_n.bytes() + m_n.bytes() % 128));

		struct Handler {
			shared(Mutex) mtx;
			shared(const BigInt*) d1;
			shared(const BigInt*) p;
			shared(const BigInt*) m2;
			shared(BigInt*) j1_2;
			void run() { 
				try {
					import botan.libstate.libstate : modexpInit;
					modexpInit(); // enable quick path for powermod
					BigInt* ret = cast(BigInt*) j1_2;
					{
						import memutils.utils;
						FixedExponentPowerMod powermod_d1_p = FixedExponentPowerMod(cast(BigInt*)d1, cast(BigInt*)p);
						BigInt _res =(cast()*powermod_d1_p)( cast(BigInt*) m2);
						synchronized(cast()mtx) ret.load(&_res);
					}
				} catch (Exception e) { logDebug("Error: ", e.toString()); }
			}
		}
		
		auto handler = Handler(cast(shared)mutex, cast(shared)m_d1, cast(shared)m_p, cast(shared)&m, cast(shared)&j1);
		Unique!Thread thr = new Thread(&handler.run);
		thr.start();
        FixedExponentPowerModImpl powermod_d2_q = cast(FixedExponentPowerModImpl)*m_powermod_d2_q;
        BigInt j2 = powermod_d2_q.opCall(&m);
		thr.join();
		BigInt j3;
		synchronized(mutex) j3 = m_mod_p.reduce(subMul(&j1, &j2, m_c));
        return mulAdd(&j3, m_q, &j2);
    }

    const IFSchemePrivateKey rsa;
    const BigInt* m_n;
    const BigInt* m_q;
    const BigInt* m_c;
    const BigInt* m_d1;
    const BigInt* m_p;
    FixedExponentPowerMod m_powermod_e_n, m_powermod_d2_q;
    ModularReducer m_mod_p;
    Blinder m_blinder;
}

/**
* RSA public (encrypt/verify) operation
*/
final class RSAPublicOperation : Verification, Encryption
{
public:
    this(in PublicKey pkey) {
        this(cast(IFSchemePublicKey) pkey);
    }

    this(in RSAPublicKey pkey) {
        this(pkey.m_pub);
    }

    this(in IFSchemePublicKey rsa)
    {
        assert(rsa.algoName == RSAPublicKey.algoName);
        m_rsa = rsa;
        m_n = &m_rsa.getN();
        m_powermod_e_n = FixedExponentPowerMod(&m_rsa.getE(), &m_rsa.getN());
    }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override size_t maxInputBits() const { return (m_n.bits() - 1); }
    override bool withRecovery() const { return true; }

    override SecureVector!ubyte encrypt(const(ubyte)* msg, size_t msg_len, RandomNumberGenerator)
    {
        BigInt m = BigInt(msg, msg_len);
        return BigInt.encode1363(publicOp(m), m_n.bytes());
    }

    override bool verify(const(ubyte)*, size_t, const(ubyte)*, size_t)
    {
        throw new InvalidState("Message recovery required");
    }

    override SecureVector!ubyte verifyMr(const(ubyte)* msg, size_t msg_len)
    {
        BigInt m = BigInt(msg, msg_len);
        return BigInt.encodeLocked(publicOp(m));
    }

private:
    BigInt publicOp(const ref BigInt m) const
    {
        if (m >= *m_n)
            throw new InvalidArgument("RSA public op - input is too large");
        return (cast()*m_powermod_e_n)(cast(BigInt*)&m);
    }

    const IFSchemePublicKey m_rsa;
    const BigInt* m_n;
    FixedExponentPowerMod m_powermod_e_n;
}

static if (BOTAN_TEST):

import botan.test;
import botan.pubkey.test;
import botan.rng.auto_rng;
import botan.pubkey.pubkey;
import botan.codec.hex;
import core.atomic;
import memutils.hashmap;

shared size_t total_tests;


size_t rsaesKat(string e,
                string p,
                string q,
                string msg,
                string padding,
                string nonce,
                string output)
{
    atomicOp!"+="(total_tests, 1);
	Unique!AutoSeededRNG rng = new AutoSeededRNG;
    
    auto privkey = RSAPrivateKey(*rng, BigInt(p), BigInt(q), BigInt(e));
    
    auto pubkey = RSAPublicKey(privkey);
    
    if (padding == "")
        padding = "Raw";
    
    auto enc = scoped!PKEncryptorEME(pubkey, padding);
    auto dec = scoped!PKDecryptorEME(privkey, padding);
    
    return validateEncryption(enc, dec, "RSAES/" ~ padding, msg, nonce, output);
}

size_t rsaSigKat(string e,
                   string p,
                   string q,
                   string msg,
                   string padding,
                   string nonce,
                   string output)
{
    atomicOp!"+="(total_tests, 1);
	Unique!AutoSeededRNG rng = new AutoSeededRNG;
    
    auto privkey = RSAPrivateKey(*rng, BigInt(p), BigInt(q), BigInt(e));
    
    auto pubkey = RSAPublicKey(privkey);
    
    if (padding == "")
        padding = "Raw";
    
    PKVerifier verify = PKVerifier(pubkey, padding);
    PKSigner sign = PKSigner(privkey, padding);
    
    return validateSignature(verify, sign, "RSA/" ~ padding, msg, *rng, nonce, output);
}

size_t rsaSigVerify(string e,
                    string n,
                    string msg,
                    string padding,
                    string signature)
{
    atomicOp!"+="(total_tests, 1);
    
    BigInt e_bn = BigInt(e);
    BigInt n_bn = BigInt(n);
    
    auto key = RSAPublicKey(n_bn.move(), e_bn.move());
    
    if (padding == "")
        padding = "Raw";
    
    PKVerifier verify = PKVerifier(key, padding);
    
    if (!verify.verifyMessage(hexDecode(msg), hexDecode(signature)))
        return 1;
    return 0;
}

size_t testPkKeygen(RandomNumberGenerator rng)
{
    size_t fails;

    auto rsa1024 = RSAPrivateKey(rng, 1024);
    rsa1024.checkKey(rng, true);
    atomicOp!"+="(total_tests, 1);

    fails += validateSaveAndLoad(rsa1024, rng);
    
    auto rsa2048 = RSAPrivateKey(rng, 2048);
    rsa2048.checkKey(rng, true);
    atomicOp!"+="(total_tests, 1);
    fails += validateSaveAndLoad(rsa2048, rng);

    return fails;
}

static if (BOTAN_HAS_TESTS && !SKIP_RSA_TEST) unittest
{
    logDebug("Testing rsa.d ...");
    size_t fails = 0;
    
	Unique!AutoSeededRNG rng = new AutoSeededRNG;

    
    File rsa_enc = File("test_data/pubkey/rsaes.vec", "r");
    File rsa_sig = File("test_data/pubkey/rsa_sig.vec", "r");
    File rsa_verify = File("test_data/pubkey/rsa_verify.vec", "r");
    
    fails += testPkKeygen(*rng);

    fails += runTestsBb(rsa_enc, "RSA Encryption", "Ciphertext", true,
        (ref HashMap!(string, string) m)
        {
            return rsaesKat(m["E"], m["P"], m["Q"], m["Msg"], m.get("Padding"), m.get("Nonce"), m["Ciphertext"]);
        });
    
    fails += runTestsBb(rsa_sig, "RSA Signature", "Signature", true,
        (ref HashMap!(string, string) m)
        {
            return rsaSigKat(m["E"], m["P"], m["Q"], m["Msg"], m.get("Padding"), m.get("Nonce"), m["Signature"]);
        });
    
    fails += runTestsBb(rsa_verify, "RSA Verify", "Signature", true,
        (ref HashMap!(string, string) m)
        {
            return rsaSigVerify(m["E"], m["N"], m["Msg"], m.get("Padding"), m["Signature"]);
        });
    
    testReport("rsa", total_tests, fails);
}