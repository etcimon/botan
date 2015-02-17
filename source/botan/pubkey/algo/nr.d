/**
* Nyberg-Rueppel
* 
* Copyright:
* (C) 1999-2010 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.algo.nr;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO && BOTAN_HAS_NYBERG_RUEPPEL):

public import botan.pubkey.pubkey;
import botan.pubkey.algo.dl_algo;
import botan.pubkey.pk_ops;
import botan.math.numbertheory.numthry;
import botan.math.numbertheory.reducer;
import botan.math.numbertheory.numthry;
import botan.pubkey.algo.keypair;
import botan.rng.rng;
import std.concurrency;
import memutils.helpers : Embed;

struct NROptions {
    enum algoName = "NR";
    enum format = DLGroup.ANSI_X9_42;
    enum msgParts = 2;

    /*
    * Check Private Nyberg-Rueppel Parameters
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
* Nyberg-Rueppel Public Key
*/
struct NRPublicKey
{
public:
    alias Options = NROptions;
    __gshared immutable string algoName = Options.algoName;

    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits) 
    {
        m_pub = new DLSchemePublicKey(Options(), alg_id, key_bits);
    }

    /*
    * NRPublicKey Constructor
    */
    this(DLGroup grp, BigInt y1)
    {
        m_pub = new DLSchemePublicKey(Options(), grp.move, y1.move);
    }

    this(PublicKey pkey) { m_pub = cast(DLSchemePublicKey) pkey; }
    this(PrivateKey pkey) { m_pub = cast(DLSchemePublicKey) pkey; }

    mixin Embed!m_pub;

    DLSchemePublicKey m_pub;
}

/**
* Nyberg-Rueppel Private Key
*/
struct NRPrivateKey
{
public:
    alias Options = NROptions;
    __gshared immutable string algoName = Options.algoName;

    /*
    * Create a NR private key
    */
    this(RandomNumberGenerator rng, DLGroup grp, BigInt x_arg = 0)
    {
        bool x_arg_0;
        if (x_arg == 0) {
            x_arg_0 = true;
            auto bi = BigInt(2);
            x_arg = BigInt.randomInteger(rng, bi, grp.getQ() - 1);
        }
        BigInt y1 = powerMod(grp.getG(), x_arg, grp.getP());

        m_priv = new DLSchemePrivateKey(Options(), grp.move, y1.move, x_arg.move);

        if (x_arg_0)
            m_priv.genCheck(rng);
        else
            m_priv.loadCheck(rng);
    }

    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits, RandomNumberGenerator rng)
    { 
        m_priv = new DLSchemePrivateKey(Options(), alg_id, key_bits);
       
        m_priv.setY(powerMod(m_priv.groupG(), m_priv.m_x, m_priv.groupP()));
        
        m_priv.loadCheck(rng);
    }

    mixin Embed!m_priv;

    DLSchemePrivateKey m_priv;

}

/**
* Nyberg-Rueppel signature operation
*/
final class NRSignatureOperation : Signature
{
public:
    override size_t messageParts() const { return 2; }
    override size_t messagePartSize() const { return m_q.bytes(); }
    override size_t maxInputBits() const { return (m_q.bits() - 1); }

    this(in PrivateKey pkey) {
        this(cast(DLSchemePrivateKey) pkey);
    }

    this(in NRPrivateKey pkey) {
        this(pkey.m_priv);
    }

    this(in DLSchemePrivateKey nr)
    {
        assert(nr.algoName == NRPublicKey.algoName);
        m_q = &nr.groupQ();
        m_x = &nr.getX();
        m_powermod_g_p = FixedBasePowerMod(nr.groupG(), nr.groupP());
        m_mod_q = ModularReducer(nr.groupQ());
    }

    override SecureVector!ubyte sign(const(ubyte)* msg, size_t msg_len, RandomNumberGenerator rng)
    {
        rng.addEntropy(msg, msg_len);
        
        BigInt f = BigInt(msg, msg_len);
        
        if (f >= *m_q)
            throw new InvalidArgument("NR_Signature_Operation: Input is out of range");
        
        BigInt c, d;
        
        while (c == 0)
        {
            BigInt k;
            do
                k.randomize(rng, m_q.bits());
            while (k >= *m_q);
            
            c = m_mod_q.reduce((*m_powermod_g_p)(k) + f);
            d = m_mod_q.reduce(k - (*m_x) * c);
        }
        
        SecureVector!ubyte output = SecureVector!ubyte(2*m_q.bytes());
        c.binaryEncode(&output[output.length / 2 - c.bytes()]);
        d.binaryEncode(&output[output.length - d.bytes()]);
        return output;
    }
private:
    const BigInt* m_q;
    const BigInt* m_x;
    FixedBasePowerMod m_powermod_g_p;
    ModularReducer m_mod_q;
}

/**
* Nyberg-Rueppel verification operation
*/
final class NRVerificationOperation : Verification
{
public:
    this(in PublicKey pkey) {
        this(cast(DLSchemePublicKey) pkey);
    }

    this(in NRPublicKey pkey) {
        this(pkey.m_pub);
    }

    this(in DLSchemePublicKey nr) 
    {
        assert(nr.algoName == NRPublicKey.algoName);
        m_q = &nr.groupQ();
        m_y = &nr.getY();
        m_p = &nr.groupP();
        m_powermod_g_p = FixedBasePowerMod(nr.groupG(), nr.groupP());
        m_mod_p = ModularReducer(nr.groupP());
        m_mod_q = ModularReducer(nr.groupQ());
    }

    override size_t messageParts() const { return 2; }
    override size_t messagePartSize() const { return m_q.bytes(); }
    override size_t maxInputBits() const { return (m_q.bits() - 1); }

    override bool withRecovery() const { return true; }

    override bool verify(const(ubyte)*, size_t, const(ubyte)*, size_t)
    {
        throw new InvalidState("Message recovery required");
    }

    override SecureVector!ubyte verifyMr(const(ubyte)* msg, size_t msg_len)
    {
        const BigInt* q = &m_mod_q.getModulus(); // TODO: why not use m_q?
        if (msg_len != 2*q.bytes())
            throw new InvalidArgument("NR verification: Invalid signature");
        
        BigInt c = BigInt(msg, q.bytes());
        BigInt d = BigInt(msg + q.bytes(), q.bytes());
        
        if (c.isZero() || c >= *q || d >= *q)
            throw new InvalidArgument("NR verification: Invalid signature");
        import std.concurrency : spawn, receiveOnly, send, thisTid;

        BigInt res;
        auto tid = spawn(
            (shared(Tid) tid, shared(const BigInt*) y, shared(const BigInt*) p, shared(BigInt*) c2, shared(BigInt*) res2) 
            { 
                import botan.libstate.libstate : modexpInit;
                modexpInit(); // enable quick path for powermod
                BigInt* ret = cast(BigInt*) res2;
                {
                    auto powermod_y_p = FixedBasePowerMod(*cast(const BigInt*)y, *cast(const BigInt*)p);
                    *ret = (*powermod_y_p)(*cast(BigInt*)c2);
                    send(cast(Tid) tid, true);
                }
                auto done = receiveOnly!bool;
                destroy(*ret);
                send(cast(Tid)tid, true); 
            }, 
            cast(shared)thisTid, cast(shared)m_y, cast(shared)m_p, cast(shared)&c, cast(shared)&res 
            );
        BigInt g_d = (*m_powermod_g_p)(d);
        bool done = receiveOnly!bool();
        BigInt i = m_mod_p.multiply(g_d, res);

        send(cast(Tid)tid, true);
        auto ret = BigInt.encodeLocked(m_mod_q.reduce(c - i));
        done = receiveOnly!bool;
        return ret;
    }
private:
    const BigInt* m_q;
    const BigInt* m_y;
    const BigInt* m_p;

    FixedBasePowerMod m_powermod_g_p;
    ModularReducer m_mod_p, m_mod_q;
}


static if (BOTAN_TEST):

import botan.test;
import botan.pubkey.test;
import botan.pubkey.pubkey;
import botan.codec.hex;
import botan.rng.auto_rng;
import core.atomic;
import memutils.hashmap;

private shared size_t total_tests;

size_t testPkKeygen(RandomNumberGenerator rng)
{    
    size_t fails;
    string[] nr_list = ["dsa/jce/1024", "dsa/botan/2048", "dsa/botan/3072"];

    foreach (nr; nr_list) {
        atomicOp!"+="(total_tests, 1);
        auto key = NRPrivateKey(rng, DLGroup(nr));
        key.checkKey(rng, true);
        fails += validateSaveAndLoad(key, rng);
    }
    
    return fails;
}

size_t nrSigKat(string p, string q, string g, string x, 
                  string hash, string msg, string nonce, string signature)
{
    //logTrace("msg: ", msg);
    atomicOp!"+="(total_tests, 1);
    auto rng = AutoSeededRNG();
    
    BigInt p_bn = BigInt(p);
    BigInt q_bn = BigInt(q);
    BigInt g_bn = BigInt(g);
    BigInt x_bn = BigInt(x);
    
    DLGroup group = DLGroup(p_bn, q_bn, g_bn);

    auto privkey = NRPrivateKey(rng, group.move(), x_bn.move());
    auto pubkey = NRPublicKey(privkey);
    
    const string padding = "EMSA1(" ~ hash ~ ")";
    
    PKVerifier verify = PKVerifier(pubkey, padding);
    PKSigner sign = PKSigner(privkey, padding);
    
    return validateSignature(verify, sign, "nr/" ~ hash, msg, rng, nonce, signature);
}

static if (!SKIP_NR_TEST) unittest
{
    logDebug("Testing nr.d ...");
    size_t fails = 0;
    
    auto rng = AutoSeededRNG();
    
    File nr_sig = File("../test_data/pubkey/nr.vec", "r");
    
    fails += runTestsBb(nr_sig, "NR Signature", "Signature", true,
        (ref HashMap!(string, string) m) {
            return nrSigKat(m["P"], m["Q"], m["G"], m["X"], m["Hash"], m["Msg"], m["Nonce"], m["Signature"]);
        });

    fails += testPkKeygen(rng);
    
    testReport("nr", total_tests, fails);
}