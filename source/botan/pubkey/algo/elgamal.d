/**
* ElGamal
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.algo.elgamal;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO && BOTAN_HAS_ELGAMAL):

public import botan.pubkey.pubkey;
import botan.pubkey.algo.dl_algo;
import botan.math.numbertheory.numthry;
import botan.math.numbertheory.reducer;
import botan.pubkey.blinding;
import botan.pubkey.pk_ops;
import botan.pubkey.workfactor;
import botan.math.numbertheory.numthry;
import botan.pubkey.algo.keypair;
import botan.rng.rng;
import botan.utils.types;
import memutils.helpers : Embed;

struct ElGamalOptions {
    enum algoName = "ElGamal";
    enum format = DLGroup.ANSI_X9_42;

    /*
    * Check Private ElGamal Parameters
    */
    static bool checkKey(in DLSchemePrivateKey privkey, RandomNumberGenerator rng, bool strong)
    {
        if (!privkey.checkKeyImpl(rng, strong))
            return false;
        
        if (!strong)
            return true;
        
        return encryptionConsistencyCheck(rng, privkey, "EME1(SHA-1)");
    }

}

/**
* ElGamal Public Key
*/
struct ElGamalPublicKey
{
public:
    alias Options = ElGamalOptions;
    __gshared immutable string algoName = Options.algoName;

    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits)
    {
        m_pub = new DLSchemePublicKey(Options(), alg_id, key_bits);
    }
    /*
    * ElGamalPublicKey Constructor
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
* ElGamal Private Key
*/
struct ElGamalPrivateKey
{
public:
    alias Options = ElGamalOptions;
    __gshared immutable string algoName = Options.algoName;

    /*
    * ElGamalPrivateKey Constructor
    */
    this(RandomNumberGenerator rng, DLGroup grp, BigInt x_arg = 0)
    {    
        bool x_arg_0;
        if (x_arg == 0) {
            x_arg_0 = true;
            x_arg.randomize(rng, 2 * dlWorkFactor(grp.getP().bits()));
        }
        BigInt y1 = powerMod(grp.getG(), x_arg, grp.getP());
        
        m_priv = new DLSchemePrivateKey(Options(), grp.move, y1.move, x_arg.move);

        if (x_arg_0)
            m_priv.genCheck(rng);
        else
            m_priv.loadCheck(rng);

    }

    this(in AlgorithmIdentifier alg_id,
         const ref SecureVector!ubyte key_bits,
         RandomNumberGenerator rng) 
    {
        m_priv = new DLSchemePrivateKey(Options(), alg_id, key_bits);

        m_priv.setY(powerMod(m_priv.groupG(), m_priv.m_x, m_priv.groupP()));
        m_priv.loadCheck(rng);
    }

    this(PrivateKey pkey) { m_priv = cast(DLSchemePrivateKey) pkey; }

    mixin Embed!m_priv;

    DLSchemePrivateKey m_priv;
}

/**
* ElGamal encryption operation
*/
final class ElGamalEncryptionOperation : Encryption
{
public:
    override size_t maxInputBits() const { return m_mod_p.getModulus().bits() - 1; }

    this(in PublicKey pkey) {
        this(cast(DLSchemePublicKey) pkey);
    }

    this(in ElGamalPublicKey pkey) {
        this(pkey.m_pub);
    }

    this(in DLSchemePublicKey key)
    {
        assert(key.algoName == ElGamalPublicKey.algoName);
        const BigInt* p = &key.groupP();
        
        m_powermod_g_p = FixedBasePowerMod(key.groupG(), *p);
        m_powermod_y_p = FixedBasePowerMod(key.getY(), *p);
        m_mod_p = ModularReducer(*p);
    }

    override SecureVector!ubyte encrypt(const(ubyte)* msg, size_t msg_len, RandomNumberGenerator rng)
    {
        const BigInt* p = &m_mod_p.getModulus();
        
        BigInt m = BigInt(msg, msg_len);
        
        if (m >= *p)
            throw new InvalidArgument("ElGamal encryption: Input is too large");

        BigInt k = BigInt(rng, 2 * dlWorkFactor(p.bits()));
        
        BigInt a = (*m_powermod_g_p)(k);
        BigInt b = m_mod_p.multiply(m, (*m_powermod_y_p)(k));
        
        SecureVector!ubyte output = SecureVector!ubyte(2*p.bytes());
        a.binaryEncode(&output[p.bytes() - a.bytes()]);
        b.binaryEncode(&output[output.length / 2 + (p.bytes() - b.bytes())]);
        return output;
    }

private:
    FixedBasePowerMod m_powermod_g_p, m_powermod_y_p;
    ModularReducer m_mod_p;
}

/**
* ElGamal decryption operation
*/
final class ElGamalDecryptionOperation : Decryption
{
public:
    override size_t maxInputBits() const { return m_mod_p.getModulus().bits() - 1; }

    this(in PrivateKey pkey, RandomNumberGenerator rng) {
        this(cast(DLSchemePrivateKey) pkey, rng);
    }

    this(in ElGamalPrivateKey key, RandomNumberGenerator rng)
    {
        this(key.m_priv, rng);
    }

    this(in DLSchemePrivateKey key, RandomNumberGenerator rng)
    {
        assert(key.algoName == ElGamalPublicKey.algoName);
        const BigInt* p = &key.groupP();
        
        m_powermod_x_p = FixedExponentPowerMod(key.getX(), *p);
        m_mod_p = ModularReducer(*p);
        
        BigInt k = BigInt(rng, p.bits() - 1);
        auto d = (*m_powermod_x_p)(k);
        m_blinder = Blinder(k, d, *p);
    }

    override SecureVector!ubyte decrypt(const(ubyte)* msg, size_t msg_len)
    {
        const BigInt* p = &m_mod_p.getModulus();
        
        const size_t p_bytes = p.bytes();
        
        if (msg_len != 2 * p_bytes)
            throw new InvalidArgument("ElGamal decryption: Invalid message");
        
        BigInt a = BigInt(msg, p_bytes);
        BigInt b = BigInt(msg + p_bytes, p_bytes);
        
        if (a >= *p || b >= *p)
            throw new InvalidArgument("ElGamal decryption: Invalid message");
        
        a = m_blinder.blind(a);
        
        BigInt r = m_mod_p.multiply(b, inverseMod((*m_powermod_x_p)(a), *p));
        
        return BigInt.encodeLocked(m_blinder.unblind(r));
    }
private:
    FixedExponentPowerMod m_powermod_x_p;
    ModularReducer m_mod_p;
    Blinder m_blinder;
}

static if (BOTAN_TEST):
import botan.test;
import botan.pubkey.test;
import botan.pubkey.pubkey;
import botan.codec.hex;
import botan.pubkey.algo.dl_group;
import botan.rng.auto_rng;
import core.atomic;
import memutils.hashmap;

private shared size_t total_tests;

size_t testPkKeygen(RandomNumberGenerator rng)
{
    size_t fails;
    
    string[] elg_list = ["modp/ietf/1024", "dsa/jce/1024", "dsa/botan/2048", "dsa/botan/3072"];
    
    foreach (elg; elg_list) {
        atomicOp!"+="(total_tests, 1);
        auto key = ElGamalPrivateKey(rng, DLGroup(elg));
        key.checkKey(rng, true);
        fails += validateSaveAndLoad(key, rng);
    }
    
    return fails;
}

size_t elgamalKat(string p,
                   string g,
                   string x,
                   string msg,
                   string padding,
                   string nonce,
                   string ciphertext)
{
    atomicOp!"+="(total_tests, 1);
    auto rng = AutoSeededRNG();
    
    BigInt p_bn = BigInt(p);
    BigInt g_bn = BigInt(g);
    BigInt x_bn = BigInt(x);
    
    DLGroup group = DLGroup(p_bn, g_bn);
    auto privkey = ElGamalPrivateKey(rng, group.move(), x_bn.move());
    
    auto pubkey = ElGamalPublicKey(privkey);
    
    if (padding == "")
        padding = "Raw";
    
    auto enc = scoped!PKEncryptorEME(pubkey, padding);
    auto dec = scoped!PKDecryptorEME(privkey, padding);
    
    return validateEncryption(enc, dec, "ElGamal/" ~ padding, msg, nonce, ciphertext);
}

static if (!SKIP_ELGAMAL_TEST) unittest
{
    logDebug("Testing elgamal.d ...");
    size_t fails = 0;
    
    auto rng = AutoSeededRNG();
    
    fails += testPkKeygen(rng);
    
    File elgamal_enc = File("../test_data/pubkey/elgamal.vec", "r");
    
    fails += runTestsBb(elgamal_enc, "ElGamal Encryption", "Ciphertext", true,
        (ref HashMap!(string, string) m) {
            return elgamalKat(m["P"], m["G"], m["X"], m["Msg"],
            m["Padding"], m["Nonce"], m["Ciphertext"]);
        });
    
    testReport("elg", total_tests, fails);
}
