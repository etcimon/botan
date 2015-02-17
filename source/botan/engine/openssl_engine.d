/**
* OpenSSL Engine
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.engine.openssl_engine;

import botan.constants;
static if (BOTAN_HAS_ENGINE_OPENSSL):

pragma(msg, "OpenSSL engine was enabled, so it is allowable to disable native public key encryption.");

import botan.engine.engine;
import botan.pubkey.pk_keys;
import botan.rng.rng;
import botan.block.block_cipher;
import botan.math.bigint.bigint;
import botan.utils.parsing;
import deimos.openssl.rc4;
import deimos.openssl.evp;

static if (BOTAN_HAS_RSA)  import botan.pubkey.algo.rsa;
static if (BOTAN_HAS_DSA)  import botan.pubkey.algo.dsa;
static if (BOTAN_HAS_ECDSA) {
    import botan.pubkey.algo.ecdsa;
    import openssl.ecdsa;
}
static if (BOTAN_HAS_DIFFIE_HELLMAN) import botan.pubkey.algo.dh;

/**
* OpenSSL Engine
*/
final class OpenSSLEngine : Engine
{
public:
    string providerName() const { return "openssl"; }

    KeyAgreement getKeyAgreementOp(in PrivateKey key, RandomNumberGenerator) const
    {
        static if (BOTAN_HAS_DIFFIE_HELLMAN) {
            if (DHPrivateKey.algoName == key.algoName)
                return new OSSLDHKAOperation(key);
        }
        
        return 0;
    }

    Signature getSignatureOp(in PrivateKey key, RandomNumberGenerator) const
    {
        static if (BOTAN_HAS_RSA) {
            if (RSAPrivateKey.algoName == key.algoName)
                return new OSSLRSAPrivateOperation(key);
        }
        
        static if (BOTAN_HAS_DSA) {
            if (DSAPrivateKey.algoName == key.algoName)
                return new OSSLDSASignatureOperation(key);
        }
        
        return 0;
    }

    Verification getVerifyOp(in PublicKey key, RandomNumberGenerator) const
    {
        static if (BOTAN_HAS_RSA) {
            if (RSAPublicKey.algoName == key.algoName)
                return new OSSLRSAPublicOperation(key);
        }
        
        static if (BOTAN_HAS_DSA) {
            if (DSAPublicKey.algoName == key.algoName)
                return new OSSLDSAVerificationOperation(key);
        }
        
        return 0;
    }

    Encryption getEncryptionOp(in PublicKey key, RandomNumberGenerator) const
    {
        static if (BOTAN_HAS_RSA) {
            if (RSAPublicKey.algoName == key.algoName)
                return new OSSLRSAPublicOperation(key);
        }
        
        return 0;
    }

    Decryption getDecryptionOp(in PrivateKey key, RandomNumberGenerator) const
    {
        static if (BOTAN_HAS_RSA) {
            if (RSAPrivateKey.algoName == key.algoName)
                return new OSSLRSAPrivateOperation(key);
        }
        
        return 0;
    }

    /*
    * Return the OpenSSL-based modular exponentiator
    */
    ModularExponentiator modExp(const ref BigInt n, PowerMod.UsageHints) const
    {
        return new OpenSSLModularExponentiator(n);
    }


    /*
    * Look for an algorithm with this name
    */
    BlockCipher findBlockCipher(in SCANToken request, AlgorithmFactory af) const
    {
        
        static if (!BOTAN_HAS_OPENSSL_NO_SHA) {
            /*
            Using OpenSSL's AES causes crashes inside EVP on x86-64 with OpenSSL 0.9.8g
            cause is unknown
            */
            mixin(HANDLE_EVP_CIPHER!("AES-128", EVPaes128ecb)());
            mixin(HANDLE_EVP_CIPHER!("AES-192", EVPaes192ecb)());
            mixin(HANDLE_EVP_CIPHER!("AES-256", EVPaes256ecb)());
        }

        static if (!BOTAN_HAS_OPENSSL_NO_DES) {
            mixin(HANDLE_EVP_CIPHER!("DES", EVP_des_ecb())());
            mixin(HANDLE_EVP_CIPHER_KEYLEN!("TripleDES", EVPdesede3ecb, 16, 24, 8)());
        }
        
        static if (!BOTAN_HAS_OPENSSL_NO_BF) {
            HANDLE_EVP_CIPHER_KEYLEN("Blowfish", EVP_bf_ecb, 1, 56, 1);
        }
        
        static if (!BOTAN_HAS_OPENSSL_NO_CAST) {
            HANDLE_EVP_CIPHER_KEYLEN("Cast-128", EVP_cast5_ecb, 1, 16, 1);
        }

        static if (!BOTAN_HAS_OPENSSL_NO_CAMELLIA) {
            HANDLE_EVP_CIPHER("Camellia-128", EVP_camellia_128_ecb);
            HANDLE_EVP_CIPHER("Camellia-192", EVP_camellia_192_ecb);
            HANDLE_EVP_CIPHER("Camellia-256", EVP_camellia_256_ecb);
        }
        
        static if (!BOTAN_HAS_OPENSSL_NO_RC2) {
            HANDLE_EVP_CIPHER_KEYLEN("RC2", EVP_rc2_ecb, 1, 32, 1);
        }
        
        static if (!BOTAN_HAS_OPENSSL_NO_RC5) {
            /*
            if (request.algoName == "RC5")
                if (request.argAsInteger(0, 12) == 12)
                    return new EVP_BlockCipher(EVP_rc5_32_12_16_ecb,
                                               "RC5(12)", 1, 32, 1);
            */
        }
        
        static if (!BOTAN_HAS_OPENSSL_NO_IDEA) {
            // HANDLE_EVP_CIPHER("IDEA", EVP_idea_ecb);
        }
        
        static if (!BOTAN_HAS_OPENSSL_NO_SEED) {
            HANDLE_EVP_CIPHER("SEED", EVP_seed_ecb);
        }
        
        return 0;
    }

    /**
    * Look for an OpenSSL-supported stream cipher (RC4)
    */
    StreamCipher findStreamCipher(in SCANToken request,
                                    AlgorithmFactory) const
    {
        if (request.algoName == "RC4")
            return new RC4OpenSSL(request.argAsInteger(0, 0));
        if (request.algoName == "RC4_drop")
            return new RC4OpenSSL(768);
        
        return 0;
    }


    /*
    * Look for an algorithm with this name
    */
    HashFunction findHash(in SCANToken request,
                           AlgorithmFactory af) const
    {
        static if (!BOTAN_HAS_OPENSSL_NO_SHA) {
            if (request.algoName == "SHA-160")
                return new EVPHashFunction(EVP_sha1(), "SHA-160");
        }
        
        static if (!BOTAN_HAS_OPENSSL_NO_SHA256) {
            if (request.algoName == "SHA-224")
                return new EVPHashFunction(EVP_sha224(), "SHA-224");
            if (request.algoName == "SHA-256")
                return new EVPHashFunction(EVP_sha256(), "SHA-256");
        }
        
        static if (!BOTAN_HAS_OPENSSL_NO_SHA512) {
            if (request.algoName == "SHA-384")
                return new EVPHashFunction(EVP_sha384(), "SHA-384");
            if (request.algoName == "SHA-512")
                return new EVPHashFunction(EVP_sha512(), "SHA-512");
        }
        
        static if (!BOTAN_HAS_OPENSSL_NO_MD2) {
            if (request.algoName == "MD2")
                return new EVPHashFunction(EVP_md2(), "MD2");
        }
        
        static if (!BOTAN_HAS_OPENSSL_NO_MD4) {
            if (request.algoName == "MD4")
                return new EVPHashFunction(EVP_md4(), "MD4");
        }
        
        static if (!BOTAN_HAS_OPENSSL_NO_MD5) {
            if (request.algoName == "MD5")
                return new EVPHashFunction(EVP_md5(), "MD5");
        }
        
        static if (!BOTAN_HAS_OPENSSL_NO_RIPEMD) {
            if (request.algoName == "RIPEMD-160")
                return new EVPHashFunction(EVP_ripemd160(), "RIPEMD-160");
        }
        
        return 0;
    }
}

package:

/*
* OpenSSL Modular Exponentiator
*/
final class OpenSSLModularExponentiator : ModularExponentiator
{
public:
    void setBase(const ref BigInt b) { m_base = b; }
    
    void setExponent(const ref BigInt e) { m_exp = e; }
    
    BigInt execute() const
    {
        OSSL_BN r;
        BN_mod_exp(r.ptr(), m_base.ptr(), m_exp.ptr(), m_mod.ptr(), m_ctx.ptr());
        return r.toBigint();
    }
    
    ModularExponentiator copy() const
    { 
        return new OpenSSLModularExponentiator(this); 
    }
    
    this(const ref BigInt n) {
        m_mod = n;
    }
private:
    OSSL_BN m_base, m_exp, m_mod;
    OSSL_BN_CTX m_ctx;
}

import openssl.bn;
/**
* Lightweight OpenSSL BN wrapper. For internal use only.
*/
struct OSSLBN
{
public:
    /*
    * OpenSSL to BigInt Conversions
    */
    BigInt toBigint() const
    {
        SecureVector!ubyte output = SecureVector!ubyte(bytes());
        BN_bn2bin(m_bn, output.ptr);
        return BigInt.decode(output);
    }
    
    /*
    * Export the BIGNUM as a bytestring
    */
    void encode(ubyte* output) const
    {
        size_t length = output.length;
        BN_bn2bin(m_bn, output.ptr + (length - bytes()));
    }
    
    /*
    * Return the number of significant bytes
    */
    size_t bytes() const
    {
        return BN_num_bytes(m_bn);
    }
    
    
    SecureVector!ubyte toBytes() const
    { 
        return BigInt.encodeLocked(toBigint()); 
    }
    
    OSSLBN opAssign(in OSSLBN other)
    {
        BN_copy(m_bn, other.m_bn);
        return this;
    }
    
    /*
    * OSSL_BN Constructor
    */
    this(const ref BigInt input = 0)
    {
        m_bn = BN_new();
        SecureVector!ubyte encoding = BigInt.encodeLocked(input);
        if (input != 0)
            BN_bin2bn(encoding.ptr, encoding.length, m_bn);
    }
    
    /*
    * OSSL_BN Constructor
    */
    this(const(ubyte)* input, size_t length)
    {
        m_bn = BN_new();
        BN_bin2bn(input, length, m_bn);
    }
    
    /*
    * OSSL_BN Copy Constructor
    */
    this(in OSSLBN other)
    {
        m_bn = BN_dup(other.m_bn);
    }
    
    this(in OSSLBN);
    
    /*
    * OSSL_BN Destructor
    */
    ~this()
    {
        BN_clear_free(m_bn);
    }
    
    
    BIGNUM* ptr() const { return m_bn; }
private:
    BIGNUM* m_bn;
}

/**
* Lightweight OpenSSL BN_CTX wrapper. For internal use only.
*/
struct OSSLBNCTX
{
public:
    OSSLBNCTX opAssign(in OSSLBNCTX bn)
    {
        m_ctx = bn.m_ctx;
        return this;
    }
    
    this(BNCTX* ctx = null)
    {
        if (ctx)
            m_ctx = ctx;
        else
            m_ctx = BN_CTX_new();
    }

    this(in OSSLBNCTX bn)
    {
        m_ctx = bn.m_ctx;
    }
    
    ~this()
    {
        BN_CTX_free(m_ctx);
    }
    
    BNCTX* ptr() const { return m_ctx; }
    
private:
    BN_CTX* m_ctx;
}


package:

/**
* RC4 as implemented by OpenSSL
*/
final class RC4OpenSSL : StreamCipher
{
public:
    void clear() { clearMem(&m_state, 1); }
    
    /*
    * Return the name of this type
    */
    @property string name() const
    {
        if (SKIP == 0)        return "RC4";
        if (SKIP == 256)      return "MARK-4";
        else                  return "RC4_skip(" ~ to!string(m_SKIP) ~ ")";
    }
    
    StreamCipher clone() const { return new RC4OpenSSL(m_SKIP); }
    
    KeyLengthSpecification keySpec() const
    {
        return KeyLengthSpecification(1, 32);
    }        
    
    this(size_t s = 0) { m_SKIP = s; clear(); }
    
    ~this() { clear(); }
protected:
    /*
    * RC4 Encryption
    */
    void cipher(const(ubyte)* input, ubyte* output, size_t length)
    {
        RC4(&m_state, length, input, output);
    }
    
    /*
    * RC4 Key Schedule
    */
    override void keySchedule(const(ubyte)* key, size_t length)
    {
        RC4_set_key(&m_state, length, key);
        ubyte dummy = 0;
        foreach (size_t i; 0 .. m_SKIP)
            RC4(&m_state, 1, &dummy, &dummy);
    }
    
    const size_t m_SKIP;
    RC4_KEY m_state;
}

/*
* EVP Block Cipher
*/
final class EVPBlockCipher : BlockCipher, SymmetricAlgorithm
{
public:
    /*
    * Clear memory of sensitive data
    */
    void clear()
    {
        const EVP_CIPHER* algo = EVP_CIPHER_CTX_cipher(&m_encrypt);
        
        EVP_CIPHER_CTX_cleanup(&m_encrypt);
        EVP_CIPHER_CTX_cleanup(&m_decrypt);
        EVP_CIPHER_CTX_init(&m_encrypt);
        EVP_CIPHER_CTX_init(&m_decrypt);
        EVP_EncryptInit_ex(&m_encrypt, algo, 0, 0, 0);
        EVP_DecryptInit_ex(&m_decrypt, algo, 0, 0, 0);
        EVP_CIPHER_CTX_set_padding(&m_encrypt, 0);
        EVP_CIPHER_CTX_set_padding(&m_decrypt, 0);
    }
    
    @property string name() const { return m_cipher_name; }
    /*
    * Return a clone of this object
    */
    BlockCipher clone() const
    {
        return new EVPBlockCipher(EVP_CIPHER_CTX_cipher(&m_encrypt),
                                   m_cipher_name,
                                   m_cipher_key_spec.minimumKeylength(),
                                   m_cipher_key_spec.maximumKeylength(),
                                   m_cipher_key_spec.keylengthMultiple());
    }
    
    @property size_t blockSize() const { return m_block_sz; }
    /*
    * EVP Block Cipher Constructor
    */
    this(const EVPCIPHER* algo,
         in string algo_name)
    {
        m_block_sz = EVP_CIPHER_block_size(algo);
        m_cipher_key_spec = EVP_CIPHER_key_length(algo);
        m_cipher_name = algo_name;
        if (EVP_CIPHER_mode(algo) != EVP_CIPH_ECB_MODE)
            throw new InvalidArgument("EVP_BlockCipher: Non-ECB EVP was passed in");
        
        EVP_CIPHER_CTX_init(&m_encrypt);
        EVP_CIPHER_CTX_init(&m_decrypt);
        
        EVP_EncryptInit_ex(&m_encrypt, algo, 0, 0, 0);
        EVP_DecryptInit_ex(&m_decrypt, algo, 0, 0, 0);
        
        EVP_CIPHER_CTX_set_padding(&m_encrypt, 0);
        EVP_CIPHER_CTX_set_padding(&m_decrypt, 0);
    }
    
    
    /*
    * EVP Block Cipher Constructor
    */
    this(const EVPCIPHER* algo,
         in string algo_name,
         size_t key_min, size_t key_max,
         size_t key_mod) 
    {
        m_block_sz = EVP_CIPHER_block_size(algo);
        m_cipher_key_spec = KeyLengthSpecification(key_min, key_max, key_mod);
        m_cipher_name = algo_name;
        if (EVP_CIPHER_mode(algo) != EVP_CIPH_ECB_MODE)
            throw new InvalidArgument("EVP_BlockCipher: Non-ECB EVP was passed in");
        
        EVP_CIPHER_CTX_init(&m_encrypt);
        EVP_CIPHER_CTX_init(&m_decrypt);
        
        EVP_EncryptInit_ex(&m_encrypt, algo, 0, 0, 0);
        EVP_DecryptInit_ex(&m_decrypt, algo, 0, 0, 0);
        
        EVP_CIPHER_CTX_set_padding(&m_encrypt, 0);
        EVP_CIPHER_CTX_set_padding(&m_decrypt, 0);
    }
    
    
    KeyLengthSpecification keySpec() const { return m_cipher_key_spec; }
    
    /*
    * EVP Block Cipher Destructor
    */
    ~this()
    {
        EVP_CIPHER_CTX_cleanup(&m_encrypt);
        EVP_CIPHER_CTX_cleanup(&m_decrypt);
    }
protected:
    /*
    * Encrypt a block
    */
    void encryptN(const(ubyte)* input, ubyte* output,
                   size_t blocks) const
    {
        int out_len = 0;
        EVP_EncryptUpdate(&m_encrypt, output, &out_len, input, blocks * m_block_sz);
    }
    
    /*
    * Decrypt a block
    */
    void decryptN(const(ubyte)* input, ubyte* output,
                   size_t blocks) const
    {
        int out_len = 0;
        EVP_DecryptUpdate(&m_decrypt, output, &out_len, input, blocks * m_block_sz);
    }
    
    /*
    * Set the key
    */
    override void keySchedule(const(ubyte)* key, size_t length)
    {
        SecureVector!ubyte full_key = SecureVector!ubyte(key, key + length);
        
        if (m_cipher_name == "TripleDES" && length == 16)
        {
            full_key ~= key[0 .. 8];
        }
        else
            if (EVP_CIPHER_CTX_set_key_length(&m_encrypt, length) == 0 ||
                EVP_CIPHER_CTX_set_key_length(&m_decrypt, length) == 0)
                throw new InvalidArgument("EVP_BlockCipher: Bad key length for " ~
                                           cipher_name);
        
        if (m_cipher_name == "RC2")
        {
            EVP_CIPHER_CTX_ctrl(&m_encrypt, EVP_CTRL_SET_RC2_KEY_BITS, length*8, 0);
            EVP_CIPHER_CTX_ctrl(&m_decrypt, EVP_CTRL_SET_RC2_KEY_BITS, length*8, 0);
        }
        
        EVP_EncryptInit_ex(&m_encrypt, 0, 0, full_key.ptr, 0);
        EVP_DecryptInit_ex(&m_decrypt, 0, 0, full_key.ptr, 0);
    }
    
    size_t m_block_sz;
    KeyLengthSpecification m_cipher_key_spec;
    string m_cipher_name;
    EVP_CIPHER_CTX m_encrypt, m_decrypt;
}


string HANDLE_EVP_CIPHER(string NAME, alias EVP)()
{
    return `if (request.algoName == ` ~ NAME ~ ` && request.argCount() == 0)
                return new EVPBlockCipher(` ~ __traits(identifier, EVP).stringof ~ `(), ` ~ NAME ~ `);`;
}


string HANDLE_EVP_CIPHER_KEYLEN(string NAME, alias EVP, ubyte MIN, ubyte MAX, ubyte MOD)() {
    return `if (request.algoName == ` ~ NAME ~ ` && request.argCount() == 0)
                return new EVPBlockCipher(` ~ __traits(identifier, EVP).stringof ~ `(), ` ~ 
        NAME ~ `, ` ~ MIN.stringof ~ `, ` ~ MAX.stringof ~ `, ` ~ MOD.stringof ~ `);`;
}

/*
* EVP Hash Function
*/
final class EVPHashFunction : HashFunction
{
public:
    /*
    * Clear memory of sensitive data
    */
    void clear()
    {
        const EVP_MD* algo = EVP_MD_CTX_md(&m_md);
        EVP_DigestInit_ex(&m_md, algo, 0);
    }
    
    @property string name() const { return m_algo_name; }
    /*
    * Return a clone of this object
    */
    HashFunction clone() const
    {
        const EVP_MD* algo = EVP_MD_CTX_md(&m_md);
        return new EVPHashFunction(algo, name);
    }
    
    @property size_t outputLength() const
    {
        return EVP_MD_size(EVP_MD_CTX_md(&m_md));
    }
    
    @property size_t hashBlockSize() const
    {
        return EVP_MD_block_size(EVP_MD_CTX_md(&m_md));
    }
    /*
    * Create an EVP hash function
    */
    this(const EVPMD* algo,
         in string name)
    {
        m_algo_name = name;
        EVP_MD_CTX_init(&m_md);
        EVP_DigestInit_ex(&m_md, algo, 0);
    }
    /*
    * Destroy an EVP hash function
    */
    ~this()
    {
        EVP_MD_CTX_cleanup(&m_md);
    }
    
protected:
    
    /*
    * Update an EVP Hash Calculation
    */
    override void addData(const(ubyte)* input, size_t length)
    {
        EVP_DigestUpdate(&m_md, input, length);
    }
    /*
    * Finalize an EVP Hash Calculation
    */
    override void finalResult(ubyte* output)
    {
        EVP_DigestFinal_ex(&m_md, output, 0);
        const EVP_MD* algo = EVP_MD_CTX_md(&m_md);
        EVP_DigestInit_ex(&m_md, algo, 0);
    }
    
    string m_algo_name;
    EVP_MD_CTX m_md;
}



package:

static if (BOTAN_HAS_DIFFIE_HELLMAN) {
    final class OSSLDHKAOperation : KeyAgreement
    {
    public:
        this(in PrivateKey pkey) {
            this(cast(DLSchemePrivateKey) pkey);
        }

        this(in DHPrivateKey pkey) {
            this(pkey);
        }

        this(in DLSchemePrivateKey dh) 
        {
            assert(dh.algoName == DHPublicKey.algoName);
            m_x = dh.getX();
            m_p = dh.groupP();
        }
        
        SecureVector!ubyte agree(const(ubyte)* w, size_t w_len)
        {
            OSSL_BN i = OSSL_BN(w, w_len);
            OSSL_BN r;
            BN_mod_exp(r.ptr(), i.ptr(), m_x.ptr(), m_p.ptr(), m_ctx.ptr());
            return r.toBytes();
        }
        
    private:
        const OSSL_BN m_x, m_p;
        OSSL_BN_CTX m_ctx;
    }
}

static if (BOTAN_HAS_DSA) {
    
    final class OSSLDSASignatureOperation : Signature
    {
    public:
        this(in PrivateKey pkey) {
            this(cast(DLSchemePrivateKey) pkey);
        }

        this(in DSAPrivateKey pkey) {
            this(pkey);
        }

        this(in DLSchemePrivateKey dsa) 
        {
            assert(dsa.algoName == DSAPublicKey.algoName);
            m_x = dsa.getX();
            m_p = dsa.groupP();
            m_q = dsa.groupQ();
            m_g = dsa.groupG();
            m_q_bits = dsa.groupQ().bits();
        }
        
        size_t messageParts() const { return 2; }
        size_t messagePartSize() const { return (m_q_bits + 7) / 8; }
        size_t maxInputBits() const { return m_q_bits; }

        SecureVector!ubyte sign(const(ubyte)* msg, size_t msg_len, RandomNumberGenerator rng)
        {
            const size_t q_bytes = (m_q_bits + 7) / 8;
            
            rng.addEntropy(msg, msg_len);
            
            BigInt k_bn;
            do
                k_bn.randomize(rng, m_q_bits);
            while (k_bn >= m_q.toBigint());
            
            OSSL_BN i = OSSL_BN(msg, msg_len);
            OSSL_BN k = OSSL_BN(k_bn);
            
            OSSL_BN r;
            BN_mod_exp(r.ptr(), m_g.ptr(), k.ptr(), m_p.ptr(), m_ctx.ptr());
            BN_nnmod(r.ptr(), r.ptr(), m_q.ptr(), m_ctx.ptr());
            
            BN_mod_inverse(k.ptr(), k.ptr(), m_q.ptr(), m_ctx.ptr());
            
            OSSL_BN s;
            BN_mul(s.ptr(), m_x.ptr(), r.ptr(), m_ctx.ptr());
            BN_add(s.ptr(), s.ptr(), i.ptr());
            BN_mod_mul(s.ptr(), s.ptr(), k.ptr(), m_q.ptr(), m_ctx.ptr());
            
            if (BN_is_zero(r.ptr()) || BN_is_zero(s.ptr()))
                throw new InternalError("OpenSSL_DSA_Op::sign: r or s was zero");
            
            SecureVector!ubyte output = SecureVector!ubyte(2*q_bytes);
            r.encode(output.ptr, q_bytes);
            s.encode(&output[q_bytes], q_bytes);
            return output;
        }
        
    private:
        const OSSL_BN m_x, m_p, m_q, m_g;
        const OSSL_BN_CTX m_ctx;
        size_t m_q_bits;
    }
    
    
    final class OSSLDSAVerificationOperation : Verification
    {
    public:
        this(in PublicKey pkey) {
            this(cast(DLSchemePublicKey) pkey);
        }

        this(in DSAPublicKey pkey) {
            this(pkey);
        }

        this(in DLSchemePublicKey dsa)
        {
            assert(dsa.algoName == DSAPublicKey.algoName);
            m_y = dsa.getY();
            m_p = dsa.groupP();
            m_q = dsa.groupQ();
            m_g = dsa.groupG();
            m_q_bits = dsa.groupQ().bits();
        }
        
        size_t messageParts() const { return 2; }
        size_t messagePartSize() const { return (m_q_bits + 7) / 8; }
        size_t maxInputBits() const { return m_q_bits; }
        
        bool withRecovery() const { return false; }
        
        bool verify(const(ubyte)* msg, size_t msg_len,
                    const(ubyte)* sig, size_t sig_len)
        {
            const size_t q_bytes = m_q.bytes();
            
            if (sig_len != 2*q_bytes || msg_len > q_bytes)
                return false;
            
            OSSL_BN r = OSSL_BN(sig, q_bytes);
            OSSL_BN s = OSSL_BN(sig + q_bytes, q_bytes);
            OSSL_BN i = OSSL_BN(msg, msg_len);
            
            if (BN_is_zero(r.ptr()) || BN_cmp(r.ptr(), m_q.ptr()) >= 0)
                return false;
            if (BN_is_zero(s.ptr()) || BN_cmp(s.ptr(), m_q.ptr()) >= 0)
                return false;
            
            if (BN_mod_inverse(s.ptr(), s.ptr(), m_q.ptr(), m_ctx.ptr()) == 0)
                return false;
            
            OSSL_BN si;
            BN_mod_mul(si.ptr(), s.ptr(), i.ptr(), m_q.ptr(), m_ctx.ptr());
            BN_mod_exp(si.ptr(), m_g.ptr(), si.ptr(), m_p.ptr(), m_ctx.ptr());
            
            OSSL_BN sr;
            BN_mod_mul(sr.ptr(), s.ptr(), r.ptr(), m_q.ptr(), m_ctx.ptr());
            BN_mod_exp(sr.ptr(), m_y.ptr(), sr.ptr(), m_p.ptr(), m_ctx.ptr());
            
            BN_mod_mul(si.ptr(), si.ptr(), sr.ptr(), m_p.ptr(), m_ctx.ptr());
            BN_nnmod(si.ptr(), si.ptr(), m_q.ptr(), m_ctx.ptr());
            
            if (BN_cmp(si.ptr(), r.ptr()) == 0)
                return true;
            return false;
        }
        
    private:
        const OSSL_BN m_y, m_p, m_q, m_g;
        const OSSL_BN_CTX m_ctx;
        size_t m_q_bits;
    }
    
    
    static if (BOTAN_HAS_RSA) {
        
        final class OSSLRSAPrivateOperation : Signature, Decryption
        {
        public:
            this(in PrivateKey pkey) {
                this(cast(IFSchemePrivateKey) pkey);
            }

            this(in RSAPrivateKey pkey) {
                this(pkey);
            }

            this(in IFSchemePrivateKey rsa)
            {
                assert(rsa.algoName == RSAPublicKey.algoName);
                m_mod = rsa.getN();
                m_p = rsa.getP();
                m_q = rsa.getQ();
                m_d1 = rsa.getD1();
                m_d2 = rsa.getD2();
                m_c = rsa.getC();
                m_n_bits = rsa.getN().bits();
            }
            
            size_t maxInputBits() const { return (m_n_bits - 1); }
            
            SecureVector!ubyte sign(const(ubyte)* msg, size_t msg_len, RandomNumberGenerator)
            {
                BigInt m = BigInt(msg, msg_len);
                BigInt x = privateOp(m);
                return BigInt.encode1363(x, (m_n_bits + 7) / 8);
            }
            
            SecureVector!ubyte decrypt(const(ubyte)* msg, size_t msg_len)
            {
                BigInt m = BigInt(msg, msg_len);
                return BigInt.encodeLocked(privateOp(m));
            }
            
        private:
            BigInt privateOp(const ref BigInt m) const
            {
                OSSL_BN j1, j2;
                OSSL_BN h = OSSL_BN(m);
                
                BN_mod_exp(j1.ptr(), h.ptr(), m_d1.ptr(), m_p.ptr(), m_ctx.ptr());
                BN_mod_exp(j2.ptr(), h.ptr(), m_d2.ptr(), m_q.ptr(), m_ctx.ptr());
                BN_sub(h.ptr(), j1.ptr(), j2.ptr());
                BN_mod_mul(h.ptr(), h.ptr(), m_c.ptr(), m_p.ptr(), m_ctx.ptr());
                BN_mul(h.ptr(), h.ptr(), m_q.ptr(), m_ctx.ptr());
                BN_add(h.ptr(), h.ptr(), j2.ptr());
                return h.toBigint();
            }
            
            const OSSL_BN m_mod, m_p, m_q, m_d1, m_d2, m_c;
            const OSSL_BN_CTX m_ctx;
            size_t m_n_bits;
        }
        
        
        final class OSSLRSAPublicOperation : Verification, Encryption
        {
        public:
            this(in PublicKey pkey) {
                this(cast(IFSchemePublicKey) pkey);
            }

            this(in RSAPublicKey pkey) {
                this(pkey);
            }

            this(in IFSchemePublicKey rsa) 
            {
                assert(rsa.algoName == RSAPublicKey.algoName);
                m_n = rsa.getN();
                m_e = rsa.getE();
                m_mod = rsa.getN();
            }
            
            size_t maxInputBits() const { return (m_n.bits() - 1); }
            bool withRecovery() const { return true; }
            
            SecureVector!ubyte encrypt(const(ubyte)* msg, size_t msg_len, RandomNumberGenerator)
            {
                BigInt m = BigInt(msg, msg_len);
                return BigInt.encode1363(publicOp(m), m_n.bytes());
            }
            
            SecureVector!ubyte verifyMr(const(ubyte)* msg, size_t msg_len)
            {
                BigInt m = BigInt(msg, msg_len);
                return BigInt.encodeLocked(publicOp(m));
            }
            
        private:
            BigInt publicOp(const ref BigInt m) const
            {
                if (m >= n)
                    throw new InvalidArgument("RSA public op - input is too large");
                
                OSSL_BN m_bn = OSSL_BN(m), r;
                BN_mod_exp(r.ptr(), m_bn.ptr(), m_e.ptr(), m_mod.ptr(), m_ctx.ptr());
                return r.toBigint();
            }
            
            const BigInt m_n;
            const OSSL_BN m_e, m_mod;
            const OSSL_BN_CTX m_ctx;
        }
        
    }
    
}