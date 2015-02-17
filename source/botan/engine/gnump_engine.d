/**
* GMP Engine
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.engine.gnump_engine;

import botan.constants;

static if (BOTAN_HAS_ENGINE_GNU_MP):

pragma(msg, "GNUMP engine was enabled, so it is allowable to disable native public key encryption.");

import botan.engine.engine;
import core.atomic;
import std.c.string;
import botan.math.bigint.bigint;
import std.c.stdlib;
import std.c.stdio;

/* GnuMP 5.0 and later have a side-channel resistent powm */
version(HAVE_MPZ_POWM_SEC)              alias mpz_powm = mpz_powm_sec;
static if (BOTAN_HAS_RSA)               import botan.pubkey.algo.rsa;
static if (BOTAN_HAS_DSA)               import botan.pubkey.algo.dsa;
static if (BOTAN_HAS_DIFFIE_HELLMAN)    import botan.pubkey.algo.dh;

size_t GNU_MP_VERSION_CODE_FOR(size_t a, size_t b, size_t c) {
    return ((a << 16) | (b << 8) | (c));
}

size_t GNU_MP_VERSION_CODE() {
    return GNU_MP_VERSION_CODE_FOR(__GNU_MP_VERSION, __GNU_MP_VERSION_MINOR, __GNU_MP_VERSION_PATCHLEVEL);
}

static assert (GNU_MP_VERSION_CODE >= GNU_MP_VERSION_CODE_FOR(4,1,0),
               "Your GNU MP install is too old, upgrade to 4.1 or later");

/*
* For keeping track of existing GMP_Engines and only
* resetting the memory when none are in use.
*/
//std::atomic<size_t> gmp_alloc_refcnt(0);
__gshared size_t gmp_alloc_refcnt;

/**
* Engine using GNU MP
*/
final class GMPEngine : Engine
{
public:
    /*
    * GMPEngine Constructor
    */
    this()
    {
        /*
    if (gmp_alloc_refcnt == 0)
        mp_set_memory_functions(gmp_malloc, gmp_realloc, gmp_free);

    gmp_alloc_refcnt++;
    */
    }
    
    ~this()
    {
        /*
    --gmp_alloc_refcnt;

    if (gmp_alloc_refcnt == 0)
        mp_set_memory_functions(NULL, NULL, NULL);
    */
    }


    string providerName() const { return "gmp"; }

    KeyAgreement getKeyAgreementOp(in PrivateKey key, RandomNumberGenerator) const
    {
        static if (BOTAN_HAS_DIFFIE_HELLMAN) {
            if (DHPrivateKey.algoName == key.algoName)
                return new GMP_DH_KA_Operation(key);
        }
        
        return null;
    }

    Signature getSignatureOp(in PrivateKey key, RandomNumberGenerator) const
    {
        static if (BOTAN_HAS_RSA) {
            if (RSAPrivateKey.algoName == key.algoName)
                return new GMPRSAPrivateOperation(key);
        }
        
        static if (BOTAN_HAS_DSA) {
            if (DSAPrivateKey.algoName == key.algoName)
                return new GMPDSASignatureOperation(key);
        }
        
        return null;
    }

    Verification getVerifyOp(in PublicKey key, RandomNumberGenerator) const
    {
        static if (BOTAN_HAS_RSA) {
            if (RSAPublicKey.algoName == key.algoName)
                return new GMPRSAPublicOperation(key);
        }
        
        static if (BOTAN_HAS_DSA) {
            if (DSAPublicKey.algoName == key.algoName)
                return new GMPDSAVerificationOperation(key);
        }
        
        return null;
    }
    
    Encryption getEncryptionOp(in PublicKey key, RandomNumberGenerator) const
    {
        static if (BOTAN_HAS_RSA) {
            if (RSAPublicKey.algoName == key.algoName)
                return new GMPRSAPublicOperation(key);
        }
        
        return null;
    }
    
    Decryption getDecryptionOp(in PrivateKey key, RandomNumberGenerator) const
    {
        static if (BOTAN_HAS_RSA) {
            if (RSAPrivateKey.algoName == key.algoName)
                return new GMPRSAPrivateOperation(key);
        }
        
        return null;
    }

    /*
    * Return the GMP-based modular exponentiator
    */
    ModularExponentiator modExp(const ref BigInt n, PowerMod.UsageHints) const
    {
        return new GMPModularExponentiator(n);
    }

}


/*
* GMP Modular Exponentiator
*/
final class GMPModularExponentiator : ModularExponentiator
{
public:
    override void setBase(const ref BigInt b) { m_base = b; }
    override void setExponent(const ref BigInt e) { m_exp = e; }
    override BigInt execute() const
    {
        GMP_MPZ r;
        mpz_powm(r.value, m_base.value, m_exp.value, mod.value);
        return r.toBigint();
    }
    
    override ModularExponentiator copy() const
    { return new GMPModularExponentiator(this); }
    
    this(const ref BigInt n) { m_mod = n; }
private:
    GMP_MPZ m_base, m_exp, m_mod;
}

/**
* Lightweight GMP mpz_t wrapper. For internal use only.
*/
struct GMP_MPZ
{
public:
    mpz_t value;
    
    /*
    * GMP to BigInt Conversions
    */
    BigInt toBigint() const
    {
        BigInt output = BigInt(BigInt.Positive, (bytes() + (word).sizeof - 1) / (word).sizeof);
        size_t dummy = 0;
        
        word* reg = output.mutablePtr();
        
        mpz_export(reg, &dummy, -1, (word).sizeof, 0, 0, value);
        
        if (mpz_sgn(value) < 0)
            output.flipSign();
        
        return output;
    }
    
    /*
    * Export the mpz_t as a bytestring
    */
    void encode(ubyte* output, size_t length) const
    {
        size_t dummy = 0;
        mpz_export(output.ptr + (length - bytes()), &dummy, 1, 1, 0, 0, value);
    }
    
    /*
    * Return the number of significant bytes
    */
    size_t bytes() const
    {
        return ((mpz_sizeinbase(value, 2) + 7) / 8);
    }
    
    SecureVector!ubyte toBytes() const
    { return BigInt.encodeLocked(toBigint()); }
    
    /*
    * GMP_MPZ Assignment Operator
    */
    GMP_MPZ opAssign(in GMP_MPZ other)
    {
        mpz_set(value, other.value);
        return this;
    }
    
    /*
    * GMP_MPZ Copy Constructor
    */
    this(in GMP_MPZ other)
    {
        mpz_init_set(value, other.value);
    }
    /*
    * GMP_MPZ Constructor
    */
    this(const ref BigInt input = 0)
    {
        mpz_init(value);
        if (input != 0)
            mpz_import(value, input.sigWords(), -1, (word).sizeof, 0, 0, input.ptr);
    }
    
    /*
    * GMP_MPZ Constructor
    */
    this(const(ubyte)* input, size_t length)
    {
        mpz_init(value);
        mpz_import(value, length, 1, 1, 0, 0, input);
    }
    
    /*
    * GMP_MPZ Destructor
    */
    ~this()
    {
        mpz_clear(value);
    }
}

static if (BOTAN_HAS_DIFFIE_HELLMAN) {
    final class GMP_DH_KA_Operation : KeyAgreement
    {
    public:
        this(in DHPrivateKey dh) 
        {
            m_x = dh.getX();
            m_p = dh.groupP();
        }
        
        SecureVector!ubyte agree(const(ubyte)* w, size_t w_len)
        {
            GMP_MPZ z = GMP_MPZ(w, w_len);
            mpz_powm(z.value, z.value, m_x.value, m_p.value);
            return z.toBytes();
        }
        
    private:
        GMP_MPZ m_x, m_p;
    }
}

static if (BOTAN_HAS_DSA) {
    
    final class GMPDSASignatureOperation : Signature
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
            
            GMP_MPZ i = GMP_MPZ(msg, msg_len);
            GMP_MPZ k = GMP_MPZ(k_bn);
            
            GMP_MPZ r;
            mpz_powm(r.value, g.value, k.value, m_p.value);
            mpz_mod(r.value, r.value, m_q.value);
            
            mpz_invert(k.value, k.value, m_q.value);
            
            GMP_MPZ s;
            mpz_mul(s.value, m_x.value, r.value);
            mpz_add(s.value, s.value, i.value);
            mpz_mul(s.value, s.value, k.value);
            mpz_mod(s.value, s.value, m_q.value);
            
            if (mpz_cmp_ui(r.value, 0) == 0 || mpz_cmp_ui(s.value, 0) == 0)
                throw new InternalError("GMP_DSA_Op::sign: r or s was zero");
            
            SecureVector!ubyte output = SecureVector(2*q_bytes);
            r.encode(output.ptr, q_bytes);
            s.encode(&output[q_bytes], q_bytes);
            return output;
        }
        
    private:
        const GMP_MPZ m_x, m_p, m_q, m_g;
        size_t m_q_bits;
    }
    
    
    final class GMPDSAVerificationOperation : Verification
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

            GMP_MPZ r = GMP_MPZ(sig, q_bytes);
            GMP_MPZ s = GMP_MPZ(sig + q_bytes, q_bytes);
            GMP_MPZ i = GMP_MPZ(msg, msg_len);
            
            if (mpz_cmp_ui(r.value, 0) <= 0 || mpz_cmp(r.value, m_q.value) >= 0)
                return false;
            if (mpz_cmp_ui(s.value, 0) <= 0 || mpz_cmp(s.value, m_q.value) >= 0)
                return false;
            
            if (mpz_invert(s.value, s.value, m_q.value) == 0)
                return false;
            
            GMP_MPZ si;
            mpz_mul(si.value, s.value, i.value);
            mpz_mod(si.value, si.value, m_q.value);
            mpz_powm(si.value, m_g.value, si.value, m_p.value);
            
            GMP_MPZ sr;
            mpz_mul(sr.value, s.value, r.value);
            mpz_mod(sr.value, sr.value, m_q.value);
            mpz_powm(sr.value, m_y.value, sr.value, m_p.value);
            
            mpz_mul(si.value, si.value, sr.value);
            mpz_mod(si.value, si.value, m_p.value);
            mpz_mod(si.value, si.value, m_q.value);
            
            if (mpz_cmp(si.value, r.value) == 0)
                return true;
            return false;            
        }
        
    private:
        const GMP_MPZ m_y, m_p, m_q, m_g;
        size_t m_q_bits;
    }
    
    
    static if (BOTAN_HAS_RSA) {
        
        final class GMPRSAPrivateOperation : Signature, Decryption
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
                GMP_MPZ j1, j2;
                GMP_MPZ h = GMP_MPZ(m);
                
                mpz_powm(j1.value, h.value, m_d1.value, m_p.value);
                mpz_powm(j2.value, h.value, m_d2.value, m_q.value);
                mpz_sub(h.value, j1.value, j2.value);
                mpz_mul(h.value, h.value, m_c.value);
                mpz_mod(h.value, h.value, m_p.value);
                mpz_mul(h.value, h.value, m_q.value);
                mpz_add(h.value, h.value, j2.value);
                return h.toBigint();
            }
            
            GMP_MPZ m_mod, m_p, m_q, m_d1, m_d2, m_c;
            size_t m_n_bits;
        }
        
        
        final class GMPRSAPublicOperation : Verification, Encryption
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
                
                GMP_MPZ m_gmp = GMP_MPZ(m);
                mpz_powm(m_gmp.value, m_gmp.value, m_e.value, m_mod.value);
                return m_gmp.toBigint();
            }
            
            const BigInt m_n;
            const GMP_MPZ m_e, m_mod;
        }
        
    }
    
}

/*
* Allocation Function for GNU MP
*/
void* gmp_malloc(size_t n)
{
    import memutils.utils : SecureMem;
    return cast(void*)SecureMem!(ubyte[]).alloc(n).ptr;
}

/*
* Deallocation Function for GNU MP
*/
void gmp_free(void* ptr, size_t n)
{
    import memutils.utils : SecureMem;
    SecureMem!(ubyte[]).free(cast(ubyte[])ptr[0 .. n]);
}

/*
* Reallocation Function for GNU MP
*/
void* gmp_realloc(void* ptr, size_t old_n, size_t new_n)
{
    void* new_buf = gmp_malloc(new_n);
    memcpy(new_buf, ptr, std.algorithm.min(old_n, new_n));
    gmp_free(ptr, old_n);
    return new_buf;
}

extern(C) nothrow @nogc
{


    const int __gmp_0 = 0;
    int __gmp_junk;
    /*void *_alloca(size_t size)
    {
    // return std.c.stdlib.alloca(size);
        char* v= cast(char*)std.c.stdlib.malloc(size);
        for (int i=0;i<size;i++)
        {
         v[i]=cast(char)0;
        }
        return v;
    //    return cast(char*)new void[size];
    }*/
    enum gmp_randalg_t:int
    {
        GMP_RAND_ALG_DEFAULT = 0,
        GMP_RAND_ALG_LC = GMP_RAND_ALG_DEFAULT /* Linear congruential.  */
    } ;
    extern  int __gmp_bits_per_limb;
    alias mp_bits_per_limb = __gmp_bits_per_limb;
    
    extern int __gmp_errno;
    alias gmp_errno = __gmp_errno;
    extern  char *  __gmp_version;
    
    alias gmp_version = __gmp_version;
    
    const __GMP_BITS_PER_MP_LIMB=32;
    const __GMP_HAVE_HOST_CPU_FAMILY_power=0;
    const __GMP_HAVE_HOST_CPU_FAMILY_powerpc=0;
    const GMP_LIMB_BITS=32;
    const GMP_NAIL_BITS=0;
    const GMP_NUMB_BITS=(GMP_LIMB_BITS - GMP_NAIL_BITS);
    const GMP_NUMB_MASK=((~ cast(mp_limb_t)( 0)) >> GMP_NAIL_BITS);
    const GMP_NUMB_MAX=GMP_NUMB_MASK;
    const GMP_NAIL_MASK=(~ GMP_NUMB_MASK);
    alias mp_limb_t = uint;
    alias mp_limb_signed_t = int;
    struct  __mpz_struct{
        int _mp_alloc;        /* Number of *limbs* allocated and pointed
                                 to by the _mp_d field.  */
        int _mp_size;            /* abs(_mp_size) is the number of limbs the
                                    last field points to.  If _mp_size is
                                    negative this is a negative number.  */
        mp_limb_t *_mp_d;        /* Pointer to the limbs.  */
    }
    alias MP_INT = __mpz_struct;
    alias mpz_t = __mpz_struct[1];
    alias mp_ptr = mp_limb_t *;
    alias mp_srcptr = mp_limb_t *;
    const __GMP_MP_SIZE_T_INT=0;
    alias mp_size_t = int;
    alias mp_exp_t = int;
    struct  __mpq_struct{
        __mpz_struct _mp_num;
        __mpz_struct _mp_den;
    }
    alias MP_RAT = __mpq_struct;
    alias mpq_t = __mpq_struct[1];
    struct  __mpf_struct{
        int _mp_prec;            /* Max precision, in number of `mp_limb_t's.
                                    Set by mpf_init and modified by
                                    mpf_set_prec.  The area pointed to by the
                                    _mp_d field contains `prec' + 1 limbs.  */
        int _mp_size;            /* abs(_mp_size) is the number of limbs the
                                    last field points to.  If _mp_size is
                                    negative this is a negative number.  */
        mp_exp_t _mp_exp;        /* Exponent, in the base of `mp_limb_t'.  */
        mp_limb_t *_mp_d;        /* Pointer to the limbs.  */
    }
    alias MP_FLOAT = __mpf_struct;
    alias mpf_t = __mpf_struct;
    struct  __gmp_randstate_struct{
        mpz_t _mp_seed;      /* _mp_d member points to state of the generator. */
        gmp_randalg_t _mp_alg;  /* Currently unused. */
        union _mp_algdata {
            void *_mp_lc;         /* Pointer to function pointers structure.  */
        }
    }
    alias gmp_randstate_t = __gmp_randstate_struct[1];
    alias mpz_srcptr = __mpz_struct *;
    alias mpz_ptr = __mpz_struct *;
    alias mpf_srcptr = __mpf_struct *;
    alias mpf_ptr = __mpf_struct *;
    alias mpq_srcptr = __mpq_struct *;
    alias mpq_ptr = __mpq_struct *;
    const __GMP_UINT_MAX=(~ cast(uint) 0);
    const __GMP_ULONG_MAX=(~ cast(uint) 0);
    const __GMP_USHRT_MAX=(cast(ushort) ~0);
    /**************** Random number routines.  ****************/
    
    /* obsolete */
    alias gmp_randinit = __gmp_randinit;
    void __gmp_randinit (gmp_randstate_t, gmp_randalg_t, ...);
    
    alias gmp_randinit_default = __gmp_randinit_default;
    void __gmp_randinit_default (gmp_randstate_t);
    
    alias gmp_randinit_lc_2exp = __gmp_randinit_lc_2exp;
    void __gmp_randinit_lc_2exp (gmp_randstate_t,
                                 mpz_srcptr, uint,
                                 uint);
    
    alias gmp_randinit_lc_2exp_size = __gmp_randinit_lc_2exp_size;
    int __gmp_randinit_lc_2exp_size (gmp_randstate_t, uint);
    
    alias gmp_randinit_mt = __gmp_randinit_mt;
    void __gmp_randinit_mt (gmp_randstate_t);
    
    alias gmp_randinit_set = __gmp_randinit_set;
    void __gmp_randinit_set (gmp_randstate_t,  __gmp_randstate_struct *);
    
    alias gmp_randseed = __gmp_randseed;
    void __gmp_randseed (gmp_randstate_t, mpz_srcptr);
    
    alias gmp_randseed_ui = __gmp_randseed_ui;
    void __gmp_randseed_ui (gmp_randstate_t, uint);
    
    alias gmp_randclear = __gmp_randclear;
    void __gmp_randclear (gmp_randstate_t);
    
    alias gmp_urandomb_ui = __gmp_urandomb_ui;
    uint __gmp_urandomb_ui (gmp_randstate_t, uint);
    
    alias gmp_urandomm_ui = __gmp_urandomm_ui;
    uint __gmp_urandomm_ui (gmp_randstate_t, uint);
    
    
    /**************** Formatted output routines.  ****************/
    
    alias gmp_asprintf = __gmp_asprintf;
    int __gmp_asprintf (char **,  char *, ...);
    
    alias gmp_fprintf = __gmp_fprintf;
    
    int __gmp_fprintf (FILE *,  char *, ...);
    
    
    alias gmp_printf = __gmp_printf;
    int __gmp_printf ( char *, ...);
    
    alias gmp_snprintf = __gmp_snprintf;
    int __gmp_snprintf (char *, size_t,  char *, ...);
    
    alias gmp_sprintf = __gmp_sprintf;
    int __gmp_sprintf (char *,  char *, ...);
    
    /**************** Formatted input routines.  ****************/
    
    alias gmp_fscanf = __gmp_fscanf;
    
    int __gmp_fscanf (FILE *,  char *, ...);
    
    
    alias gmp_scanf = __gmp_scanf;
    int __gmp_scanf ( char *, ...);
    
    alias gmp_sscanf = __gmp_sscanf;
    int __gmp_sscanf ( char *,  char *, ...);
    
    /**************** Integer (i.e. Z) routines.  ****************/
    
    void *_mpz_realloc (mpz_ptr, mp_size_t);
    
    alias mpz_abs = __gmpz_abs;
    
    void __gmpz_abs (mpz_ptr, mpz_srcptr);
    
    
    alias mpz_add = __gmpz_add;
    void __gmpz_add (mpz_ptr, mpz_srcptr, mpz_srcptr);
    
    alias mpz_add_ui = __gmpz_add_ui;
    void __gmpz_add_ui (mpz_ptr, mpz_srcptr, uint);
    
    alias mpz_addmul = __gmpz_addmul;
    void __gmpz_addmul (mpz_ptr, mpz_srcptr, mpz_srcptr);
    
    alias mpz_addmul_ui = __gmpz_addmul_ui;
    void __gmpz_addmul_ui (mpz_ptr, mpz_srcptr, uint);
    
    alias mpz_and = __gmpz_and;
    void __gmpz_and (mpz_ptr, mpz_srcptr, mpz_srcptr);
    
    alias mpz_array_init = __gmpz_array_init;
    void __gmpz_array_init (mpz_ptr, mp_size_t, mp_size_t);
    
    alias mpz_bin_ui = __gmpz_bin_ui;
    void __gmpz_bin_ui (mpz_ptr, mpz_srcptr, uint);
    
    alias mpz_bin_uiui = __gmpz_bin_uiui;
    void __gmpz_bin_uiui (mpz_ptr, uint, uint);
    
    alias mpz_cdiv_q = __gmpz_cdiv_q;
    void __gmpz_cdiv_q (mpz_ptr, mpz_srcptr, mpz_srcptr);
    
    alias mpz_cdiv_q_2exp = __gmpz_cdiv_q_2exp;
    void __gmpz_cdiv_q_2exp (mpz_ptr, mpz_srcptr, uint);
    
    alias mpz_cdiv_q_ui = __gmpz_cdiv_q_ui;
    uint __gmpz_cdiv_q_ui (mpz_ptr, mpz_srcptr, uint);
    
    alias mpz_cdiv_qr = __gmpz_cdiv_qr;
    void __gmpz_cdiv_qr (mpz_ptr, mpz_ptr, mpz_srcptr, mpz_srcptr);
    
    alias mpz_cdiv_qr_ui = __gmpz_cdiv_qr_ui;
    uint __gmpz_cdiv_qr_ui (mpz_ptr, mpz_ptr, mpz_srcptr, uint);
    
    alias mpz_cdiv_r = __gmpz_cdiv_r;
    void __gmpz_cdiv_r (mpz_ptr, mpz_srcptr, mpz_srcptr);
    
    alias mpz_cdiv_r_2exp = __gmpz_cdiv_r_2exp;
    void __gmpz_cdiv_r_2exp (mpz_ptr, mpz_srcptr, uint);
    
    alias mpz_cdiv_r_ui = __gmpz_cdiv_r_ui;
    uint __gmpz_cdiv_r_ui (mpz_ptr, mpz_srcptr, uint);
    
    alias mpz_cdiv_ui = __gmpz_cdiv_ui;
    uint __gmpz_cdiv_ui (mpz_srcptr, uint);
    
    alias mpz_clear = __gmpz_clear;
    void __gmpz_clear (mpz_ptr);
    
    alias mpz_clrbit = __gmpz_clrbit;
    void __gmpz_clrbit (mpz_ptr, uint);
    
    alias mpz_cmp = __gmpz_cmp;
    int __gmpz_cmp (mpz_srcptr, mpz_srcptr);
    
    alias mpz_cmp_d = __gmpz_cmp_d;
    int __gmpz_cmp_d (mpz_srcptr, double);
    
    alias _mpz_cmp_si = __gmpz_cmp_si;
    int __gmpz_cmp_si (mpz_srcptr, int);
    
    alias _mpz_cmp_ui = __gmpz_cmp_ui;
    int __gmpz_cmp_ui (mpz_srcptr, uint);
    
    alias mpz_cmpabs = __gmpz_cmpabs;
    int __gmpz_cmpabs (mpz_srcptr, mpz_srcptr);
    
    alias mpz_cmpabs_d = __gmpz_cmpabs_d;
    int __gmpz_cmpabs_d (mpz_srcptr, double);
    
    alias mpz_cmpabs_ui = __gmpz_cmpabs_ui;
    int __gmpz_cmpabs_ui (mpz_srcptr, uint);
    
    alias mpz_com = __gmpz_com;
    void __gmpz_com (mpz_ptr, mpz_srcptr);
    
    alias mpz_combit = __gmpz_combit;
    void __gmpz_combit (mpz_ptr, uint);
    
    alias mpz_congruent_p = __gmpz_congruent_p;
    int __gmpz_congruent_p (mpz_srcptr, mpz_srcptr, mpz_srcptr);
    
    alias mpz_congruent_2exp_p = __gmpz_congruent_2exp_p;
    int __gmpz_congruent_2exp_p (mpz_srcptr, mpz_srcptr, uint);
    
    alias mpz_congruent_ui_p = __gmpz_congruent_ui_p;
    int __gmpz_congruent_ui_p (mpz_srcptr, uint, uint);
    
    alias mpz_divexact = __gmpz_divexact;
    void __gmpz_divexact (mpz_ptr, mpz_srcptr, mpz_srcptr);
    
    alias mpz_divexact_ui = __gmpz_divexact_ui;
    void __gmpz_divexact_ui (mpz_ptr, mpz_srcptr, uint);
    
    alias mpz_divisible_p = __gmpz_divisible_p;
    int __gmpz_divisible_p (mpz_srcptr, mpz_srcptr);
    
    alias mpz_divisible_ui_p = __gmpz_divisible_ui_p;
    int __gmpz_divisible_ui_p (mpz_srcptr, uint);
    
    alias mpz_divisible_2exp_p = __gmpz_divisible_2exp_p;
    int __gmpz_divisible_2exp_p (mpz_srcptr, uint);
    
    alias mpz_dump = __gmpz_dump;
    void __gmpz_dump (mpz_srcptr);
    
    alias mpz_export = __gmpz_export;
    void *__gmpz_export (void *, size_t *, int, size_t, int, size_t, mpz_srcptr);
    
    alias mpz_fac_ui = __gmpz_fac_ui;
    void __gmpz_fac_ui (mpz_ptr, uint);
    
    alias mpz_fdiv_q = __gmpz_fdiv_q;
    void __gmpz_fdiv_q (mpz_ptr, mpz_srcptr, mpz_srcptr);
    
    alias mpz_fdiv_q_2exp = __gmpz_fdiv_q_2exp;
    void __gmpz_fdiv_q_2exp (mpz_ptr, mpz_srcptr, uint);
    
    alias mpz_fdiv_q_ui = __gmpz_fdiv_q_ui;
    uint __gmpz_fdiv_q_ui (mpz_ptr, mpz_srcptr, uint);
    
    alias mpz_fdiv_qr = __gmpz_fdiv_qr;
    void __gmpz_fdiv_qr (mpz_ptr, mpz_ptr, mpz_srcptr, mpz_srcptr);
    
    alias mpz_fdiv_qr_ui = __gmpz_fdiv_qr_ui;
    uint __gmpz_fdiv_qr_ui (mpz_ptr, mpz_ptr, mpz_srcptr, uint);
    
    alias mpz_fdiv_r = __gmpz_fdiv_r;
    void __gmpz_fdiv_r (mpz_ptr, mpz_srcptr, mpz_srcptr);
    
    alias mpz_fdiv_r_2exp = __gmpz_fdiv_r_2exp;
    void __gmpz_fdiv_r_2exp (mpz_ptr, mpz_srcptr, uint);
    
    alias mpz_fdiv_r_ui = __gmpz_fdiv_r_ui;
    uint __gmpz_fdiv_r_ui (mpz_ptr, mpz_srcptr, uint);
    
    alias mpz_fdiv_ui = __gmpz_fdiv_ui;
    uint __gmpz_fdiv_ui (mpz_srcptr, uint);
    
    alias mpz_fib_ui = __gmpz_fib_ui;
    void __gmpz_fib_ui (mpz_ptr, uint);
    
    alias mpz_fib2_ui = __gmpz_fib2_ui;
    void __gmpz_fib2_ui (mpz_ptr, mpz_ptr, uint);
    
    alias mpz_fits_sint_p = __gmpz_fits_sint_p;
    int __gmpz_fits_sint_p (mpz_srcptr);
    
    alias mpz_fits_slong_p = __gmpz_fits_slong_p;
    int __gmpz_fits_slong_p (mpz_srcptr);
    
    alias mpz_fits_sshort_p = __gmpz_fits_sshort_p;
    int __gmpz_fits_sshort_p (mpz_srcptr);
    
    alias mpz_fits_uint_p = __gmpz_fits_uint_p;
    
    int __gmpz_fits_uint_p (mpz_srcptr);
    
    
    alias mpz_fits_ulong_p = __gmpz_fits_ulong_p;
    
    int __gmpz_fits_ulong_p (mpz_srcptr);
    
    
    alias mpz_fits_ushort_p = __gmpz_fits_ushort_p;
    
    int __gmpz_fits_ushort_p (mpz_srcptr);
    
    
    alias mpz_gcd = __gmpz_gcd;
    void __gmpz_gcd (mpz_ptr, mpz_srcptr, mpz_srcptr);
    
    alias mpz_gcd_ui = __gmpz_gcd_ui;
    uint __gmpz_gcd_ui (mpz_ptr, mpz_srcptr, uint);
    
    alias mpz_gcdext = __gmpz_gcdext;
    void __gmpz_gcdext (mpz_ptr, mpz_ptr, mpz_ptr, mpz_srcptr, mpz_srcptr);
    
    alias mpz_get_d = __gmpz_get_d;
    double __gmpz_get_d (mpz_srcptr);
    
    alias mpz_get_d_2exp = __gmpz_get_d_2exp;
    double __gmpz_get_d_2exp (int *, mpz_srcptr);
    
    alias mpz_get_si = __gmpz_get_si;
    /* signed */ int __gmpz_get_si (mpz_srcptr);
    
    alias mpz_get_str = __gmpz_get_str;
    char *__gmpz_get_str (char *, int, mpz_srcptr);
    
    alias mpz_get_ui = __gmpz_get_ui;
    
    uint __gmpz_get_ui (mpz_srcptr);
    
    
    alias mpz_getlimbn = __gmpz_getlimbn;
    
    mp_limb_t __gmpz_getlimbn (mpz_srcptr, mp_size_t);
    
    
    alias mpz_hamdist = __gmpz_hamdist;
    uint __gmpz_hamdist (mpz_srcptr, mpz_srcptr);
    
    alias mpz_import = __gmpz_import;
    void __gmpz_import (mpz_ptr, size_t, int, size_t, int, size_t,  void *);
    
    alias mpz_init = __gmpz_init;
    void __gmpz_init (mpz_ptr);
    
    alias mpz_init2 = __gmpz_init2;
    void __gmpz_init2 (mpz_ptr, uint);
    
    alias mpz_init_set = __gmpz_init_set;
    void __gmpz_init_set (mpz_ptr, mpz_srcptr);
    
    alias mpz_init_set_d = __gmpz_init_set_d;
    void __gmpz_init_set_d (mpz_ptr, double);
    
    alias mpz_init_set_si = __gmpz_init_set_si;
    void __gmpz_init_set_si (mpz_ptr, int);
    
    alias mpz_init_set_str = __gmpz_init_set_str;
    int __gmpz_init_set_str (mpz_ptr,  char *, int);
    
    alias mpz_init_set_ui = __gmpz_init_set_ui;
    void __gmpz_init_set_ui (mpz_ptr, uint);
    
    alias mpz_inp_raw = __gmpz_inp_raw;
    
    size_t __gmpz_inp_raw (mpz_ptr, FILE *);
    
    
    alias mpz_inp_str = __gmpz_inp_str;
    
    size_t __gmpz_inp_str (mpz_ptr, FILE *, int);
    
    
    alias mpz_invert = __gmpz_invert;
    int __gmpz_invert (mpz_ptr, mpz_srcptr, mpz_srcptr);
    
    alias mpz_ior = __gmpz_ior;
    void __gmpz_ior (mpz_ptr, mpz_srcptr, mpz_srcptr);
    
    alias mpz_jacobi = __gmpz_jacobi;
    int __gmpz_jacobi (mpz_srcptr, mpz_srcptr);
    
    alias mpz_kronecker = mpz_jacobi;
    
    alias mpz_kronecker_si = __gmpz_kronecker_si;
    int __gmpz_kronecker_si (mpz_srcptr, long);
    
    alias mpz_kronecker_ui = __gmpz_kronecker_ui;
    int __gmpz_kronecker_ui (mpz_srcptr, uint);
    
    alias mpz_si_kronecker = __gmpz_si_kronecker;
    int __gmpz_si_kronecker (long, mpz_srcptr);
    
    alias mpz_ui_kronecker = __gmpz_ui_kronecker;
    int __gmpz_ui_kronecker (uint, mpz_srcptr);
    
    alias mpz_lcm = __gmpz_lcm;
    void __gmpz_lcm (mpz_ptr, mpz_srcptr, mpz_srcptr);
    
    alias mpz_lcm_ui = __gmpz_lcm_ui;
    void __gmpz_lcm_ui (mpz_ptr, mpz_srcptr, uint);
    
    alias mpz_legendre = mpz_jacobi;
    
    alias mpz_lucnum_ui = __gmpz_lucnum_ui;
    void __gmpz_lucnum_ui (mpz_ptr, uint);
    
    alias mpz_lucnum2_ui = __gmpz_lucnum2_ui;
    void __gmpz_lucnum2_ui (mpz_ptr, mpz_ptr, uint);
    
    alias mpz_millerrabin = __gmpz_millerrabin;
    int __gmpz_millerrabin (mpz_srcptr, int);
    
    alias mpz_mod = __gmpz_mod;
    void __gmpz_mod (mpz_ptr, mpz_srcptr, mpz_srcptr);
    
    alias mpz_mod_ui = mpz_fdiv_r_ui;
    
    alias mpz_mul = __gmpz_mul;
    void __gmpz_mul (mpz_ptr, mpz_srcptr, mpz_srcptr);
    
    alias mpz_mul_2exp = __gmpz_mul_2exp;
    void __gmpz_mul_2exp (mpz_ptr, mpz_srcptr, uint);
    
    alias mpz_mul_si = __gmpz_mul_si;
    void __gmpz_mul_si (mpz_ptr, mpz_srcptr, int);
    
    alias mpz_mul_ui = __gmpz_mul_ui;
    void __gmpz_mul_ui (mpz_ptr, mpz_srcptr, uint);
    
    alias mpz_neg = __gmpz_neg;
    
    void __gmpz_neg (mpz_ptr, mpz_srcptr);
    
    
    alias mpz_nextprime = __gmpz_nextprime;
    void __gmpz_nextprime (mpz_ptr, mpz_srcptr);
    
    alias mpz_out_raw = __gmpz_out_raw;
    
    size_t __gmpz_out_raw (FILE *, mpz_srcptr);
    
    
    alias mpz_out_str = __gmpz_out_str;
    
    size_t __gmpz_out_str (FILE *, int, mpz_srcptr);
    
    
    alias mpz_perfect_power_p = __gmpz_perfect_power_p;
    int __gmpz_perfect_power_p (mpz_srcptr);
    
    alias mpz_perfect_square_p = __gmpz_perfect_square_p;
    
    int __gmpz_perfect_square_p (mpz_srcptr);
    
    
    alias mpz_popcount = __gmpz_popcount;
    
    uint __gmpz_popcount (mpz_srcptr);
    
    
    alias mpz_pow_ui = __gmpz_pow_ui;
    void __gmpz_pow_ui (mpz_ptr, mpz_srcptr, uint);
    
    alias mpz_powm = __gmpz_powm;
    void __gmpz_powm (mpz_ptr, mpz_srcptr, mpz_srcptr, mpz_srcptr);
    
    alias mpz_powm_ui = __gmpz_powm_ui;
    void __gmpz_powm_ui (mpz_ptr, mpz_srcptr, uint, mpz_srcptr);
    
    alias mpz_probab_prime_p = __gmpz_probab_prime_p;
    int __gmpz_probab_prime_p (mpz_srcptr, int);
    
    alias mpz_random = __gmpz_random;
    void __gmpz_random (mpz_ptr, mp_size_t);
    
    alias mpz_random2 = __gmpz_random2;
    void __gmpz_random2 (mpz_ptr, mp_size_t);
    
    alias mpz_realloc2 = __gmpz_realloc2;
    void __gmpz_realloc2 (mpz_ptr, uint);
    
    alias mpz_remove = __gmpz_remove;
    uint __gmpz_remove (mpz_ptr, mpz_srcptr, mpz_srcptr);
    
    alias mpz_root = __gmpz_root;
    int __gmpz_root (mpz_ptr, mpz_srcptr, uint);
    
    alias mpz_rootrem = __gmpz_rootrem;
    void __gmpz_rootrem (mpz_ptr,mpz_ptr, mpz_srcptr, uint);
    
    alias mpz_rrandomb = __gmpz_rrandomb;
    void __gmpz_rrandomb (mpz_ptr, gmp_randstate_t, uint);
    
    alias mpz_scan0 = __gmpz_scan0;
    uint __gmpz_scan0 (mpz_srcptr, uint);
    
    alias mpz_scan1 = __gmpz_scan1;
    uint __gmpz_scan1 (mpz_srcptr, uint);
    
    alias mpz_set = __gmpz_set;
    void __gmpz_set (mpz_ptr, mpz_srcptr);
    
    alias mpz_set_d = __gmpz_set_d;
    void __gmpz_set_d (mpz_ptr, double);
    
    alias mpz_set_f = __gmpz_set_f;
    void __gmpz_set_f (mpz_ptr, mpf_srcptr);
    
    alias mpz_set_q = __gmpz_set_q;
    
    void __gmpz_set_q (mpz_ptr, mpq_srcptr);
    
    
    alias mpz_set_si = __gmpz_set_si;
    void __gmpz_set_si (mpz_ptr, int);
    
    alias mpz_set_str = __gmpz_set_str;
    int __gmpz_set_str (mpz_ptr,  char *, int);
    
    alias mpz_set_ui = __gmpz_set_ui;
    void __gmpz_set_ui (mpz_ptr, uint);
    
    alias mpz_setbit = __gmpz_setbit;
    void __gmpz_setbit (mpz_ptr, uint);
    
    alias mpz_size = __gmpz_size;
    
    size_t __gmpz_size (mpz_srcptr);
    
    
    alias mpz_sizeinbase = __gmpz_sizeinbase;
    size_t __gmpz_sizeinbase (mpz_srcptr, int);
    
    alias mpz_sqrt = __gmpz_sqrt;
    void __gmpz_sqrt (mpz_ptr, mpz_srcptr);
    
    alias mpz_sqrtrem = __gmpz_sqrtrem;
    void __gmpz_sqrtrem (mpz_ptr, mpz_ptr, mpz_srcptr);
    
    alias mpz_sub = __gmpz_sub;
    void __gmpz_sub (mpz_ptr, mpz_srcptr, mpz_srcptr);
    
    alias mpz_sub_ui = __gmpz_sub_ui;
    void __gmpz_sub_ui (mpz_ptr, mpz_srcptr, uint);
    
    alias mpz_ui_sub = __gmpz_ui_sub;
    void __gmpz_ui_sub (mpz_ptr, uint, mpz_srcptr);
    
    alias mpz_submul = __gmpz_submul;
    void __gmpz_submul (mpz_ptr, mpz_srcptr, mpz_srcptr);
    
    alias mpz_submul_ui = __gmpz_submul_ui;
    void __gmpz_submul_ui (mpz_ptr, mpz_srcptr, uint);
    
    alias mpz_swap = __gmpz_swap;
    void __gmpz_swap (mpz_ptr, mpz_ptr);
    
    alias mpz_tdiv_ui = __gmpz_tdiv_ui;
    uint __gmpz_tdiv_ui (mpz_srcptr, uint);
    
    alias mpz_tdiv_q = __gmpz_tdiv_q;
    void __gmpz_tdiv_q (mpz_ptr, mpz_srcptr, mpz_srcptr);
    
    alias mpz_tdiv_q_2exp = __gmpz_tdiv_q_2exp;
    void __gmpz_tdiv_q_2exp (mpz_ptr, mpz_srcptr, uint);
    
    alias mpz_tdiv_q_ui = __gmpz_tdiv_q_ui;
    uint __gmpz_tdiv_q_ui (mpz_ptr, mpz_srcptr, uint);
    
    alias mpz_tdiv_qr = __gmpz_tdiv_qr;
    void __gmpz_tdiv_qr (mpz_ptr, mpz_ptr, mpz_srcptr, mpz_srcptr);
    
    alias mpz_tdiv_qr_ui = __gmpz_tdiv_qr_ui;
    uint __gmpz_tdiv_qr_ui (mpz_ptr, mpz_ptr, mpz_srcptr, uint);
    
    alias mpz_tdiv_r = __gmpz_tdiv_r;
    void __gmpz_tdiv_r (mpz_ptr, mpz_srcptr, mpz_srcptr);
    
    alias mpz_tdiv_r_2exp = __gmpz_tdiv_r_2exp;
    void __gmpz_tdiv_r_2exp (mpz_ptr, mpz_srcptr, uint);
    
    alias mpz_tdiv_r_ui = __gmpz_tdiv_r_ui;
    uint __gmpz_tdiv_r_ui (mpz_ptr, mpz_srcptr, uint);
    
    alias mpz_tstbit = __gmpz_tstbit;
    int __gmpz_tstbit (mpz_srcptr, uint);
    
    alias mpz_ui_pow_ui = __gmpz_ui_pow_ui;
    void __gmpz_ui_pow_ui (mpz_ptr, uint, uint);
    
    alias mpz_urandomb = __gmpz_urandomb;
    void __gmpz_urandomb (mpz_ptr, gmp_randstate_t, uint);
    
    alias mpz_urandomm = __gmpz_urandomm;
    void __gmpz_urandomm (mpz_ptr, gmp_randstate_t, mpz_srcptr);
    
    alias mpz_xor = __gmpz_xor;
    alias mpz_eor = __gmpz_xor;
    void __gmpz_xor (mpz_ptr, mpz_srcptr, mpz_srcptr);
    
    
    /**************** Rational (i.e. Q) routines.  ****************/
    
    alias mpq_abs = __gmpq_abs;
    
    void __gmpq_abs (mpq_ptr, mpq_srcptr);
    
    
    alias mpq_add = __gmpq_add;
    void __gmpq_add (mpq_ptr, mpq_srcptr, mpq_srcptr);
    
    alias mpq_canonicalize = __gmpq_canonicalize;
    void __gmpq_canonicalize (mpq_ptr);
    
    alias mpq_clear = __gmpq_clear;
    void __gmpq_clear (mpq_ptr);
    
    alias mpq_cmp = __gmpq_cmp;
    int __gmpq_cmp (mpq_srcptr, mpq_srcptr);
    
    alias _mpq_cmp_si = __gmpq_cmp_si;
    int __gmpq_cmp_si (mpq_srcptr, long, uint);
    
    alias _mpq_cmp_ui = __gmpq_cmp_ui;
    int __gmpq_cmp_ui (mpq_srcptr, uint, uint);
    
    alias mpq_div = __gmpq_div;
    void __gmpq_div (mpq_ptr, mpq_srcptr, mpq_srcptr);
    
    alias mpq_div_2exp = __gmpq_div_2exp;
    void __gmpq_div_2exp (mpq_ptr, mpq_srcptr, uint);
    
    alias mpq_equal = __gmpq_equal;
    int __gmpq_equal (mpq_srcptr, mpq_srcptr);
    
    alias mpq_get_num = __gmpq_get_num;
    void __gmpq_get_num (mpz_ptr, mpq_srcptr);
    
    alias mpq_get_den = __gmpq_get_den;
    void __gmpq_get_den (mpz_ptr, mpq_srcptr);
    
    alias mpq_get_d = __gmpq_get_d;
    double __gmpq_get_d (mpq_srcptr);
    
    alias mpq_get_str = __gmpq_get_str;
    char *__gmpq_get_str (char *, int, mpq_srcptr);
    
    alias mpq_init = __gmpq_init;
    void __gmpq_init (mpq_ptr);
    
    alias mpq_inp_str = __gmpq_inp_str;
    
    size_t __gmpq_inp_str (mpq_ptr, FILE *, int);
    
    
    alias mpq_inv = __gmpq_inv;
    void __gmpq_inv (mpq_ptr, mpq_srcptr);
    
    alias mpq_mul = __gmpq_mul;
    void __gmpq_mul (mpq_ptr, mpq_srcptr, mpq_srcptr);
    
    alias mpq_mul_2exp = __gmpq_mul_2exp;
    void __gmpq_mul_2exp (mpq_ptr, mpq_srcptr, uint);
    
    alias mpq_neg = __gmpq_neg;
    
    void __gmpq_neg (mpq_ptr, mpq_srcptr);
    
    
    alias mpq_out_str = __gmpq_out_str;
    
    size_t __gmpq_out_str (FILE *, int, mpq_srcptr);
    
    
    alias mpq_set = __gmpq_set;
    void __gmpq_set (mpq_ptr, mpq_srcptr);
    
    alias mpq_set_d = __gmpq_set_d;
    void __gmpq_set_d (mpq_ptr, double);
    
    alias mpq_set_den = __gmpq_set_den;
    void __gmpq_set_den (mpq_ptr, mpz_srcptr);
    
    alias mpq_set_f = __gmpq_set_f;
    void __gmpq_set_f (mpq_ptr, mpf_srcptr);
    
    alias mpq_set_num = __gmpq_set_num;
    void __gmpq_set_num (mpq_ptr, mpz_srcptr);
    
    alias mpq_set_si = __gmpq_set_si;
    void __gmpq_set_si (mpq_ptr, int, uint);
    
    alias mpq_set_str = __gmpq_set_str;
    int __gmpq_set_str (mpq_ptr,  char *, int);
    
    alias mpq_set_ui = __gmpq_set_ui;
    void __gmpq_set_ui (mpq_ptr, uint, uint);
    
    alias mpq_set_z = __gmpq_set_z;
    void __gmpq_set_z (mpq_ptr, mpz_srcptr);
    
    alias mpq_sub = __gmpq_sub;
    void __gmpq_sub (mpq_ptr, mpq_srcptr, mpq_srcptr);
    
    alias mpq_swap = __gmpq_swap;
    void __gmpq_swap (mpq_ptr, mpq_ptr);
    
    
    /**************** Float (i.e. F) routines.  ****************/
    
    alias mpf_abs = __gmpf_abs;
    void __gmpf_abs (mpf_ptr, mpf_srcptr);
    
    alias mpf_add = __gmpf_add;
    void __gmpf_add (mpf_ptr, mpf_srcptr, mpf_srcptr);
    
    alias mpf_add_ui = __gmpf_add_ui;
    void __gmpf_add_ui (mpf_ptr, mpf_srcptr, uint);
    alias mpf_ceil = __gmpf_ceil;
    void __gmpf_ceil (mpf_ptr, mpf_srcptr);
    
    alias mpf_clear = __gmpf_clear;
    void __gmpf_clear (mpf_ptr);
    
    alias mpf_cmp = __gmpf_cmp;
    int __gmpf_cmp (mpf_srcptr, mpf_srcptr);
    
    alias mpf_cmp_d = __gmpf_cmp_d;
    int __gmpf_cmp_d (mpf_srcptr, double);
    
    alias mpf_cmp_si = __gmpf_cmp_si;
    int __gmpf_cmp_si (mpf_srcptr, int);
    
    alias mpf_cmp_ui = __gmpf_cmp_ui;
    int __gmpf_cmp_ui (mpf_srcptr, uint);
    
    alias mpf_div = __gmpf_div;
    void __gmpf_div (mpf_ptr, mpf_srcptr, mpf_srcptr);
    
    alias mpf_div_2exp = __gmpf_div_2exp;
    void __gmpf_div_2exp (mpf_ptr, mpf_srcptr, uint);
    
    alias mpf_div_ui = __gmpf_div_ui;
    void __gmpf_div_ui (mpf_ptr, mpf_srcptr, uint);
    
    alias mpf_dump = __gmpf_dump;
    void __gmpf_dump (mpf_srcptr);
    
    alias mpf_eq = __gmpf_eq;
    int __gmpf_eq (mpf_srcptr, mpf_srcptr, uint);
    
    alias mpf_fits_sint_p = __gmpf_fits_sint_p;
    int __gmpf_fits_sint_p (mpf_srcptr);
    
    alias mpf_fits_slong_p = __gmpf_fits_slong_p;
    int __gmpf_fits_slong_p (mpf_srcptr);
    
    alias mpf_fits_sshort_p = __gmpf_fits_sshort_p;
    int __gmpf_fits_sshort_p (mpf_srcptr);
    
    alias mpf_fits_uint_p = __gmpf_fits_uint_p;
    int __gmpf_fits_uint_p (mpf_srcptr);
    
    alias mpf_fits_ulong_p = __gmpf_fits_ulong_p;
    int __gmpf_fits_ulong_p (mpf_srcptr);
    
    alias mpf_fits_ushort_p = __gmpf_fits_ushort_p;
    int __gmpf_fits_ushort_p (mpf_srcptr);
    
    alias mpf_floor = __gmpf_floor;
    void __gmpf_floor (mpf_ptr, mpf_srcptr);
    
    alias mpf_get_d = __gmpf_get_d;
    double __gmpf_get_d (mpf_srcptr);
    
    alias mpf_get_d_2exp = __gmpf_get_d_2exp;
    double __gmpf_get_d_2exp (int *, mpf_srcptr);
    
    alias mpf_get_default_prec = __gmpf_get_default_prec;
    uint __gmpf_get_default_prec ();
    
    alias mpf_get_prec = __gmpf_get_prec;
    uint __gmpf_get_prec (mpf_srcptr);
    
    alias mpf_get_si = __gmpf_get_si;
    long __gmpf_get_si (mpf_srcptr);
    
    alias mpf_get_str = __gmpf_get_str;
    char *__gmpf_get_str (char *, mp_exp_t *, int, size_t, mpf_srcptr);
    
    alias mpf_get_ui = __gmpf_get_ui;
    uint __gmpf_get_ui (mpf_srcptr);
    
    alias mpf_init = __gmpf_init;
    void __gmpf_init (mpf_ptr);
    
    alias mpf_init2 = __gmpf_init2;
    void __gmpf_init2 (mpf_ptr, uint);
    
    alias mpf_init_set = __gmpf_init_set;
    void __gmpf_init_set (mpf_ptr, mpf_srcptr);
    
    alias mpf_init_set_d = __gmpf_init_set_d;
    void __gmpf_init_set_d (mpf_ptr, double);
    
    alias mpf_init_set_si = __gmpf_init_set_si;
    void __gmpf_init_set_si (mpf_ptr, int);
    
    alias mpf_init_set_str = __gmpf_init_set_str;
    int __gmpf_init_set_str (mpf_ptr,  char *, int);
    
    alias mpf_init_set_ui = __gmpf_init_set_ui;
    void __gmpf_init_set_ui (mpf_ptr, uint);
    
    alias mpf_inp_str = __gmpf_inp_str;
    
    size_t __gmpf_inp_str (mpf_ptr, FILE *, int);
    
    
    alias mpf_integer_p = __gmpf_integer_p;
    int __gmpf_integer_p (mpf_srcptr);
    
    alias mpf_mul = __gmpf_mul;
    void __gmpf_mul (mpf_ptr, mpf_srcptr, mpf_srcptr);
    
    alias mpf_mul_2exp = __gmpf_mul_2exp;
    void __gmpf_mul_2exp (mpf_ptr, mpf_srcptr, uint);
    
    alias mpf_mul_ui = __gmpf_mul_ui;
    void __gmpf_mul_ui (mpf_ptr, mpf_srcptr, uint);
    
    alias mpf_neg = __gmpf_neg;
    void __gmpf_neg (mpf_ptr, mpf_srcptr);
    
    alias mpf_out_str = __gmpf_out_str;
    
    size_t __gmpf_out_str (FILE *, int, size_t, mpf_srcptr);
    
    
    alias mpf_pow_ui = __gmpf_pow_ui;
    void __gmpf_pow_ui (mpf_ptr, mpf_srcptr, uint);
    
    alias mpf_random2 = __gmpf_random2;
    void __gmpf_random2 (mpf_ptr, mp_size_t, mp_exp_t);
    
    alias mpf_reldiff = __gmpf_reldiff;
    void __gmpf_reldiff (mpf_ptr, mpf_srcptr, mpf_srcptr);
    
    alias mpf_set = __gmpf_set;
    void __gmpf_set (mpf_ptr, mpf_srcptr);
    
    alias mpf_set_d = __gmpf_set_d;
    void __gmpf_set_d (mpf_ptr, double);
    
    alias mpf_set_default_prec = __gmpf_set_default_prec;
    void __gmpf_set_default_prec (uint);
    
    alias mpf_set_prec = __gmpf_set_prec;
    void __gmpf_set_prec (mpf_ptr, uint);
    
    alias mpf_set_prec_raw = __gmpf_set_prec_raw;
    void __gmpf_set_prec_raw (mpf_ptr, uint);
    
    alias mpf_set_q = __gmpf_set_q;
    void __gmpf_set_q (mpf_ptr, mpq_srcptr);
    
    alias mpf_set_si = __gmpf_set_si;
    void __gmpf_set_si (mpf_ptr, int);
    
    alias mpf_set_str = __gmpf_set_str;
    int __gmpf_set_str (mpf_ptr,  char *, int);
    
    alias mpf_set_ui = __gmpf_set_ui;
    void __gmpf_set_ui (mpf_ptr, uint);
    
    alias mpf_set_z = __gmpf_set_z;
    void __gmpf_set_z (mpf_ptr, mpz_srcptr);
    
    alias mpf_size = __gmpf_size;
    size_t __gmpf_size (mpf_srcptr);
    
    alias mpf_sqrt = __gmpf_sqrt;
    void __gmpf_sqrt (mpf_ptr, mpf_srcptr);
    
    alias mpf_sqrt_ui = __gmpf_sqrt_ui;
    void __gmpf_sqrt_ui (mpf_ptr, uint);
    
    alias mpf_sub = __gmpf_sub;
    void __gmpf_sub (mpf_ptr, mpf_srcptr, mpf_srcptr);
    
    alias mpf_sub_ui = __gmpf_sub_ui;
    void __gmpf_sub_ui (mpf_ptr, mpf_srcptr, uint);
    
    alias mpf_swap = __gmpf_swap;
    void __gmpf_swap (mpf_ptr, mpf_ptr);
    
    alias mpf_trunc = __gmpf_trunc;
    void __gmpf_trunc (mpf_ptr, mpf_srcptr);
    
    alias mpf_ui_div = __gmpf_ui_div;
    void __gmpf_ui_div (mpf_ptr, uint, mpf_srcptr);
    
    alias mpf_ui_sub = __gmpf_ui_sub;
    void __gmpf_ui_sub (mpf_ptr, uint, mpf_srcptr);
    
    alias mpf_urandomb = __gmpf_urandomb;
    void __gmpf_urandomb (mpf_t, gmp_randstate_t, uint);
    
    
}
