/**
* Compile-time constants for conditional compilation
* 
* Copyright:
* (C) 2014-2015 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.constants;

public import botan_math.mp_types;
enum LogLevel = Debug;

// FocusTests: `dub test --d-version=FocusTests --d-version=Test_RSA` (see
// scripts/test-focus.ps1). Without FocusTests every SKIP_* stays false (except
// CVC, which keeps its existing hole).
version (FocusTests) enum BOTAN_FOCUS_TESTS = true;
else                 enum BOTAN_FOCUS_TESTS = false;

private mixin template BotanSkipTest(string skipIdent, string testVersion, bool defaultSkip = false)
{
    static if (defaultSkip)
        mixin("version (FocusTests) {\n"
            ~ "    version (" ~ testVersion ~ ") enum " ~ skipIdent ~ " = false;\n"
            ~ "    else enum " ~ skipIdent ~ " = true;\n"
            ~ "} else enum " ~ skipIdent ~ " = true;\n");
    else
        mixin("version (FocusTests) {\n"
            ~ "    version (" ~ testVersion ~ ") enum " ~ skipIdent ~ " = false;\n"
            ~ "    else enum " ~ skipIdent ~ " = true;\n"
            ~ "} else enum " ~ skipIdent ~ " = false;\n");
}

mixin BotanSkipTest!("SKIP_TRANSFORM_TEST", "Test_Transform");
mixin BotanSkipTest!("SKIP_X509_TEST", "Test_X509");
mixin BotanSkipTest!("SKIP_BLOCK_TEST", "Test_Block");
mixin BotanSkipTest!("SKIP_CVC_TEST", "Test_CVC"); // TODO: EAC11 ECDSA Key decoding
mixin BotanSkipTest!("SKIP_CRYPTOBOX_TEST", "Test_CryptoBox");
mixin BotanSkipTest!("SKIP_RFC3394_TEST", "Test_RFC3394");
mixin BotanSkipTest!("SKIP_TSS_TEST", "Test_TSS");
mixin BotanSkipTest!("SKIP_ZFEC_TEST", "Test_ZFEC");
mixin BotanSkipTest!("SKIP_PKCS12_TEST", "Test_PKCS12");
mixin BotanSkipTest!("SKIP_HASH_TEST", "Test_Hash");
mixin BotanSkipTest!("SKIP_XOF_TEST", "Test_XOF");
mixin BotanSkipTest!("SKIP_KDF_TEST", "Test_KDF");
mixin BotanSkipTest!("SKIP_COMPRESSION_TEST", "Test_Compression");
mixin BotanSkipTest!("SKIP_MAC_TEST", "Test_MAC");
mixin BotanSkipTest!("SKIP_BIGINT_TEST", "Test_BigInt");
mixin BotanSkipTest!("SKIP_EC_GFP_TEST", "Test_EC_GFP");
mixin BotanSkipTest!("SKIP_AEAD_TEST", "Test_AEAD");
mixin BotanSkipTest!("SKIP_OCB_TEST", "Test_OCB");
mixin BotanSkipTest!("SKIP_CIPHER_MODE_TEST", "Test_CipherMode");
mixin BotanSkipTest!("SKIP_BCRYPT_TEST", "Test_Bcrypt");
mixin BotanSkipTest!("SKIP_PASSHASH9_TEST", "Test_PassHash9");
mixin BotanSkipTest!("SKIP_PBKDF_TEST", "Test_PBKDF");
mixin BotanSkipTest!("SKIP_ARGON2_FMT_TEST", "Test_Argon2Fmt");
mixin BotanSkipTest!("SKIP_HKDF_TEST", "Test_HKDF");
mixin BotanSkipTest!("SKIP_CURVE25519_TEST", "Test_Curve25519");
mixin BotanSkipTest!("SKIP_ED25519_TEST", "Test_Ed25519");
mixin BotanSkipTest!("SKIP_ED448_TEST", "Test_Ed448");
mixin BotanSkipTest!("SKIP_X448_TEST", "Test_X448");
mixin BotanSkipTest!("SKIP_SM2_TEST", "Test_SM2");
mixin BotanSkipTest!("SKIP_ML_KEM_TEST", "Test_ML_KEM");
mixin BotanSkipTest!("SKIP_ML_DSA_TEST", "Test_ML_DSA");
mixin BotanSkipTest!("SKIP_SLH_DSA_TEST", "Test_SLH_DSA");
mixin BotanSkipTest!("SKIP_FRODOKEM_TEST", "Test_FRODOKEM");
mixin BotanSkipTest!("SKIP_XMSS_TEST", "Test_XMSS");
mixin BotanSkipTest!("SKIP_HSS_LMS_TEST", "Test_HSS_LMS");
mixin BotanSkipTest!("SKIP_HYBRID_KEM_TEST", "Test_HYBRID_KEM");
mixin BotanSkipTest!("SKIP_CMCE_TEST", "Test_CMCE");
mixin BotanSkipTest!("SKIP_ECGDSA_TEST", "Test_ECGDSA");
mixin BotanSkipTest!("SKIP_ECKCDSA_TEST", "Test_ECKCDSA");
mixin BotanSkipTest!("SKIP_ECIES_TEST", "Test_ECIES");
mixin BotanSkipTest!("SKIP_DH_TEST", "Test_DH");
mixin BotanSkipTest!("SKIP_DLIES_TEST", "Test_DLIES");
mixin BotanSkipTest!("SKIP_DSA_TEST", "Test_DSA");
mixin BotanSkipTest!("SKIP_ECDH_TEST", "Test_ECDH");
mixin BotanSkipTest!("SKIP_ECDSA_TEST", "Test_ECDSA");
mixin BotanSkipTest!("SKIP_ELGAMAL_TEST", "Test_ElGamal");
mixin BotanSkipTest!("SKIP_GOST_TEST", "Test_GOST");
mixin BotanSkipTest!("SKIP_NR_TEST", "Test_NR");
mixin BotanSkipTest!("SKIP_RFC6979_TEST", "Test_RFC6979");
mixin BotanSkipTest!("SKIP_RSA_TEST", "Test_RSA");
mixin BotanSkipTest!("SKIP_RW_TEST", "Test_RW");
mixin BotanSkipTest!("SKIP_X509_KEY_TEST", "Test_X509_Key");
mixin BotanSkipTest!("SKIP_RNG_TEST", "Test_RNG");
mixin BotanSkipTest!("SKIP_SYSTEM_RNG_TEST", "Test_System_RNG");
mixin BotanSkipTest!("SKIP_PROCESSOR_RNG_TEST", "Test_Processor_RNG");
mixin BotanSkipTest!("SKIP_ENTROPY_RDSEED_TEST", "Test_Entropy_Rdseed");
mixin BotanSkipTest!("SKIP_ENTROPY_GETENTROPY_TEST", "Test_Entropy_Getentropy");
mixin BotanSkipTest!("SKIP_STREAM_CIPHER_TEST", "Test_Stream");
mixin BotanSkipTest!("SKIP_HOTP_TEST", "Test_HOTP");
mixin BotanSkipTest!("SKIP_BASE32_TEST", "Test_Base32");
mixin BotanSkipTest!("SKIP_BASE58_TEST", "Test_Base58");
mixin BotanSkipTest!("SKIP_BASE64_TEST", "Test_Base64");
mixin BotanSkipTest!("SKIP_FPE_TEST", "Test_FPE");
mixin BotanSkipTest!("SKIP_NIST_KEYWRAP_TEST", "Test_NIST_Keywrap");
mixin BotanSkipTest!("SKIP_EME_RAW_TEST", "Test_EME_RAW");
mixin BotanSkipTest!("SKIP_CHACHA_RNG_TEST", "Test_ChaCha_RNG");
mixin BotanSkipTest!("SKIP_SPAKE2P_TEST", "Test_SPAKE2P");
mixin BotanSkipTest!("SKIP_SRP6_TEST", "Test_SRP6");
mixin BotanSkipTest!("SKIP_ISO9796_TEST", "Test_ISO9796");
mixin BotanSkipTest!("SKIP_TLS_TEST", "Test_TLS");
mixin BotanSkipTest!("SKIP_ASN1_TEST", "Test_ASN1");
mixin BotanSkipTest!("SKIP_WORKFACTOR_TEST", "Test_Workfactor");
mixin BotanSkipTest!("SKIP_CHARSET_TEST", "Test_Charset");
mixin BotanSkipTest!("SKIP_PARSING_TEST", "Test_Parsing");
mixin BotanSkipTest!("SKIP_CALENDAR_TEST", "Test_Calendar");
mixin BotanSkipTest!("SKIP_ROUGHTIME_TEST", "Test_Roughtime");

version(CanTest)     {    enum BOTAN_HAS_TESTS = true;                                                         }
else                      enum BOTAN_HAS_TESTS = false;


// D package / release identifiers (match dub.json and git tag v3.13.1)
enum BOTAN_VERSION_MAJOR = 3;
enum BOTAN_VERSION_MINOR = 13;
enum BOTAN_VERSION_PATCH = 1;
enum BOTAN_VERSION_DATESTAMP = 20260817;
enum BOTAN_VERSION_RELEASE_TYPE = "release";
enum BOTAN_VERSION_VC_REVISION = "git:v3.13.1";
enum BOTAN_DISTRIBUTION_INFO = "etcimon/botan";

enum BOTAN_TARGET_CPU_HAS_KNOWN_ENDIANNESS = true;
enum BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK = true;
enum BOTAN_TARGET_HAS_NATIVE_UINT128 = false;
enum DEFAULT_BUFFERSIZE = 4096;
enum TLS_DEFAULT_BUFFERSIZE = 4096;

enum BOTAN_MEM_POOL_CHUNK_SIZE = 64*1024;
enum BOTAN_BLOCK_CIPHER_PAR_MULT = 4;

enum BOTAN_KARAT_MUL_THRESHOLD = 32;
enum BOTAN_KARAT_SQR_THRESHOLD = 32;
enum BOTAN_RNG_MAX_OUTPUT_BEFORE_RESEED = 512;
enum BOTAN_RNG_RESEED_POLL_BITS = 128;

version(Cipher_Mode_Padding) { enum BOTAN_HAS_CIPHER_MODE_PADDING = true; }
else                         enum BOTAN_HAS_CIPHER_MODE_PADDING = false;
version(Auto_Seeding_RNG)    { enum BOTAN_HAS_AUTO_SEEDING_RNG = true; }
else                         enum BOTAN_HAS_AUTO_SEEDING_RNG = false;
version(Codec_Filters)       { enum BOTAN_HAS_CODEC_FILTERS = true; }
else                         enum BOTAN_HAS_CODEC_FILTERS = false;
version(HKDF)                { enum BOTAN_HAS_HKDF = true; }
else                         enum BOTAN_HAS_HKDF = false;
// Listed on lite/pubkey/hash; reserved for a locking allocator backend.
// No in-tree consumer yet — the identifier must still map here.
version(Locking_Allocator)   { enum BOTAN_HAS_LOCKING_ALLOCATOR = true; }
else                         enum BOTAN_HAS_LOCKING_ALLOCATOR = false;

// Constant-time helpers (`botan.utils.ct`, padding unpad, codec lookup,
// HMAC short-key schedule, `sameMem`). Same shape as algorithm flags:
// default off (`No_CT`) for speed; enable with `version(CT)` /
// `--d-version=CT` / `"versions": ["CT"]`. `version(No_CT)` is explicit
// and is the default. Mutually exclusive with `CT`. Implementation
// files use `static if (BOTAN_HAS_CT)`, never `version(CT)` / `version(No_CT)`.
version(CT)
{
    version(No_CT) static assert(false, "CT and No_CT are mutually exclusive");
    enum BOTAN_HAS_CT = true;
}
else                         { enum BOTAN_HAS_CT = false; }

version (unittest)     enum BOTAN_TEST = true;
else                   enum BOTAN_TEST = false;

version(D_InlineAsm_X86) {    enum BOTAN_HAS_DMD_X86_INLINE_ASM = true;                                                  
                              enum BOTAN_HAS_DMD_X86_64_INLINE_ASM = false;                                              }
else version(D_InlineAsm_X86_64){  enum BOTAN_HAS_DMD_X86_INLINE_ASM = false; 
                              enum BOTAN_HAS_DMD_X86_64_INLINE_ASM = true;                                               }
else                     {    enum BOTAN_HAS_DMD_X86_INLINE_ASM = false;
                              enum BOTAN_HAS_DMD_X86_64_INLINE_ASM = false;                                              }

version(FORCE_SSE4)      {    enum BOTAN_FORCE_SSE4 = true;                                                              }
else                          enum BOTAN_FORCE_SSE4 = false;
version(SIMD_SSE2)       {    enum BOTAN_HAS_SIMD_SSE2 = true;          static assert(BOTAN_HAS_SIMD);                   }
else                          enum BOTAN_HAS_SIMD_SSE2 = false;
version(SIMD_Altivec)    {    static if (BOTAN_TARGET_CPU_IS_PPC_FAMILY) 
                                  enum BOTAN_HAS_SIMD_ALTIVEC = true;
                              else enum BOTAN_HAS_SIMD_ALTIVEC = false;                                                  }
else                              enum BOTAN_HAS_SIMD_ALTIVEC = false;
version(SIMD_Scalar)     {    enum BOTAN_HAS_SIMD_SCALAR = true;                                                         }
else                          enum BOTAN_HAS_SIMD_SCALAR = false;

static if (BOTAN_HAS_SIMD_SCALAR || BOTAN_HAS_SIMD_ALTIVEC || BOTAN_HAS_SIMD_SSE2)
    enum BOTAN_HAS_SIMD_OPS = true;
else
    enum BOTAN_HAS_SIMD_OPS = false;

static if (BOTAN_HAS_X86_ARCH && BOTAN_HAS_SIMD_SSE2) pragma(msg, "Error: SIMD_SSE2 cannot be enabled on x86 architecture.");

version(No_SSE_Intrinsics){   enum BOTAN_NO_SSE_INTRINSICS = true;      static assert(!BOTAN_HAS_SIMD_SSE2);             }
else                          enum BOTAN_NO_SSE_INTRINSICS = false;

version(Bench)           {    enum BOTAN_HAS_BENCHMARK = true;                                                           }
else                          enum BOTAN_HAS_BENCHMARK = false;

version(Self_Tests)      {    enum BOTAN_HAS_SELFTESTS = true;                                                           }
else                           enum BOTAN_HAS_SELFTESTS = false;
version(RT_Test)         {    enum BOTAN_PUBLIC_KEY_STRONG_CHECKS_ON_LOAD = true;                                        }
else                          enum BOTAN_PUBLIC_KEY_STRONG_CHECKS_ON_LOAD = false;
version(RT_Test_Priv)    {    enum BOTAN_PRIVATE_KEY_STRONG_CHECKS_ON_LOAD = true;                                       }
else                          enum BOTAN_PRIVATE_KEY_STRONG_CHECKS_ON_LOAD = false;
version(RT_Test_Priv_Gen){    enum BOTAN_PRIVATE_KEY_STRONG_CHECKS_ON_GENERATE = true;                                   }
else                          enum BOTAN_PRIVATE_KEY_STRONG_CHECKS_ON_GENERATE = false;
version(PUBKEY)          {    enum BOTAN_HAS_PUBLIC_KEY_CRYPTO = true;                                                   }
else                          enum BOTAN_HAS_PUBLIC_KEY_CRYPTO = false;
version(TLS)             {    enum BOTAN_HAS_TLS = true;                                                                 }
else                          enum BOTAN_HAS_TLS = false;
version(TLS_13)          {    enum BOTAN_HAS_TLS_13 = true; static assert(BOTAN_HAS_TLS, "TLS_13 requires TLS");          }
else                          enum BOTAN_HAS_TLS_13 = false;
version(TLS_NULL)        {    enum BOTAN_HAS_TLS_NULL = true; static assert(BOTAN_HAS_TLS, "TLS_NULL requires TLS");      }
else                          enum BOTAN_HAS_TLS_NULL = false;
version(X509)            {    enum BOTAN_HAS_X509_CERTIFICATES = true;                                                   }
else                          enum BOTAN_HAS_X509_CERTIFICATES = false;
version(OCSP_Staple)     {    enum BOTAN_HAS_OCSP_STAPLE = true;
                              static assert(BOTAN_HAS_TLS, "OCSP_Staple requires TLS");
                              static assert(BOTAN_HAS_X509_CERTIFICATES, "OCSP_Staple requires X509"); }
else                          enum BOTAN_HAS_OCSP_STAPLE = false;
version(CertStore_Flatfile){  enum BOTAN_HAS_CERTSTORE_FLATFILE = true;                                                  }
else                          enum BOTAN_HAS_CERTSTORE_FLATFILE = false;
version(CertStore_System)  {  enum BOTAN_HAS_CERTSTORE_SYSTEM = true;                                                    }
else                          enum BOTAN_HAS_CERTSTORE_SYSTEM = false;
version(CVC)             {    enum BOTAN_HAS_CARD_VERIFIABLE_CERTIFICATES = true;                                        }
else                          enum BOTAN_HAS_CARD_VERIFIABLE_CERTIFICATES = false;
version(SQLite)          {    enum BOTAN_HAS_SQLITE = true;                                                              }
else                          enum BOTAN_HAS_SQLITE = false;
version(AONT)            {    enum BOTAN_HAS_AONT = true;                                                                }
else                          enum BOTAN_HAS_AONT = false;
version(CryptoBox)       {    enum BOTAN_HAS_CRYPTOBOX = true;                                                           }
else                          enum BOTAN_HAS_CRYPTOBOX = false;
version(CryptoBox_PSK)   {    enum BOTAN_HAS_CRYPTOBOX_PSK = true;                                                       }
else                          enum BOTAN_HAS_CRYPTOBOX_PSK = false;
version(FPE_FE1)         {    enum BOTAN_HAS_FPE_FE1 = true;                                                             }
else                          enum BOTAN_HAS_FPE_FE1 = false;
version(RFC3394)         {    enum BOTAN_HAS_RFC3394_KEYWRAP = true;                                                     }
else                          enum BOTAN_HAS_RFC3394_KEYWRAP = false;
version(HOTP)            {    enum BOTAN_HAS_HOTP = true;                                                                }
else version(TOTP)       {    enum BOTAN_HAS_HOTP = true;                                                                }
else                          enum BOTAN_HAS_HOTP = false;
enum BOTAN_HAS_TOTP = BOTAN_HAS_HOTP;
version(SPAKE2P)         {    enum BOTAN_HAS_SPAKE2P = true;                                                             }
else                          enum BOTAN_HAS_SPAKE2P = false;
version(Roughtime)       {    enum BOTAN_HAS_ROUGHTIME = true;
                              static assert(BOTAN_HAS_PUBLIC_KEY_CRYPTO, "Roughtime requires PUBKEY");
                              static assert(BOTAN_HAS_ED25519, "Roughtime requires Ed25519");
                              static assert(BOTAN_HAS_SHA2_64, "Roughtime requires SHA2_64"); }
else                          enum BOTAN_HAS_ROUGHTIME = false;
version(Base32)          {    enum BOTAN_HAS_BASE32 = true;                                                              }
else                          enum BOTAN_HAS_BASE32 = false;
version(Base58)          {    enum BOTAN_HAS_BASE58 = true;                                                              }
else                          enum BOTAN_HAS_BASE58 = false;
version(NIST_Keywrap)    {    enum BOTAN_HAS_NIST_KEYWRAP = true;                                                        }
else                          enum BOTAN_HAS_NIST_KEYWRAP = false;
version(PassHash9)       {    enum BOTAN_HAS_PASSHASH9 = true;                                                           }
else                          enum BOTAN_HAS_PASSHASH9 = false;
version(BCrypt)          {    enum BOTAN_HAS_BCRYPT = true;                                                              }
else                          enum BOTAN_HAS_BCRYPT = false;
version(SRP6)            {    enum BOTAN_HAS_SRP6 = true;                                                                }
else                          enum BOTAN_HAS_SRP6 = false;
version(TSS)             {    enum BOTAN_HAS_THRESHOLD_SECRET_SHARING = true;                                            }
else                          enum BOTAN_HAS_THRESHOLD_SECRET_SHARING = false;
version(ZFEC)            {    enum BOTAN_HAS_ZFEC = true;                                                                }
else                          enum BOTAN_HAS_ZFEC = false;
version(KDF1)            {    enum BOTAN_HAS_KDF1 = true;                                                                }
else                          enum BOTAN_HAS_KDF1 = false;
version(KDF2)            {    enum BOTAN_HAS_KDF2 = true;                                                                }
else                          enum BOTAN_HAS_KDF2 = false;
version(X942_PRF)        {    enum BOTAN_HAS_X942_PRF = true;                                                            }
else                          enum BOTAN_HAS_X942_PRF = false;
version(SSL_V3_PRF)      {    enum BOTAN_HAS_SSL_V3_PRF = true;                                                          }
else                          enum BOTAN_HAS_SSL_V3_PRF = false;
version(TLS_V10_PRF)     {    enum BOTAN_HAS_TLS_V10_PRF = true;                                                         }
else                          enum BOTAN_HAS_TLS_V10_PRF = false;
version(TLS_V12_PRF)     {    enum BOTAN_HAS_TLS_V12_PRF = true;                                                         }
else                          enum BOTAN_HAS_TLS_V12_PRF = false;
version(SP800_108)       {    enum BOTAN_HAS_SP800_108 = true;                                                           }
else                          enum BOTAN_HAS_SP800_108 = false;
version(SP800_56A)       {    enum BOTAN_HAS_SP800_56A = true;                                                           }
else                          enum BOTAN_HAS_SP800_56A = false;
version(SP800_56C)       {    enum BOTAN_HAS_SP800_56C = true;                                                           }
else                          enum BOTAN_HAS_SP800_56C = false;
version(KDF1_18033)      {    enum BOTAN_HAS_KDF1_18033 = true;                                                          }
else                          enum BOTAN_HAS_KDF1_18033 = false;
version(XMD)             {    enum BOTAN_HAS_XMD = true;                                                                 }
else                          enum BOTAN_HAS_XMD = false;
version(AES_NI)          {    enum BOTAN_HAS_AES_NI = true;            static assert(BOTAN_HAS_SIMD);                    }
else                          enum BOTAN_HAS_AES_NI = false;
version(MD4_x86_32)      {    enum BOTAN_HAS_MD4_X86_32 = true;        static assert(BOTAN_HAS_X86_ARCH, ERR_ARCH);      }
else                          enum BOTAN_HAS_MD4_X86_32 = false;
version(MD5_x86_32)      {    enum BOTAN_HAS_MD5_X86_32 = true;        static assert(BOTAN_HAS_X86_ARCH, ERR_ARCH);      }
else                          enum BOTAN_HAS_MD5_X86_32 = false;
version(SHA1_x86_64)     {    enum BOTAN_HAS_SHA1_X86_64 = true;       static assert(BOTAN_HAS_X86_64_ARCH, ERR_ARCH);   }
else                          enum BOTAN_HAS_SHA1_X86_64 = false;
version(SHA1_x86_32)     {    enum BOTAN_HAS_SHA1_X86_32 = true;       static assert(BOTAN_HAS_X86_ARCH, ERR_ARCH);      }
else                          enum BOTAN_HAS_SHA1_X86_32 = false;
version(CFB)             {    enum BOTAN_HAS_MODE_CFB = true;                                                            }
else                          enum BOTAN_HAS_MODE_CFB = false;
version(ECB)             {    enum BOTAN_HAS_MODE_ECB = true;                                                            }
else                          enum BOTAN_HAS_MODE_ECB = false;
version(CBC)             {    enum BOTAN_HAS_MODE_CBC = true;                                                            }
else                          enum BOTAN_HAS_MODE_CBC = false;
version(XTS)             {    enum BOTAN_HAS_MODE_XTS = true;                                                            }
else                          enum BOTAN_HAS_MODE_XTS = false;
version(OFB)             {    enum BOTAN_HAS_OFB = true;                                                                 }
else                          enum BOTAN_HAS_OFB = false;
version(CTR_BE)          {    enum BOTAN_HAS_CTR_BE = true;                                                              }
else                          enum BOTAN_HAS_CTR_BE = false;
version(AEAD_FILTER)     {    enum BOTAN_HAS_AEAD_FILTER = true;                                                         }
else                          enum BOTAN_HAS_AEAD_FILTER = false;
version(AEAD_CCM)        {    enum BOTAN_HAS_AEAD_CCM = true;                                                            }
else                          enum BOTAN_HAS_AEAD_CCM = false;
version(AEAD_EAX)        {    enum BOTAN_HAS_AEAD_EAX = true;                                                            }
else                          enum BOTAN_HAS_AEAD_EAX = false;
version(AEAD_OCB)        {    enum BOTAN_HAS_AEAD_OCB = true;                                                            }
else                          enum BOTAN_HAS_AEAD_OCB = false;
version(AEAD_GCM)        {    enum BOTAN_HAS_AEAD_GCM = true;                                                            }
else                          enum BOTAN_HAS_AEAD_GCM = false;
version(AEAD_SIV)        {    enum BOTAN_HAS_AEAD_SIV = true;                                                            }
else                          enum BOTAN_HAS_AEAD_SIV = false;
version(AEAD_GCM_SIV)    {    enum BOTAN_HAS_AEAD_GCM_SIV = true;                                                        }
else                          enum BOTAN_HAS_AEAD_GCM_SIV = false;
version(AEAD_ASCON128)   {    enum BOTAN_HAS_AEAD_ASCON128 = true;                                                       }
else                          enum BOTAN_HAS_AEAD_ASCON128 = false;
version(AEAD_CHACHA20_POLY1305){enum BOTAN_HAS_AEAD_CHACHA20_POLY1305 = true;                                            }
else                          enum BOTAN_HAS_AEAD_CHACHA20_POLY1305 = false;

version(RFC6979)         {    enum BOTAN_HAS_RFC6979_GENERATOR = true;                                                   }
else                          enum BOTAN_HAS_RFC6979_GENERATOR = false;
version(RSA)             {    enum BOTAN_HAS_RSA = true;                                                                 }
else                          enum BOTAN_HAS_RSA = false;
version(RSA_Insecure)    {    enum BOTAN_HAS_RSA_INSECURE = true;                                                        }
else                          enum BOTAN_HAS_RSA_INSECURE = false;
version(RW)              {    enum BOTAN_HAS_RW = true;                                                                  }
else                          enum BOTAN_HAS_RW = false;
version(DLIES)           {    enum BOTAN_HAS_DLIES = true;                                                               }
else                          enum BOTAN_HAS_DLIES = false;                                                            
version(DSA)             {    enum BOTAN_HAS_DSA = true;                                                                 }
else                          enum BOTAN_HAS_DSA = false;
version(ECDSA)           {    enum BOTAN_HAS_ECDSA = true;                                                               }
else                          enum BOTAN_HAS_ECDSA = false;
version(ElGamal)         {    enum BOTAN_HAS_ELGAMAL = true;                                                             }
else                          enum BOTAN_HAS_ELGAMAL = false;
version(GOST_3410)       {    enum BOTAN_HAS_GOST_34_10_2001 = true;                                                     }
else                          enum BOTAN_HAS_GOST_34_10_2001 = false;
version(Nyberg_Rueppel)  {    enum BOTAN_HAS_NYBERG_RUEPPEL = true;                                                      }
else                          enum BOTAN_HAS_NYBERG_RUEPPEL = false;
version(Diffie_Hellman)  {    enum BOTAN_HAS_DIFFIE_HELLMAN = true;                                                      }
else                          enum BOTAN_HAS_DIFFIE_HELLMAN = false;
version(ECDH)            {    enum BOTAN_HAS_ECDH = true;                                                                }
else                          enum BOTAN_HAS_ECDH = false;
version(Curve25519)      {    enum BOTAN_HAS_CURVE25519 = true;                                                          }
else version(X25519)     {    enum BOTAN_HAS_CURVE25519 = true;                                                          }
else                          enum BOTAN_HAS_CURVE25519 = false;
enum BOTAN_HAS_X25519 = BOTAN_HAS_CURVE25519;
version(Ed25519)         {    enum BOTAN_HAS_ED25519 = true;                                                             }
else                          enum BOTAN_HAS_ED25519 = false;
version(Ed448)           {
                              // 7×64-bit field / scalar; 32-bit `word` cannot hold the limbs.
                              static if (BOTAN_MP_WORD_BITS == 64)
                                  enum BOTAN_HAS_ED448 = true;
                              else
                                  enum BOTAN_HAS_ED448 = false;
                         }
else                          enum BOTAN_HAS_ED448 = false;
version(X448)            {
                              static if (BOTAN_MP_WORD_BITS == 64)
                                  enum BOTAN_HAS_X448 = true;
                              else
                                  enum BOTAN_HAS_X448 = false;
                         }
else                          enum BOTAN_HAS_X448 = false;
version(SM2)             {    enum BOTAN_HAS_SM2 = true;                                                                 }
else                          enum BOTAN_HAS_SM2 = false;
version(ECGDSA)          {    enum BOTAN_HAS_ECGDSA = true;                                                              }
else                          enum BOTAN_HAS_ECGDSA = false;
version(ECKCDSA)         {    enum BOTAN_HAS_ECKCDSA = true;                                                             }
else                          enum BOTAN_HAS_ECKCDSA = false;
version(ECIES)           {    enum BOTAN_HAS_ECIES = true;                                                               }
else                          enum BOTAN_HAS_ECIES = false;
version(AES)             {    enum BOTAN_HAS_AES = true;                                                                 }
else                          enum BOTAN_HAS_AES = false;
version(Blowfish)        {    enum BOTAN_HAS_BLOWFISH = true;                                                            }
else                          enum BOTAN_HAS_BLOWFISH = false;
version(Camellia)        {    enum BOTAN_HAS_CAMELLIA = true;                                                            }
else                          enum BOTAN_HAS_CAMELLIA = false;
version(ARIA)            {    enum BOTAN_HAS_ARIA = true;                                                                }
else                          enum BOTAN_HAS_ARIA = false;
version(SHACAL2)         {    enum BOTAN_HAS_SHACAL2 = true;                                                             }
else                          enum BOTAN_HAS_SHACAL2 = false;
version(SM4)             {    enum BOTAN_HAS_SM4 = true;                                                                 }
else                          enum BOTAN_HAS_SM4 = false;
version(Kuznyechik)      {    enum BOTAN_HAS_KUZNYECHIK = true;                                                          }
else                          enum BOTAN_HAS_KUZNYECHIK = false;
version(CAST)            {    enum BOTAN_HAS_CAST = true;                                                                }
else                          enum BOTAN_HAS_CAST = false;
version(Cascade)         {    enum BOTAN_HAS_CASCADE = true;                                                             }
else                          enum BOTAN_HAS_CASCADE = false;
version(DES)             {    enum BOTAN_HAS_DES = true;                                                                 }
else                          enum BOTAN_HAS_DES = false;
version(GOST_28147)      {    enum BOTAN_HAS_GOST_28147_89 = true;                                                       }
else                          enum BOTAN_HAS_GOST_28147_89 = false;
version(IDEA)            {    enum BOTAN_HAS_IDEA = true;                                                                }
else                          enum BOTAN_HAS_IDEA = false;
version(KASUMI)          {    enum BOTAN_HAS_KASUMI = true;                                                              }
else                          enum BOTAN_HAS_KASUMI = false;
version(LION)            {    enum BOTAN_HAS_LION = true;                                                                }
else                          enum BOTAN_HAS_LION = false;
version(MARS)            {    enum BOTAN_HAS_MARS = true;                                                                }
else                          enum BOTAN_HAS_MARS = false;
version(MISTY1)          {    enum BOTAN_HAS_MISTY1 = true;                                                              }
else                          enum BOTAN_HAS_MISTY1 = false;
version(NOEKEON)         {    enum BOTAN_HAS_NOEKEON = true;                                                             }
else                          enum BOTAN_HAS_NOEKEON = false;
version(RC2)             {    enum BOTAN_HAS_RC2 = true;                                                                 }
else                          enum BOTAN_HAS_RC2 = false;
version(RC5)             {    enum BOTAN_HAS_RC5 = true;                                                                 }
else                          enum BOTAN_HAS_RC5 = false;
version(RC6)             {    enum BOTAN_HAS_RC6 = true;                                                                 }
else                          enum BOTAN_HAS_RC6 = false;
version(SAFER)           {    enum BOTAN_HAS_SAFER = true;                                                               }
else                          enum BOTAN_HAS_SAFER = false;
version(SEED)            {    enum BOTAN_HAS_SEED = true;                                                                }
else                          enum BOTAN_HAS_SEED = false;
version(Serpent)         {    enum BOTAN_HAS_SERPENT = true;                                                             }
else                          enum BOTAN_HAS_SERPENT = false;
version(TEA)             {    enum BOTAN_HAS_TEA = true;                                                                 }
else                          enum BOTAN_HAS_TEA = false;
version(Twofish)         {    enum BOTAN_HAS_TWOFISH = true;                                                             }
else                          enum BOTAN_HAS_TWOFISH = false;
version(Threefish)       {    enum BOTAN_HAS_THREEFISH_512 = true;                                                       }
else                          enum BOTAN_HAS_THREEFISH_512 = false;
version(XTEA)            {    enum BOTAN_HAS_XTEA = true;                                                                }
else                          enum BOTAN_HAS_XTEA = false;
version(Adler32)         {    enum BOTAN_HAS_ADLER32 = true;                                                             }
else                          enum BOTAN_HAS_ADLER32 = false;
version(CRC24)           {    enum BOTAN_HAS_CRC24 = true;                                                               }
else                          enum BOTAN_HAS_CRC24 = false;
version(CRC32)           {    enum BOTAN_HAS_CRC32 = true;                                                               }
else                          enum BOTAN_HAS_CRC32 = false;
version(BLAKE2B)         {    enum BOTAN_HAS_BLAKE2B = true;                                                               }
else                          enum BOTAN_HAS_BLAKE2B = false;
version(BLAKE2S)         {    enum BOTAN_HAS_BLAKE2S = true;                                                               }
else                          enum BOTAN_HAS_BLAKE2S = false;
version(SM3)             {    enum BOTAN_HAS_SM3 = true;                                                                 }
else                          enum BOTAN_HAS_SM3 = false;
version(Ascon_Hash256)   {    enum BOTAN_HAS_ASCON_HASH256 = true;                                                       }
else                          enum BOTAN_HAS_ASCON_HASH256 = false;
version(Ascon_XOF)       {    enum BOTAN_HAS_ASCON_XOF128 = true;                                                        }
else                          enum BOTAN_HAS_ASCON_XOF128 = false;
version(SHAKE_XOF)       {    enum BOTAN_HAS_SHAKE_XOF = true;                                                           }
else                          enum BOTAN_HAS_SHAKE_XOF = false;
version(AES_CTR_XOF)     {    enum BOTAN_HAS_AES_CTR_XOF = true;
                              static assert(BOTAN_HAS_AES, "AES_CTR_XOF requires AES");
                              static assert(BOTAN_HAS_CTR_BE, "AES_CTR_XOF requires CTR_BE"); }
else                          enum BOTAN_HAS_AES_CTR_XOF = false;
version(SHAKE_Cipher)    {    enum BOTAN_HAS_SHAKE_CIPHER = true;                                                        }
else                          enum BOTAN_HAS_SHAKE_CIPHER = false;
version(CSHAKE_XOF)      {    enum BOTAN_HAS_CSHAKE_XOF = true;                                                          }
else                          enum BOTAN_HAS_CSHAKE_XOF = false;
version(Truncated_Hash)  {    enum BOTAN_HAS_TRUNCATED_HASH = true;                                                      }
else                          enum BOTAN_HAS_TRUNCATED_HASH = false;
version(Streebog)        {    enum BOTAN_HAS_STREEBOG = true;                                                            }
else                          enum BOTAN_HAS_STREEBOG = false;
version(GOST_3411)       {    enum BOTAN_HAS_GOST_34_11 = true;                                                          }
else                          enum BOTAN_HAS_GOST_34_11 = false;
version(HAS_160)         {    enum BOTAN_HAS_HAS_160 = true;                                                             }
else                          enum BOTAN_HAS_HAS_160 = false;
version(Keccak)          {    enum BOTAN_HAS_KECCAK = true;                                                              }
else                          enum BOTAN_HAS_KECCAK = false;
version(MD2)             {    enum BOTAN_HAS_MD2 = true;                                                                 }
else                          enum BOTAN_HAS_MD2 = false;
version(MD4)             {    enum BOTAN_HAS_MD4 = true;                                                                 }
else                          enum BOTAN_HAS_MD4 = false;
version(MD5)             {    enum BOTAN_HAS_MD5 = true;                                                                 }
else                          enum BOTAN_HAS_MD5 = false;
version(RIPEMD_128)      {    enum BOTAN_HAS_RIPEMD_128 = true;                                                          }
else                          enum BOTAN_HAS_RIPEMD_128 = false;
version(RIPEMD_160)      {    enum BOTAN_HAS_RIPEMD_160 = true;                                                          }
else                          enum BOTAN_HAS_RIPEMD_160 = false;
version(SHA1)            {    enum BOTAN_HAS_SHA1 = true;                                                                }
else                          enum BOTAN_HAS_SHA1 = false;  
version(SHA2_32)         {    enum BOTAN_HAS_SHA2_32 = true;                                                             }
else                          enum BOTAN_HAS_SHA2_32 = false;
version(SHA2_64)         {    enum BOTAN_HAS_SHA2_64 = true;                                                             }
else                          enum BOTAN_HAS_SHA2_64 = false;
version(SHA3)            {    enum BOTAN_HAS_SHA3 = true;                                                                }
else                          enum BOTAN_HAS_SHA3 = false;
version(ML_KEM)          {    enum BOTAN_HAS_ML_KEM = true;
                              static assert(BOTAN_HAS_PUBLIC_KEY_CRYPTO, "ML_KEM requires PUBKEY");
                              static assert(BOTAN_HAS_SHA3, "ML_KEM requires SHA3");
                              static assert(BOTAN_HAS_SHAKE_XOF, "ML_KEM requires SHAKE_XOF"); }
else                          enum BOTAN_HAS_ML_KEM = false;
version(ML_DSA)          {    enum BOTAN_HAS_ML_DSA = true;
                              static assert(BOTAN_HAS_PUBLIC_KEY_CRYPTO, "ML_DSA requires PUBKEY");
                              static assert(BOTAN_HAS_SHAKE_XOF, "ML_DSA requires SHAKE_XOF"); }
else                          enum BOTAN_HAS_ML_DSA = false;
version(SLH_DSA)         {    enum BOTAN_HAS_SLH_DSA = true;
                              static assert(BOTAN_HAS_PUBLIC_KEY_CRYPTO, "SLH_DSA requires PUBKEY");
                              static assert(BOTAN_HAS_SHAKE_XOF, "SLH_DSA requires SHAKE_XOF");
                              static assert(BOTAN_HAS_SHA2_32, "SLH_DSA requires SHA2_32");
                              static assert(BOTAN_HAS_SHA2_64, "SLH_DSA requires SHA2_64");
                              version(HMAC) {} else static assert(false, "SLH_DSA requires HMAC"); }
else                          enum BOTAN_HAS_SLH_DSA = false;
version(FrodoKEM)        {    enum BOTAN_HAS_FRODOKEM = true;
                              static assert(BOTAN_HAS_PUBLIC_KEY_CRYPTO, "FrodoKEM requires PUBKEY");
                              static assert(BOTAN_HAS_SHAKE_XOF, "FrodoKEM requires SHAKE_XOF"); }
else                          enum BOTAN_HAS_FRODOKEM = false;
version(XMSS)            {    enum BOTAN_HAS_XMSS = true;
                              static assert(BOTAN_HAS_PUBLIC_KEY_CRYPTO, "XMSS requires PUBKEY");
                              static assert(BOTAN_HAS_SHA2_32, "XMSS requires SHA2_32");
                              static assert(BOTAN_HAS_SHA2_64, "XMSS requires SHA2_64");
                              static assert(BOTAN_HAS_TRUNCATED_HASH, "XMSS requires Truncated_Hash");
                              version(Shake) {} else static assert(false, "XMSS requires Shake"); }
else                          enum BOTAN_HAS_XMSS = false;
version(HSS_LMS)         {    enum BOTAN_HAS_HSS_LMS = true;
                              static assert(BOTAN_HAS_PUBLIC_KEY_CRYPTO, "HSS_LMS requires PUBKEY");
                              static assert(BOTAN_HAS_SHA2_32, "HSS_LMS requires SHA2_32");
                              static assert(BOTAN_HAS_TRUNCATED_HASH, "HSS_LMS requires Truncated_Hash");
                              version(Shake) {} else static assert(false, "HSS_LMS requires Shake"); }
else                          enum BOTAN_HAS_HSS_LMS = false;
version(Hybrid_KEM)      {    enum BOTAN_HAS_HYBRID_KEM = true;
                              static assert(BOTAN_HAS_PUBLIC_KEY_CRYPTO, "Hybrid_KEM requires PUBKEY");
                              static assert(BOTAN_HAS_ML_KEM, "Hybrid_KEM requires ML_KEM");
                              static assert(BOTAN_HAS_CURVE25519, "Hybrid_KEM requires Curve25519");
                              static assert(BOTAN_HAS_SHA3, "Hybrid_KEM requires SHA3"); }
else                          enum BOTAN_HAS_HYBRID_KEM = false;
version(TLS_13_PQC)      {    enum BOTAN_HAS_TLS_13_PQC = true;
                              static assert(BOTAN_HAS_TLS_13, "TLS_13_PQC requires TLS_13");
                              static assert(BOTAN_HAS_ML_KEM, "TLS_13_PQC requires ML_KEM");
                              static assert(BOTAN_HAS_CURVE25519, "TLS_13_PQC requires Curve25519"); }
else                          enum BOTAN_HAS_TLS_13_PQC = false;
version(Classic_McEliece) {   enum BOTAN_HAS_CLASSIC_MCELIECE = true;
                              static assert(BOTAN_HAS_PUBLIC_KEY_CRYPTO, "Classic_McEliece requires PUBKEY");
                              static assert(BOTAN_HAS_SHAKE_XOF, "Classic_McEliece requires SHAKE_XOF"); }
else                          enum BOTAN_HAS_CLASSIC_MCELIECE = false;
version(Shake)           {    enum BOTAN_HAS_SHAKE = true;                                                               }
else                          enum BOTAN_HAS_SHAKE = false;
version(Skein_512)       {    enum BOTAN_HAS_SKEIN_512 = true;                                                           }
else                          enum BOTAN_HAS_SKEIN_512 = false;
version(Tiger)           {    enum BOTAN_HAS_TIGER = true;                                                               }
else                          enum BOTAN_HAS_TIGER = false;
version(Whirlpool)       {    enum BOTAN_HAS_WHIRLPOOL = true;                                                           }
else                          enum BOTAN_HAS_WHIRLPOOL = false;
version(ParallelHash)    {    enum BOTAN_HAS_PARALLEL_HASH = true;                                                       }
else                          enum BOTAN_HAS_PARALLEL_HASH = false;
version(Comb4P)          {    enum BOTAN_HAS_COMB4P = true;                                                              }
else                          enum BOTAN_HAS_COMB4P = false;
version(POLY1305)        {    enum BOTAN_HAS_POLY1305 = true;                                                            }
else                          enum BOTAN_HAS_POLY1305 = false;
version(CBC_MAC)         {    enum BOTAN_HAS_CBC_MAC = true;                                                             }
else                          enum BOTAN_HAS_CBC_MAC = false;
version(CMAC)            {    enum BOTAN_HAS_CMAC = true;                                                                }
else                          enum BOTAN_HAS_CMAC = false;
version(HMAC)            {    enum BOTAN_HAS_HMAC = true;                                                                }
else                          enum BOTAN_HAS_HMAC = false;
version(SSL3_MAC)        {    enum BOTAN_HAS_SSL3_MAC = true;                                                            }
else                          enum BOTAN_HAS_SSL3_MAC = false;
version(ANSI_X919_MAC)   {    enum BOTAN_HAS_ANSI_X919_MAC = true;                                                       }
else                          enum BOTAN_HAS_ANSI_X919_MAC = false;
version(SipHash)         {    enum BOTAN_HAS_SIPHASH = true;                                                             }
else                          enum BOTAN_HAS_SIPHASH = false;
version(GMAC)            {    enum BOTAN_HAS_GMAC = true;                                                                }
else                          enum BOTAN_HAS_GMAC = false;
version(KMAC)            {    enum BOTAN_HAS_KMAC = true;                                                                }
else                          enum BOTAN_HAS_KMAC = false;
version(BLAKE2BMAC)      {    enum BOTAN_HAS_BLAKE2BMAC = true;                                                          }
else                          enum BOTAN_HAS_BLAKE2BMAC = false;
version(PBKDF1)          {    enum BOTAN_HAS_PBKDF1 = true;                                                              }
else                          enum BOTAN_HAS_PBKDF1 = false;
version(PBKDF2)          {    enum BOTAN_HAS_PBKDF2 = true;                                                              }
else                          enum BOTAN_HAS_PBKDF2 = false;
version(Argon2)          {    enum BOTAN_HAS_ARGON2 = true;                                                              }
else                          enum BOTAN_HAS_ARGON2 = false;
version(Argon2_Fmt)      {    enum BOTAN_HAS_ARGON2_FMT = true;                                                          }
else                          enum BOTAN_HAS_ARGON2_FMT = false;
version(Scrypt)          {    enum BOTAN_HAS_SCRYPT = true;                                                              }
else                          enum BOTAN_HAS_SCRYPT = false;
version(PBKDF_BCrypt)    {    enum BOTAN_HAS_PBKDF_BCRYPT = true;                                                        }
else                          enum BOTAN_HAS_PBKDF_BCRYPT = false;
version(PGP_S2K)         {    enum BOTAN_HAS_PGP_S2K = true;                                                             }
else                          enum BOTAN_HAS_PGP_S2K = false;
version(PKCS12_KDF)      {    enum BOTAN_HAS_PKCS12_KDF = true;                                                          }
else                          enum BOTAN_HAS_PKCS12_KDF = false;
version(PKCS12)          {    enum BOTAN_HAS_PKCS12 = true;
                              static assert(BOTAN_HAS_X509_CERTIFICATES, "PKCS12 requires X509");
                              static assert(BOTAN_HAS_PUBLIC_KEY_CRYPTO, "PKCS12 requires PUBKEY");
                              static assert(BOTAN_HAS_PKCS12_KDF, "PKCS12 requires PKCS12_KDF"); }
else                          enum BOTAN_HAS_PKCS12 = false;
version(RC4)             {    enum BOTAN_HAS_RC4 = true;                                                                 }
else                          enum BOTAN_HAS_RC4 = false;
version(ChaCha)          {    enum BOTAN_HAS_CHACHA = true;                                                              }
else                          enum BOTAN_HAS_CHACHA = false;
version(Salsa20)         {    enum BOTAN_HAS_SALSA20 = true;                                                             }
else                          enum BOTAN_HAS_SALSA20 = false;
version(AES_SSSE3)       {    debug enum BOTAN_HAS_AES_SSSE3 = true;     static assert(BOTAN_HAS_SIMD);                  }
else                          enum BOTAN_HAS_AES_SSSE3 = false;
version(Serpent_SIMD)    {    enum BOTAN_HAS_SERPENT_SIMD = true;        static assert(BOTAN_HAS_SIMD_OPS);              }
else                          enum BOTAN_HAS_SERPENT_SIMD = false;
version(Threefish_512_AVX2){  enum BOTAN_HAS_THREEFISH_512_AVX2 = true;  static assert(BOTAN_HAS_SIMD_ALTIVEC);          }
else                          enum BOTAN_HAS_THREEFISH_512_AVX2 = false;
version(Noekeon_SIMD)    {    enum BOTAN_HAS_NOEKEON_SIMD = true;        static assert(BOTAN_HAS_SIMD_OPS);              }
else                          enum BOTAN_HAS_NOEKEON_SIMD = false;
version(XTEA_SIMD)       {    enum BOTAN_HAS_XTEA_SIMD = true;           static assert(BOTAN_HAS_SIMD_OPS);              }
else                          enum BOTAN_HAS_XTEA_SIMD = false;
version(IDEA_SSE2 )      {    enum BOTAN_HAS_IDEA_SSE2 = true;           static assert(BOTAN_HAS_SIMD);                  }
else                          enum BOTAN_HAS_IDEA_SSE2 = false;
version(SHA1_SSE2)       {    enum BOTAN_HAS_SHA1_SSE2 = true;           static assert(BOTAN_HAS_SIMD);                  }
else                          enum BOTAN_HAS_SHA1_SSE2 = false;
version(SHA2_32_SSE2)    {    enum BOTAN_HAS_SHA2_32_SSE2 = true;
                              static assert(BOTAN_HAS_SHA2_32, "SHA2_32_SSE2 requires SHA2_32");
                              static assert(BOTAN_HAS_SIMD, "SHA2_32_SSE2 requires SIMD"); }
else                          enum BOTAN_HAS_SHA2_32_SSE2 = false;
version(SHA2_32_X86)     {    enum BOTAN_HAS_SHA2_32_X86 = true;
                              static assert(BOTAN_HAS_SHA2_32, "SHA2_32_X86 requires SHA2_32");
                              static assert(BOTAN_HAS_SIMD, "SHA2_32_X86 requires SIMD"); }
else                          enum BOTAN_HAS_SHA2_32_X86 = false;
version(ChaCha_SIMD)     {    enum BOTAN_HAS_CHACHA_SIMD = true;
                              static assert(BOTAN_HAS_CHACHA, "ChaCha_SIMD requires ChaCha");
                              static assert(BOTAN_HAS_SIMD, "ChaCha_SIMD requires SIMD"); }
else                          enum BOTAN_HAS_CHACHA_SIMD = false;
version(ChaCha_AVX2)     {
                              // x8 body is LDC SIMD (int8 / shufflevector); DMD has no impl.
                              version (LDC) {
                                  enum BOTAN_HAS_CHACHA_AVX2 = true;
                                  static assert(BOTAN_HAS_CHACHA, "ChaCha_AVX2 requires ChaCha");
                              }
                              else enum BOTAN_HAS_CHACHA_AVX2 = false;
                         }
else                          enum BOTAN_HAS_CHACHA_AVX2 = false;
version(SM4_HWAES)       {    enum BOTAN_HAS_SM4_HWAES = true;
                              static assert(BOTAN_HAS_SM4, "SM4_HWAES requires SM4");
                              static assert(BOTAN_HAS_AES_NI, "SM4_HWAES requires AES_NI"); }
else                          enum BOTAN_HAS_SM4_HWAES = false;
version(ARIA_HWAES)      {    enum BOTAN_HAS_ARIA_HWAES = true;
                              static assert(BOTAN_HAS_ARIA, "ARIA_HWAES requires ARIA");
                              static assert(BOTAN_HAS_AES_NI, "ARIA_HWAES requires AES_NI"); }
else                          enum BOTAN_HAS_ARIA_HWAES = false;
version(Camellia_HWAES)  {    enum BOTAN_HAS_CAMELLIA_HWAES = true;
                              static assert(BOTAN_HAS_CAMELLIA, "Camellia_HWAES requires Camellia");
                              static assert(BOTAN_HAS_AES_NI, "Camellia_HWAES requires AES_NI"); }
else                          enum BOTAN_HAS_CAMELLIA_HWAES = false;


version(Engine_ASM)      {    enum BOTAN_HAS_ENGINE_ASSEMBLER = true;                                                    }
else                          enum BOTAN_HAS_ENGINE_ASSEMBLER = false;
version(Engine_AES_ISA)  {    enum BOTAN_HAS_ENGINE_AES_ISA = true;                                                      }
else                          enum BOTAN_HAS_ENGINE_AES_ISA = false;
version(Engine_SIMD)     {    enum BOTAN_HAS_ENGINE_SIMD = true;         static assert(BOTAN_HAS_SIMD);                  }
else                          enum BOTAN_HAS_ENGINE_SIMD = false;
version(Engine_GNU_MP)   {    enum BOTAN_HAS_ENGINE_GNU_MP = true;                                                       }
else                          enum BOTAN_HAS_ENGINE_GNU_MP = false;
version(Engine_OPENSSL)  {    enum BOTAN_HAS_ENGINE_OPENSSL = true;                                                      }
else                          enum BOTAN_HAS_ENGINE_OPENSSL = false;
version(Entropy_HRTimer) {    enum BOTAN_HAS_ENTROPY_SRC_HIGH_RESOLUTION_TIMER = true;                                   }
else                          enum BOTAN_HAS_ENTROPY_SRC_HIGH_RESOLUTION_TIMER = false;
version(Entropy_Rdrand)  {    enum BOTAN_HAS_ENTROPY_SRC_RDRAND = true;                                                  }
else                          enum BOTAN_HAS_ENTROPY_SRC_RDRAND = false;
version(Entropy_Rdseed)  {    enum BOTAN_HAS_ENTROPY_SRC_RDSEED = true;                                                  }
else                          enum BOTAN_HAS_ENTROPY_SRC_RDSEED = false;
version(Entropy_Getentropy){  enum BOTAN_HAS_ENTROPY_SRC_GETENTROPY = true;                                               }
else                          enum BOTAN_HAS_ENTROPY_SRC_GETENTROPY = false;
version(Entropy_DevRand) {    enum BOTAN_HAS_ENTROPY_SRC_DEV_RANDOM = true;                                              }    
else                          enum BOTAN_HAS_ENTROPY_SRC_DEV_RANDOM = false;
version(Entropy_EGD)     {    enum BOTAN_HAS_ENTROPY_SRC_EGD = true;                                                     }
else                          enum BOTAN_HAS_ENTROPY_SRC_EGD = false;
version(Entropy_UnixProc){    enum BOTAN_HAS_ENTROPY_SRC_UNIX_PROCESS_RUNNER = true;                                     }
else                          enum BOTAN_HAS_ENTROPY_SRC_UNIX_PROCESS_RUNNER = false;
version(Entropy_BEOS)    {    enum BOTAN_HAS_ENTROPY_SRC_BEOS = true;                                                    }
else                          enum BOTAN_HAS_ENTROPY_SRC_BEOS = false;
version(Entropy_CAPI)    {    enum BOTAN_HAS_ENTROPY_SRC_CAPI = true;                                                    }
else                          enum BOTAN_HAS_ENTROPY_SRC_CAPI = false;
version(Entropy_Win32)   {    enum BOTAN_HAS_ENTROPY_SRC_WIN32 = true;                                                   }
else                          enum BOTAN_HAS_ENTROPY_SRC_WIN32 = false;
version(Entropy_ProcWalk){    enum BOTAN_HAS_ENTROPY_SRC_PROC_WALKER = true;                                             }
else                          enum BOTAN_HAS_ENTROPY_SRC_PROC_WALKER = false;
version(EMSA1)           {    enum BOTAN_HAS_EMSA1 = true;                                                               }
else                          enum BOTAN_HAS_EMSA1 = false;
version(EMSA1_BSI)       {    enum BOTAN_HAS_EMSA1_BSI = true;                                                           }
else                          enum BOTAN_HAS_EMSA1_BSI = false;
version(EMSA_X931)       {    enum BOTAN_HAS_EMSA_X931 = true;                                                           }
else                          enum BOTAN_HAS_EMSA_X931 = false;
version(EMSA_PKCS1)      {    enum BOTAN_HAS_EMSA_PKCS1 = true;                                                          }
else                          enum BOTAN_HAS_EMSA_PKCS1 = false;
version(EMSA_PSSR)       {    enum BOTAN_HAS_EMSA_PSSR = true;                                                           }
else                          enum BOTAN_HAS_EMSA_PSSR = false;
version(EMSA_RAW)        {    enum BOTAN_HAS_EMSA_RAW = true;                                                            }
else                          enum BOTAN_HAS_EMSA_RAW = false;
version(ISO9796)         {    enum BOTAN_HAS_ISO9796 = true;                                                             }
else                          enum BOTAN_HAS_ISO9796 = false;
version(EME_OAEP)        {    enum BOTAN_HAS_EME_OAEP = true;                                                            }
else                          enum BOTAN_HAS_EME_OAEP = false;
version(EME_PKCS1v15)    {    enum BOTAN_HAS_EME_PKCS1_V15 = true;                                                       }
else                          enum BOTAN_HAS_EME_PKCS1_V15 = false;
version(EME_RAW)         {    enum BOTAN_HAS_EME_RAW = true;                                                             }
else                          enum BOTAN_HAS_EME_RAW = false;
version(PBE_PKCSv20)     {    enum BOTAN_HAS_PBE_PKCS_V20 = true;                                                        }
else                          enum BOTAN_HAS_PBE_PKCS_V20 = false;
version(GCM_CLMUL)       {    enum BOTAN_HAS_GCM_CLMUL = true;            static assert(BOTAN_HAS_SIMD);                 }
else                          enum BOTAN_HAS_GCM_CLMUL = false;   

version(X931_RNG)        {    enum BOTAN_HAS_X931_RNG = true;                                                            }
else                          enum BOTAN_HAS_X931_RNG = false;
version(HMAC_DRBG)       {    enum BOTAN_HAS_HMAC_DRBG = true;                                                           }
else                          enum BOTAN_HAS_HMAC_DRBG = false;
version(Stateful_RNG)    {    enum BOTAN_HAS_STATEFUL_RNG = true;                                                        }
else                          enum BOTAN_HAS_STATEFUL_RNG = false;
version(ChaCha_RNG)      {    enum BOTAN_HAS_CHACHA_RNG = true;                                                          }
else                          enum BOTAN_HAS_CHACHA_RNG = false;
version(System_RNG)      {    enum BOTAN_HAS_SYSTEM_RNG = true;                                                          }
else                          enum BOTAN_HAS_SYSTEM_RNG = false;
version(Processor_RNG)   {    enum BOTAN_HAS_PROCESSOR_RNG = true;                                                       }
else                          enum BOTAN_HAS_PROCESSOR_RNG = false;

version(ZLib)            {    enum BOTAN_HAS_ZLIB = true;                                                                }
else                          enum BOTAN_HAS_ZLIB = false;
version(Bzip2)           {    enum BOTAN_HAS_BZIP2 = true;                                                               }
else                          enum BOTAN_HAS_BZIP2 = false;
version(LZMA)            {    enum BOTAN_HAS_LZMA = true;                                                                }
else                          enum BOTAN_HAS_LZMA = false;

version(OPENSSL_NO_SHA)  {    enum BOTAN_HAS_OPENSSL_NO_SHA = true;                                                      }
else                          enum BOTAN_HAS_OPENSSL_NO_SHA = false;
version(OPENSSL_NO_SHA256) {  enum BOTAN_HAS_OPENSSL_NO_SHA256 = true;                                                   }
else                          enum BOTAN_HAS_OPENSSL_NO_SHA256 = false;
version(OPENSSL_NO_SHA512) {  enum BOTAN_HAS_OPENSSL_NO_SHA512 = true;                                                   }
else                          enum BOTAN_HAS_OPENSSL_NO_SHA512 = false;
version(OPENSSL_NO_MD2)  {    enum BOTAN_HAS_OPENSSL_NO_MD2 = true;                                                      }
else                          enum BOTAN_HAS_OPENSSL_NO_MD2 = false;
version(OPENSSL_NO_MD4)  {    enum BOTAN_HAS_OPENSSL_NO_MD4 = true;                                                      }
else                          enum BOTAN_HAS_OPENSSL_NO_MD4 = false;
version(OPENSSL_NO_MD5)  {    enum BOTAN_HAS_OPENSSL_NO_MD5 = true;                                                      }
else                          enum BOTAN_HAS_OPENSSL_NO_MD5 = false;
version(OPENSSL_NO_RIPEMD) {  enum BOTAN_HAS_OPENSSL_NO_RIPEMD = true;                                                   }
else                          enum BOTAN_HAS_OPENSSL_NO_RIPEMD = false;


version(OPENSSL_NO_AES)  {    enum BOTAN_HAS_OPENSSL_NO_AES = true;                                                      }
else                          enum BOTAN_HAS_OPENSSL_NO_AES = false;
version(OPENSSL_NO_DES)  {    enum BOTAN_HAS_OPENSSL_NO_DES = true;                                                      }
else                          enum BOTAN_HAS_OPENSSL_NO_DES = false;
version(OPENSSL_NO_BF)   {    enum BOTAN_HAS_OPENSSL_NO_BF = true;                                                       }
else                          enum BOTAN_HAS_OPENSSL_NO_BF = false;
version(OPENSSL_NO_CAST) {    enum BOTAN_HAS_OPENSSL_NO_CAST = true;                                                     }
else                          enum BOTAN_HAS_OPENSSL_NO_CAST = false;
version(OPENSSL_NO_CAMELLIA){ enum BOTAN_HAS_OPENSSL_NO_CAMELLIA = true;                                                 }
else                          enum BOTAN_HAS_OPENSSL_NO_CAMELLIA = false;
version(OPENSSL_NO_RC2)  {    enum BOTAN_HAS_OPENSSL_NO_RC2 = true;                                                      }
else                          enum BOTAN_HAS_OPENSSL_NO_RC2 = false;
version(OPENSSL_NO_RC5)  {    enum BOTAN_HAS_OPENSSL_NO_RC5 = true;                                                      }
else                          enum BOTAN_HAS_OPENSSL_NO_RC5 = false;
version(OPENSSL_NO_IDEA) {    enum BOTAN_HAS_OPENSSL_NO_IDEA = true;                                                     }
else                          enum BOTAN_HAS_OPENSSL_NO_IDEA = false;
version(OPENSSL_NO_SEED) {    enum BOTAN_HAS_OPENSSL_NO_SEED = true;                                                     }
else                          enum BOTAN_HAS_OPENSSL_NO_SEED = false;

// workaround for DMD bug in release
static if (!__traits(compiles, BOTAN_HAS_AES_SSSE3)) enum BOTAN_HAS_AES_SSSE3 = false;

enum { // LogLevel
    Trace,
    Info,
    Debug,
    Error,
    None
}

void logTrace(ARGS...)(lazy ARGS args) {
    static if (LogLevel <= Trace) {
        import std.stdio: writeln;
        writeln("T: ", args);
    }
}

void logInfo(ARGS...)(lazy ARGS args) {
    static if (LogLevel <= Info) {
        import std.stdio: writeln;
        writeln("I: ", args);
    }
}

void logDebug(ARGS...)(lazy ARGS args) {
    
    static if (LogLevel <= Debug) {
        import std.stdio: writeln;
        writeln("D: ", args);
    }
}

void logError(ARGS...)(lazy ARGS args) {
    static if (LogLevel <= Error) {
        import std.stdio: writeln, stderr;
        stderr.writeln("E: ", args);
    }
}
