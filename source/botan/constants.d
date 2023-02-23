/**
* Compile-time constants for conditional compilation
* 
* Copyright:
* (C) 2014-2015 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.constants;

public import botan_math.mp_types;
enum LogLevel = Debug;

enum SKIP_TRANSFORM_TEST = false;
enum SKIP_X509_TEST = false;
enum SKIP_BLOCK_TEST = false;
enum SKIP_CVC_TEST = false; // TODO: EAC11 ECDSA Key decoding
enum SKIP_CRYPTOBOX_TEST = false;
enum SKIP_RFC3394_TEST = false;
enum SKIP_TSS_TEST = false;
enum SKIP_HASH_TEST = false;
enum SKIP_KDF_TEST = false;
enum SKIP_COMPRESSION_TEST = false;
enum SKIP_MAC_TEST = false;
enum SKIP_BIGINT_TEST = false;
enum SKIP_EC_GFP_TEST = false;
enum SKIP_AEAD_TEST = false;
enum SKIP_OCB_TEST = false;
enum SKIP_CIPHER_MODE_TEST = false;
enum SKIP_BCRYPT_TEST = false;
enum SKIP_PASSHASH9_TEST = false;
enum SKIP_PBKDF_TEST = false;
enum SKIP_HKDF_TEST = false;
enum SKIP_CURVE25519_TEST = false;
enum SKIP_DH_TEST = false;
enum SKIP_DLIES_TEST = false;
enum SKIP_DSA_TEST = false;
enum SKIP_ECDH_TEST = false;
enum SKIP_ECDSA_TEST = false;
enum SKIP_ELGAMAL_TEST = false;
enum SKIP_GOST_TEST = false;
enum SKIP_NR_TEST = false;
enum SKIP_RFC6979_TEST = false;
enum SKIP_RSA_TEST = false;
enum SKIP_RW_TEST = false;
enum SKIP_X509_KEY_TEST = false;
enum SKIP_RNG_TEST = false;
enum SKIP_STREAM_CIPHER_TEST = false;
enum SKIP_TLS_TEST = false;

version(CanTest)     {    enum BOTAN_HAS_TESTS = true;                                                         }
else                      enum BOTAN_HAS_TESTS = false;


// This indicates the corresponding Botan (C++) version numbers
enum BOTAN_VERSION_MAJOR = 1;
enum BOTAN_VERSION_MINOR = 12;
enum BOTAN_VERSION_PATCH = 3;
enum BOTAN_VERSION_DATESTAMP = 20151109;
enum BOTAN_VERSION_RELEASE_TYPE = "unreleased";
enum BOTAN_VERSION_VC_REVISION = "git:6661c489929afc6c83c3038518dc37fd58938f3a";
enum BOTAN_DISTRIBUTION_INFO = "unspecified";

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

// todo: Make version specifiers for the below constants
enum BOTAN_HAS_CIPHER_MODE_PADDING = true;
enum BOTAN_HAS_AUTO_SEEDING_RNG = true;
enum BOTAN_HAS_CODEC_FILTERS = true;
enum BOTAN_HAS_HKDF = true;

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
version(X509)            {    enum BOTAN_HAS_X509_CERTIFICATES = true;                                                   }
else                          enum BOTAN_HAS_X509_CERTIFICATES = false;
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
version(PassHash9)       {    enum BOTAN_HAS_PASSHASH9 = true;                                                           }
else                          enum BOTAN_HAS_PASSHASH9 = false;
version(BCrypt)          {    enum BOTAN_HAS_BCRYPT = true;                                                              }
else                          enum BOTAN_HAS_BCRYPT = false;
version(SRP6)            {    enum BOTAN_HAS_SRP6 = true;                                                                }
else                          enum BOTAN_HAS_SRP6 = false;
version(TSS)             {    enum BOTAN_HAS_THRESHOLD_SECRET_SHARING = true;                                            }
else                          enum BOTAN_HAS_THRESHOLD_SECRET_SHARING = false;
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
version(AEAD_CHACHA20_POLY1305){enum BOTAN_HAS_AEAD_CHACHA20_POLY1305 = true;                                            }
else                          enum BOTAN_HAS_AEAD_CHACHA20_POLY1305 = false;

version(RFC6979)         {    enum BOTAN_HAS_RFC6979_GENERATOR = true;                                                   }
else                          enum BOTAN_HAS_RFC6979_GENERATOR = false;
version(RSA)             {    enum BOTAN_HAS_RSA = true;                                                                 }
else                          enum BOTAN_HAS_RSA = false;
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
else                          enum BOTAN_HAS_CURVE25519 = false;
version(AES)             {    enum BOTAN_HAS_AES = true;                                                                 }
else                          enum BOTAN_HAS_AES = false;
version(Blowfish)        {    enum BOTAN_HAS_BLOWFISH = true;                                                            }
else                          enum BOTAN_HAS_BLOWFISH = false;
version(Camellia)        {    enum BOTAN_HAS_CAMELLIA = true;                                                            }
else                          enum BOTAN_HAS_CAMELLIA = false;
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
version(PBKDF1)          {    enum BOTAN_HAS_PBKDF1 = true;                                                              }
else                          enum BOTAN_HAS_PBKDF1 = false;
version(PBKDF2)          {    enum BOTAN_HAS_PBKDF2 = true;                                                              }
else                          enum BOTAN_HAS_PBKDF2 = false;
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
version(EME_OAEP)        {    enum BOTAN_HAS_EME_OAEP = true;                                                            }
else                          enum BOTAN_HAS_EME_OAEP = false;
version(EME_PKCS1v15)    {    enum BOTAN_HAS_EME_PKCS1_V15 = true;                                                       }
else                          enum BOTAN_HAS_EME_PKCS1_V15 = false;
version(PBE_PKCSv20)     {    enum BOTAN_HAS_PBE_PKCS_V20 = true;                                                        }
else                          enum BOTAN_HAS_PBE_PKCS_V20 = false;
version(GCM_CLMUL)       {    enum BOTAN_HAS_GCM_CLMUL = true;            static assert(BOTAN_HAS_SIMD);                 }
else                          enum BOTAN_HAS_GCM_CLMUL = false;   

version(X931_RNG)        {    enum BOTAN_HAS_X931_RNG = true;                                                            }
else                          enum BOTAN_HAS_X931_RNG = false;
version(HMAC_DRBG)       {    enum BOTAN_HAS_HMAC_DRBG = true;                                                           }
else                          enum BOTAN_HAS_HMAC_DRBG = false;

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
