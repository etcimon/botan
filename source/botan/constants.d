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

const LogLevel = Debug;

const SKIP_TRANSFORM_TEST = false;
const SKIP_X509_TEST = false;
const SKIP_BLOCK_TEST = false;
const SKIP_CVC_TEST = true; // TODO: EAC11 ECDSA Key decoding
const SKIP_CRYPTOBOX_TEST = false;
const SKIP_RFC3394_TEST = false;
const SKIP_TSS_TEST = false;
const SKIP_HASH_TEST = false;
const SKIP_KDF_TEST = false;
const SKIP_MAC_TEST = false;
const SKIP_BIGINT_TEST = false;
const SKIP_EC_GFP_TEST = false;
const SKIP_AEAD_TEST = false;
const SKIP_OCB_TEST = false;
const SKIP_CIPHER_MODE_TEST = false;
const SKIP_BCRYPT_TEST = false;
const SKIP_PASSHASH9_TEST = false;
const SKIP_PBKDF_TEST = false;
const SKIP_HKDF_TEST = false;
const SKIP_DH_TEST = false;
const SKIP_DLIES_TEST = false;
const SKIP_DSA_TEST = false;
const SKIP_ECDH_TEST = false;
const SKIP_ECDSA_TEST = false;
const SKIP_ELGAMAL_TEST = false;
const SKIP_GOST_TEST = false;
const SKIP_NR_TEST = false;
const SKIP_RFC6979_TEST = false;
const SKIP_RSA_TEST = false;
const SKIP_RW_TEST = false;
const SKIP_X509_KEY_TEST = false;
const SKIP_RNG_TEST = false;
const SKIP_STREAM_CIPHER_TEST = false;
const SKIP_TLS_TEST = false;

// This indicates the corresponding Botan (C++) version numbers
const BOTAN_VERSION_MAJOR = 1;
const BOTAN_VERSION_MINOR = 11;
const BOTAN_VERSION_PATCH = 10;
const BOTAN_VERSION_DATESTAMP = 20150217;
const BOTAN_VERSION_RELEASE_TYPE = "unreleased";
const BOTAN_VERSION_VC_REVISION = "git:455bd2557cbb1343e59eefd97cb449f06a702c28";
const BOTAN_DISTRIBUTION_INFO = "unspecified";

const BOTAN_TARGET_CPU_HAS_KNOWN_ENDIANNESS = true;
const BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK = true;
const BOTAN_TARGET_HAS_NATIVE_UINT128 = false;
const DEFAULT_BUFFERSIZE = 4096;
const TLS_DEFAULT_BUFFERSIZE = 4096;

const BOTAN_MEM_POOL_CHUNK_SIZE = 64*1024;
const BOTAN_BLOCK_CIPHER_PAR_MULT = 4;

version(X86) { const BOTAN_HAS_X86_ARCH = true; const BOTAN_HAS_X86_64_ARCH = false; const BOTAN_HAS_ARM_ARCH = false; }
version(X86_64) { const BOTAN_HAS_X86_ARCH = false; const BOTAN_HAS_X86_64_ARCH = true; const BOTAN_HAS_ARM_ARCH = false; }
version(ARM) { const BOTAN_HAS_X86_ARCH = false; const BOTAN_HAS_X86_64_ARCH = false; const BOTAN_HAS_ARM_ARCH = true; }

const ERR_ARCH = "Cannot compile the selected module on this processor architecture.";

static if (BOTAN_HAS_X86_ARCH)
    const BOTAN_MP_WORD_BITS = 32; 
else static if (BOTAN_HAS_X86_64_ARCH)
    const BOTAN_MP_WORD_BITS = 64;
else static if (BOTAN_HAS_ARM_ARCH)
    const BOTAN_MP_WORD_BITS = 32;
// todo: else static if (BOTAN_HAS_PPC_ARCH)

version(D_SIMD) const BOTAN_HAS_SIMD = true;
else            const BOTAN_HAS_SIMD = false;


const BOTAN_KARAT_MUL_THRESHOLD = 32;
const BOTAN_KARAT_SQR_THRESHOLD = 32;
const BOTAN_RNG_MAX_OUTPUT_BEFORE_RESEED = 512;
const BOTAN_RNG_RESEED_POLL_BITS = 128;

// todo: Make version specifiers for the below constants
const BOTAN_HAS_CIPHER_MODE_PADDING = true;
const BOTAN_HAS_AUTO_SEEDING_RNG = true;
const BOTAN_HAS_CODEC_FILTERS = true;
const BOTAN_HAS_HKDF = true;

version (unittest)     const BOTAN_TEST = true;
else                   const BOTAN_TEST = false;

version(D_InlineAsm_X86) {    const BOTAN_HAS_DMD_X86_INLINE_ASM = true;                                                  
                              const BOTAN_HAS_DMD_X86_64_INLINE_ASM = false;                                              }
else version(D_InlineAsm_X86_64){  const BOTAN_HAS_DMD_X86_INLINE_ASM = false; 
                              const BOTAN_HAS_DMD_X86_64_INLINE_ASM = true;                                               }
else                     {    const BOTAN_HAS_DMD_X86_INLINE_ASM = false;
                              const BOTAN_HAS_DMD_X86_64_INLINE_ASM = false;                                              }

version(FORCE_SSE4)      {    const BOTAN_FORCE_SSE4 = true;                                                              }
else                          const BOTAN_FORCE_SSE4 = false;
version(SIMD_SSE2)       {    const BOTAN_HAS_SIMD_SSE2 = true;          static assert(BOTAN_HAS_SIMD);                   }
else                          const BOTAN_HAS_SIMD_SSE2 = false;
version(SIMD_Altivec)    {    static if (BOTAN_TARGET_CPU_IS_PPC_FAMILY) 
                                  const BOTAN_HAS_SIMD_ALTIVEC = true;
                              else const BOTAN_HAS_SIMD_ALTIVEC = false;                                                  }
else                              const BOTAN_HAS_SIMD_ALTIVEC = false;
version(SIMD_Scalar)     {    const BOTAN_HAS_SIMD_SCALAR = true;                                                         }
else                          const BOTAN_HAS_SIMD_SCALAR = false;

static if (BOTAN_HAS_SIMD_SCALAR || BOTAN_HAS_SIMD_ALTIVEC || BOTAN_HAS_SIMD_SSE2)
    const BOTAN_HAS_SIMD_OPS = true;
else
    const BOTAN_HAS_SIMD_OPS = false;

static if (BOTAN_HAS_X86_ARCH && BOTAN_HAS_SIMD_SSE2) pragma(msg, "Error: SIMD_SSE2 cannot be enabled on x86 architecture.");

version(No_SSE_Intrinsics){   const BOTAN_NO_SSE_INTRINSICS = true;      static assert(!BOTAN_HAS_SIMD_SSE2);             }
else                          const BOTAN_NO_SSE_INTRINSICS = false;

version(Bench)           {    const BOTAN_HAS_BENCHMARK = true;                                                           }
else                          const BOTAN_HAS_BENCHMARK = false;

version(Self_Tests)      {    const BOTAN_HAS_SELFTESTS = true;                                                           }
else                           const BOTAN_HAS_SELFTESTS = false;
version(RT_Test)         {    const BOTAN_PUBLIC_KEY_STRONG_CHECKS_ON_LOAD = true;                                        }
else                          const BOTAN_PUBLIC_KEY_STRONG_CHECKS_ON_LOAD = false;
version(RT_Test_Priv)    {    const BOTAN_PRIVATE_KEY_STRONG_CHECKS_ON_LOAD = true;                                       }
else                          const BOTAN_PRIVATE_KEY_STRONG_CHECKS_ON_LOAD = false;
version(RT_Test_Priv_Gen){    const BOTAN_PRIVATE_KEY_STRONG_CHECKS_ON_GENERATE = true;                                   }
else                          const BOTAN_PRIVATE_KEY_STRONG_CHECKS_ON_GENERATE = false;
version(PUBKEY)          {    const BOTAN_HAS_PUBLIC_KEY_CRYPTO = true;                                                   }
else                          const BOTAN_HAS_PUBLIC_KEY_CRYPTO = false;
version(TLS)             {    const BOTAN_HAS_TLS = true;                                                                 }
else                          const BOTAN_HAS_TLS = false;
version(X509)            {    const BOTAN_HAS_X509_CERTIFICATES = true;                                                   }
else                          const BOTAN_HAS_X509_CERTIFICATES = false;
version(CVC)             {    const BOTAN_HAS_CARD_VERIFIABLE_CERTIFICATES = true;                                        }
else                          const BOTAN_HAS_CARD_VERIFIABLE_CERTIFICATES = false;
version(SQLite)          {    const BOTAN_HAS_SQLITE = true;                                                              }
else                          const BOTAN_HAS_SQLITE = false;
version(AONT)            {    const BOTAN_HAS_AONT = true;                                                                }
else                          const BOTAN_HAS_AONT = false;
version(CryptoBox)       {    const BOTAN_HAS_CRYPTOBOX = true;                                                           }
else                          const BOTAN_HAS_CRYPTOBOX = false;
version(CryptoBox_PSK)   {    const BOTAN_HAS_CRYPTOBOX_PSK = true;                                                       }
else                          const BOTAN_HAS_CRYPTOBOX_PSK = false;
version(FPE_FE1)         {    const BOTAN_HAS_FPE_FE1 = true;                                                             }
else                          const BOTAN_HAS_FPE_FE1 = false;
version(RFC3394)         {    const BOTAN_HAS_RFC3394_KEYWRAP = true;                                                     }
else                          const BOTAN_HAS_RFC3394_KEYWRAP = false;
version(PassHash9)       {    const BOTAN_HAS_PASSHASH9 = true;                                                           }
else                          const BOTAN_HAS_PASSHASH9 = false;
version(BCrypt)          {    const BOTAN_HAS_BCRYPT = true;                                                              }
else                          const BOTAN_HAS_BCRYPT = false;
version(SRP6)            {    const BOTAN_HAS_SRP6 = true;                                                                }
else                          const BOTAN_HAS_SRP6 = false;
version(TSS)             {    const BOTAN_HAS_THRESHOLD_SECRET_SHARING = true;                                            }
else                          const BOTAN_HAS_THRESHOLD_SECRET_SHARING = false;
version(KDF1)            {    const BOTAN_HAS_KDF1 = true;                                                                }
else                          const BOTAN_HAS_KDF1 = false;
version(KDF2)            {    const BOTAN_HAS_KDF2 = true;                                                                }
else                          const BOTAN_HAS_KDF2 = false;
version(X942_PRF)        {    const BOTAN_HAS_X942_PRF = true;                                                            }
else                          const BOTAN_HAS_X942_PRF = false;
version(SSL_V3_PRF)      {    const BOTAN_HAS_SSL_V3_PRF = true;                                                          }
else                          const BOTAN_HAS_SSL_V3_PRF = false;
version(TLS_V10_PRF)     {    const BOTAN_HAS_TLS_V10_PRF = true;                                                         }
else                          const BOTAN_HAS_TLS_V10_PRF = false;
version(TLS_V12_PRF)     {    const BOTAN_HAS_TLS_V12_PRF = true;                                                         }
else                          const BOTAN_HAS_TLS_V12_PRF = false;
version(AES_NI)          {    const BOTAN_HAS_AES_NI = true;            static assert(BOTAN_HAS_SIMD);                    }
else                          const BOTAN_HAS_AES_NI = false;
version(Serpent_x86_32)  {    const BOTAN_HAS_SERPENT_X86_32 = true;    static assert(BOTAN_HAS_X86_ARCH, ERR_ARCH);      }
else                          const BOTAN_HAS_SERPENT_X86_32 = false;
version(MD4_x86_32)      {    const BOTAN_HAS_MD4_X86_32 = true;        static assert(BOTAN_HAS_X86_ARCH, ERR_ARCH);      }
else                          const BOTAN_HAS_MD4_X86_32 = false;
version(MD5_x86_32)      {    const BOTAN_HAS_MD5_X86_32 = true;        static assert(BOTAN_HAS_X86_ARCH, ERR_ARCH);      }
else                          const BOTAN_HAS_MD5_X86_32 = false;
version(SHA1_x86_64)     {    const BOTAN_HAS_SHA1_X86_64 = true;       static assert(BOTAN_HAS_X86_64_ARCH, ERR_ARCH);   }
else                          const BOTAN_HAS_SHA1_X86_64 = false;
version(SHA1_x86_32)     {    const BOTAN_HAS_SHA1_X86_32 = true;       static assert(BOTAN_HAS_X86_ARCH, ERR_ARCH);      }
else                          const BOTAN_HAS_SHA1_X86_32 = false;
version(CFB)             {    const BOTAN_HAS_MODE_CFB = true;                                                            }
else                          const BOTAN_HAS_MODE_CFB = false;
version(ECB)             {    const BOTAN_HAS_MODE_ECB = true;                                                            }
else                          const BOTAN_HAS_MODE_ECB = false;
version(CBC)             {    const BOTAN_HAS_MODE_CBC = true;                                                            }
else                          const BOTAN_HAS_MODE_CBC = false;
version(XTS)             {    const BOTAN_HAS_MODE_XTS = true;                                                            }
else                          const BOTAN_HAS_MODE_XTS = false;
version(OFB)             {    const BOTAN_HAS_OFB = true;                                                                 }
else                          const BOTAN_HAS_OFB = false;
version(CTR_BE)          {    const BOTAN_HAS_CTR_BE = true;                                                              }
else                          const BOTAN_HAS_CTR_BE = false;
version(AEAD_FILTER)     {    const BOTAN_HAS_AEAD_FILTER = true;                                                         }
else                          const BOTAN_HAS_AEAD_FILTER = false;
version(AEAD_CCM)        {    const BOTAN_HAS_AEAD_CCM = true;                                                            }
else                          const BOTAN_HAS_AEAD_CCM = false;
version(AEAD_EAX)        {    const BOTAN_HAS_AEAD_EAX = true;                                                            }
else                          const BOTAN_HAS_AEAD_EAX = false;
version(AEAD_OCB)        {    const BOTAN_HAS_AEAD_OCB = true;                                                            }
else                          const BOTAN_HAS_AEAD_OCB = false;
version(AEAD_GCM)        {    const BOTAN_HAS_AEAD_GCM = true;                                                            }
else                          const BOTAN_HAS_AEAD_GCM = false;
version(AEAD_SIV)        {    const BOTAN_HAS_AEAD_SIV = true;                                                            }
else                          const BOTAN_HAS_AEAD_SIV = false;

version(RFC6979)         {    const BOTAN_HAS_RFC6979_GENERATOR = true;                                                   }
else                          const BOTAN_HAS_RFC6979_GENERATOR = false;
version(RSA)             {    const BOTAN_HAS_RSA = true;                                                                 }
else                          const BOTAN_HAS_RSA = false;
version(RW)              {    const BOTAN_HAS_RW = true;                                                                  }
else                          const BOTAN_HAS_RW = false;
version(DLIES)           {    const BOTAN_HAS_DLIES = true;                                                               }
else                          const BOTAN_HAS_DLIES = false;                                                            
version(DSA)             {    const BOTAN_HAS_DSA = true;                                                                 }
else                          const BOTAN_HAS_DSA = false;
version(ECDSA)           {    const BOTAN_HAS_ECDSA = true;                                                               }
else                          const BOTAN_HAS_ECDSA = false;
version(ElGamal)         {    const BOTAN_HAS_ELGAMAL = true;                                                             }
else                          const BOTAN_HAS_ELGAMAL = false;
version(GOST_3410)       {    const BOTAN_HAS_GOST_34_10_2001 = true;                                                     }
else                          const BOTAN_HAS_GOST_34_10_2001 = false;
version(Nyberg_Rueppel)  {    const BOTAN_HAS_NYBERG_RUEPPEL = true;                                                      }
else                          const BOTAN_HAS_NYBERG_RUEPPEL = false;
version(Diffie_Hellman)  {    const BOTAN_HAS_DIFFIE_HELLMAN = true;                                                      }
else                          const BOTAN_HAS_DIFFIE_HELLMAN = false;
version(ECDH)            {    const BOTAN_HAS_ECDH = true;                                                                }
else                          const BOTAN_HAS_ECDH = false;
version(AES)             {    const BOTAN_HAS_AES = true;                                                                 }
else                          const BOTAN_HAS_AES = false;
version(Blowfish)        {    const BOTAN_HAS_BLOWFISH = true;                                                            }
else                          const BOTAN_HAS_BLOWFISH = false;
version(Camellia)        {    const BOTAN_HAS_CAMELLIA = true;                                                            }
else                          const BOTAN_HAS_CAMELLIA = false;
version(CAST)            {    const BOTAN_HAS_CAST = true;                                                                }
else                          const BOTAN_HAS_CAST = false;
version(Cascade)         {    const BOTAN_HAS_CASCADE = true;                                                             }
else                          const BOTAN_HAS_CASCADE = false;
version(DES)             {    const BOTAN_HAS_DES = true;                                                                 }
else                          const BOTAN_HAS_DES = false;
version(GOST_28147)      {    const BOTAN_HAS_GOST_28147_89 = true;                                                       }
else                          const BOTAN_HAS_GOST_28147_89 = false;
version(IDEA)            {    const BOTAN_HAS_IDEA = true;                                                                }
else                          const BOTAN_HAS_IDEA = false;
version(KASUMI)          {    const BOTAN_HAS_KASUMI = true;                                                              }
else                          const BOTAN_HAS_KASUMI = false;
version(LION)            {    const BOTAN_HAS_LION = true;                                                                }
else                          const BOTAN_HAS_LION = false;
version(MARS)            {    const BOTAN_HAS_MARS = true;                                                                }
else                          const BOTAN_HAS_MARS = false;
version(MISTY1)          {    const BOTAN_HAS_MISTY1 = true;                                                              }
else                          const BOTAN_HAS_MISTY1 = false;
version(NOEKEON)         {    const BOTAN_HAS_NOEKEON = true;                                                             }
else                          const BOTAN_HAS_NOEKEON = false;
version(RC2)             {    const BOTAN_HAS_RC2 = true;                                                                 }
else                          const BOTAN_HAS_RC2 = false;
version(RC5)             {    const BOTAN_HAS_RC5 = true;                                                                 }
else                          const BOTAN_HAS_RC5 = false;
version(RC6)             {    const BOTAN_HAS_RC6 = true;                                                                 }
else                          const BOTAN_HAS_RC6 = false;
version(SAFER)           {    const BOTAN_HAS_SAFER = true;                                                               }
else                          const BOTAN_HAS_SAFER = false;
version(SEED)            {    const BOTAN_HAS_SEED = true;                                                                }
else                          const BOTAN_HAS_SEED = false;
version(Serpent)         {    const BOTAN_HAS_SERPENT = true;                                                             }
else                          const BOTAN_HAS_SERPENT = false;
version(TEA)             {    const BOTAN_HAS_TEA = true;                                                                 }
else                          const BOTAN_HAS_TEA = false;
version(Twofish)         {    const BOTAN_HAS_TWOFISH = true;                                                             }
else                          const BOTAN_HAS_TWOFISH = false;
version(Threefish)       {    const BOTAN_HAS_THREEFISH_512 = true;                                                       }
else                          const BOTAN_HAS_THREEFISH_512 = false;
version(XTEA)            {    const BOTAN_HAS_XTEA = true;                                                                }
else                          const BOTAN_HAS_XTEA = false;
version(Adler32)         {    const BOTAN_HAS_ADLER32 = true;                                                             }
else                          const BOTAN_HAS_ADLER32 = false;
version(CRC24)           {    const BOTAN_HAS_CRC24 = true;                                                               }
else                          const BOTAN_HAS_CRC24 = false;
version(CRC32)           {    const BOTAN_HAS_CRC32 = true;                                                               }
else                          const BOTAN_HAS_CRC32 = false;
version(GOST_3411)       {    const BOTAN_HAS_GOST_34_11 = true;                                                          }
else                          const BOTAN_HAS_GOST_34_11 = false;
version(HAS_160)         {    const BOTAN_HAS_HAS_160 = true;                                                             }
else                          const BOTAN_HAS_HAS_160 = false;
version(Keccak)          {    const BOTAN_HAS_KECCAK = true;                                                              }
else                          const BOTAN_HAS_KECCAK = false;
version(MD2)             {    const BOTAN_HAS_MD2 = true;                                                                 }
else                          const BOTAN_HAS_MD2 = false;
version(MD4)             {    const BOTAN_HAS_MD4 = true;                                                                 }
else                          const BOTAN_HAS_MD4 = false;
version(MD5)             {    const BOTAN_HAS_MD5 = true;                                                                 }
else                          const BOTAN_HAS_MD5 = false;
version(RIPEMD_128)      {    const BOTAN_HAS_RIPEMD_128 = true;                                                          }
else                          const BOTAN_HAS_RIPEMD_128 = false;
version(RIPEMD_160)      {    const BOTAN_HAS_RIPEMD_160 = true;                                                          }
else                          const BOTAN_HAS_RIPEMD_160 = false;
version(SHA1)            {    const BOTAN_HAS_SHA1 = true;                                                                }
else                          const BOTAN_HAS_SHA1 = false;  
version(SHA2_32)         {    const BOTAN_HAS_SHA2_32 = true;                                                             }
else                          const BOTAN_HAS_SHA2_32 = false;
version(SHA2_64)         {    const BOTAN_HAS_SHA2_64 = true;                                                             }
else                          const BOTAN_HAS_SHA2_64 = false;
version(Skein_512)       {    const BOTAN_HAS_SKEIN_512 = true;                                                           }
else                          const BOTAN_HAS_SKEIN_512 = false;
version(Tiger)           {    const BOTAN_HAS_TIGER = true;                                                               }
else                          const BOTAN_HAS_TIGER = false;
version(Whirlpool)       {    const BOTAN_HAS_WHIRLPOOL = true;                                                           }
else                          const BOTAN_HAS_WHIRLPOOL = false;
version(ParallelHash)    {    const BOTAN_HAS_PARALLEL_HASH = true;                                                       }
else                          const BOTAN_HAS_PARALLEL_HASH = false;
version(Comb4P)          {    const BOTAN_HAS_COMB4P = true;                                                              }
else                          const BOTAN_HAS_COMB4P = false;
version(CBC_MAC)         {    const BOTAN_HAS_CBC_MAC = true;                                                             }
else                          const BOTAN_HAS_CBC_MAC = false;
version(CMAC)            {    const BOTAN_HAS_CMAC = true;                                                                }
else                          const BOTAN_HAS_CMAC = false;
version(HMAC)            {    const BOTAN_HAS_HMAC = true;                                                                }
else                          const BOTAN_HAS_HMAC = false;
version(SSL3_MAC)        {    const BOTAN_HAS_SSL3_MAC = true;                                                            }
else                          const BOTAN_HAS_SSL3_MAC = false;
version(ANSI_X919_MAC)   {    const BOTAN_HAS_ANSI_X919_MAC = true;                                                       }
else                          const BOTAN_HAS_ANSI_X919_MAC = false;
version(PBKDF1)          {    const BOTAN_HAS_PBKDF1 = true;                                                              }
else                          const BOTAN_HAS_PBKDF1 = false;
version(PBKDF2)          {    const BOTAN_HAS_PBKDF2 = true;                                                              }
else                          const BOTAN_HAS_PBKDF2 = false;
version(RC4)             {    const BOTAN_HAS_RC4 = true;                                                                 }
else                          const BOTAN_HAS_RC4 = false;
version(ChaCha)          {    const BOTAN_HAS_CHACHA = true;                                                              }
else                          const BOTAN_HAS_CHACHA = false;
version(Salsa20)         {    const BOTAN_HAS_SALSA20 = true;                                                             }
else                          const BOTAN_HAS_SALSA20 = false;
version(AES_SSSE3)       {    const BOTAN_HAS_AES_SSSE3 = true;           static assert(BOTAN_HAS_SIMD);                  }
else                          const BOTAN_HAS_AES_SSSE3 = false;
version(Serpent_SIMD)    {    const BOTAN_HAS_SERPENT_SIMD = true;        static assert(BOTAN_HAS_SIMD_OPS);              }
else                          const BOTAN_HAS_SERPENT_SIMD = false;
version(Threefish_512_AVX2){  const BOTAN_HAS_THREEFISH_512_AVX2 = true;  static assert(BOTAN_HAS_SIMD_ALTIVEC);          }
else                          const BOTAN_HAS_THREEFISH_512_AVX2 = false;
version(Noekeon_SIMD)    {    const BOTAN_HAS_NOEKEON_SIMD = true;        static assert(BOTAN_HAS_SIMD_OPS);              }
else                          const BOTAN_HAS_NOEKEON_SIMD = false;
version(XTEA_SIMD)       {    const BOTAN_HAS_XTEA_SIMD = true;           static assert(BOTAN_HAS_SIMD_OPS);              }
else                          const BOTAN_HAS_XTEA_SIMD = false;
version(IDEA_SSE2 )      {    const BOTAN_HAS_IDEA_SSE2 = true;           static assert(BOTAN_HAS_SIMD);                  }
else                          const BOTAN_HAS_IDEA_SSE2 = false;
version(SHA1_SSE2)       {    const BOTAN_HAS_SHA1_SSE2 = true;           static assert(BOTAN_HAS_SIMD);                  }
else                          const BOTAN_HAS_SHA1_SSE2 = false;


version(Engine_ASM)      {    const BOTAN_HAS_ENGINE_ASSEMBLER = true;                                                    }
else                          const BOTAN_HAS_ENGINE_ASSEMBLER = false;
version(Engine_AES_ISA)  {    const BOTAN_HAS_ENGINE_AES_ISA = true;                                                      }
else                          const BOTAN_HAS_ENGINE_AES_ISA = false;
version(Engine_SIMD)     {    const BOTAN_HAS_ENGINE_SIMD = true;         static assert(BOTAN_HAS_SIMD);                  }
else                          const BOTAN_HAS_ENGINE_SIMD = false;
version(Engine_GNU_MP)   {    const BOTAN_HAS_ENGINE_GNU_MP = true;                                                       }
else                          const BOTAN_HAS_ENGINE_GNU_MP = false;
version(Engine_OPENSSL)  {    const BOTAN_HAS_ENGINE_OPENSSL = true;                                                      }
else                          const BOTAN_HAS_ENGINE_OPENSSL = false;
version(Entropy_HRTimer) {    const BOTAN_HAS_ENTROPY_SRC_HIGH_RESOLUTION_TIMER = true;                                   }
else                          const BOTAN_HAS_ENTROPY_SRC_HIGH_RESOLUTION_TIMER = false;
version(Entropy_Rdrand)  {    const BOTAN_HAS_ENTROPY_SRC_RDRAND = true;                                                  }
else                          const BOTAN_HAS_ENTROPY_SRC_RDRAND = false;
version(Entropy_DevRand) {    const BOTAN_HAS_ENTROPY_SRC_DEV_RANDOM = true;                                              }    
else                          const BOTAN_HAS_ENTROPY_SRC_DEV_RANDOM = false;
version(Entropy_EGD)     {    const BOTAN_HAS_ENTROPY_SRC_EGD = true;                                                     }
else                          const BOTAN_HAS_ENTROPY_SRC_EGD = false;
version(Entropy_UnixProc){    const BOTAN_HAS_ENTROPY_SRC_UNIX_PROCESS_RUNNER = true;                                     }
else                          const BOTAN_HAS_ENTROPY_SRC_UNIX_PROCESS_RUNNER = false;
version(Entropy_BEOS)    {    const BOTAN_HAS_ENTROPY_SRC_BEOS = true;                                                    }
else                          const BOTAN_HAS_ENTROPY_SRC_BEOS = false;
version(Entropy_CAPI)    {    const BOTAN_HAS_ENTROPY_SRC_CAPI = true;                                                    }
else                          const BOTAN_HAS_ENTROPY_SRC_CAPI = false;
version(Entropy_Win32)   {    const BOTAN_HAS_ENTROPY_SRC_WIN32 = true;                                                   }
else                          const BOTAN_HAS_ENTROPY_SRC_WIN32 = false;
version(Entropy_ProcWalk){    const BOTAN_HAS_ENTROPY_SRC_PROC_WALKER = true;                                             }
else                          const BOTAN_HAS_ENTROPY_SRC_PROC_WALKER = false;
version(EMSA1)           {    const BOTAN_HAS_EMSA1 = true;                                                               }
else                          const BOTAN_HAS_EMSA1 = false;
version(EMSA1_BSI)       {    const BOTAN_HAS_EMSA1_BSI = true;                                                           }
else                          const BOTAN_HAS_EMSA1_BSI = false;
version(EMSA_X931)       {    const BOTAN_HAS_EMSA_X931 = true;                                                           }
else                          const BOTAN_HAS_EMSA_X931 = false;
version(EMSA_PKCS1)      {    const BOTAN_HAS_EMSA_PKCS1 = true;                                                          }
else                          const BOTAN_HAS_EMSA_PKCS1 = false;
version(EMSA_PSSR)       {    const BOTAN_HAS_EMSA_PSSR = true;                                                           }
else                          const BOTAN_HAS_EMSA_PSSR = false;
version(EMSA_RAW)        {    const BOTAN_HAS_EMSA_RAW = true;                                                            }
else                          const BOTAN_HAS_EMSA_RAW = false;
version(EME_OAEP)        {    const BOTAN_HAS_EME_OAEP = true;                                                            }
else                          const BOTAN_HAS_EME_OAEP = false;
version(EME_PKCS1v15)    {    const BOTAN_HAS_EME_PKCS1_V15 = true;                                                       }
else                          const BOTAN_HAS_EME_PKCS1_V15 = false;
version(PBE_PKCSv20)     {    const BOTAN_HAS_PBE_PKCS_V20 = true;                                                        }
else                          const BOTAN_HAS_PBE_PKCS_V20 = false;
version(GCM_CLMUL)       {    const BOTAN_HAS_GCM_CLMUL = true;            static assert(BOTAN_HAS_SIMD);                 }
else                          const BOTAN_HAS_GCM_CLMUL = false;   

version(X931_RNG)        {    const BOTAN_HAS_X931_RNG = true;                                                            }
else                          const BOTAN_HAS_X931_RNG = false;
version(HMAC_DRBG)       {    const BOTAN_HAS_HMAC_DRBG = true;                                                           }
else                          const BOTAN_HAS_HMAC_DRBG = false;

version(ZLib)            {    const BOTAN_HAS_ZLIB = true;                                                                }
else                          const BOTAN_HAS_ZLIB = false;
version(Bzip2)           {    const BOTAN_HAS_BZIP2 = true;                                                               }
else                          const BOTAN_HAS_BZIP2 = false;
version(LZMA)            {    const BOTAN_HAS_LZMA = true;                                                                }
else                          const BOTAN_HAS_LZMA = false;

version(OPENSSL_NO_SHA)  {    const BOTAN_HAS_OPENSSL_NO_SHA = true;                                                      }
else                          const BOTAN_HAS_OPENSSL_NO_SHA = false;
version(OPENSSL_NO_SHA256) {  const BOTAN_HAS_OPENSSL_NO_SHA256 = true;                                                   }
else                          const BOTAN_HAS_OPENSSL_NO_SHA256 = false;
version(OPENSSL_NO_SHA512) {  const BOTAN_HAS_OPENSSL_NO_SHA512 = true;                                                   }
else                          const BOTAN_HAS_OPENSSL_NO_SHA512 = false;
version(OPENSSL_NO_MD2)  {    const BOTAN_HAS_OPENSSL_NO_MD2 = true;                                                      }
else                          const BOTAN_HAS_OPENSSL_NO_MD2 = false;
version(OPENSSL_NO_MD4)  {    const BOTAN_HAS_OPENSSL_NO_MD4 = true;                                                      }
else                          const BOTAN_HAS_OPENSSL_NO_MD4 = false;
version(OPENSSL_NO_MD5)  {    const BOTAN_HAS_OPENSSL_NO_MD5 = true;                                                      }
else                          const BOTAN_HAS_OPENSSL_NO_MD5 = false;
version(OPENSSL_NO_RIPEMD) {  const BOTAN_HAS_OPENSSL_NO_RIPEMD = true;                                                   }
else                          const BOTAN_HAS_OPENSSL_NO_RIPEMD = false;


version(OPENSSL_NO_AES)  {    const BOTAN_HAS_OPENSSL_NO_AES = true;                                                      }
else                          const BOTAN_HAS_OPENSSL_NO_AES = false;
version(OPENSSL_NO_DES)  {    const BOTAN_HAS_OPENSSL_NO_DES = true;                                                      }
else                          const BOTAN_HAS_OPENSSL_NO_DES = false;
version(OPENSSL_NO_BF)   {    const BOTAN_HAS_OPENSSL_NO_BF = true;                                                       }
else                          const BOTAN_HAS_OPENSSL_NO_BF = false;
version(OPENSSL_NO_CAST) {    const BOTAN_HAS_OPENSSL_NO_CAST = true;                                                     }
else                          const BOTAN_HAS_OPENSSL_NO_CAST = false;
version(OPENSSL_NO_CAMELLIA){ const BOTAN_HAS_OPENSSL_NO_CAMELLIA = true;                                                 }
else                          const BOTAN_HAS_OPENSSL_NO_CAMELLIA = false;
version(OPENSSL_NO_RC2)  {    const BOTAN_HAS_OPENSSL_NO_RC2 = true;                                                      }
else                          const BOTAN_HAS_OPENSSL_NO_RC2 = false;
version(OPENSSL_NO_RC5)  {    const BOTAN_HAS_OPENSSL_NO_RC5 = true;                                                      }
else                          const BOTAN_HAS_OPENSSL_NO_RC5 = false;
version(OPENSSL_NO_IDEA) {    const BOTAN_HAS_OPENSSL_NO_IDEA = true;                                                     }
else                          const BOTAN_HAS_OPENSSL_NO_IDEA = false;
version(OPENSSL_NO_SEED) {    const BOTAN_HAS_OPENSSL_NO_SEED = true;                                                     }
else                          const BOTAN_HAS_OPENSSL_NO_SEED = false;

enum { // LogLevel
    Trace,
    Info,
    Debug,
    Error,
    None
}

void logTrace(ARGS...)(ARGS args) {
    static if (LogLevel <= Trace) {
        import std.stdio: writeln;
        writeln("T: ", args);
    }
}

void logInfo(ARGS...)(ARGS args) {
    static if (LogLevel <= Info) {
        import std.stdio: writeln;
        writeln("I: ", args);
    }
}

void logDebug(ARGS...)(ARGS args) {
    
    static if (LogLevel <= Debug) {
        import std.stdio: writeln;
        writeln("D: ", args);
    }
}

void logError(ARGS...)(ARGS args) {
    static if (LogLevel <= Error) {
        import std.stdio: writeln, stderr;
        stderr.writeln("E: ", args);
    }
}