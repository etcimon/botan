/**
* Core Engine
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.engine.core_engine;

import botan.engine.engine;
import botan.rng.rng;
import botan.utils.parsing;
import botan.filters.filters;
import botan.algo_factory.algo_factory;
import botan.modes.mode_pad;
import botan.filters.transform_filter;
import botan.math.numbertheory.def_powm;
import botan.algo_base.scan_token;
import botan.algo_factory.algo_factory;
import std.algorithm : canFind;
import std.conv : to;

import botan.constants;
static if (BOTAN_HAS_MODE_CFB)        import botan.modes.cfb;
static if (BOTAN_HAS_MODE_ECB)        import botan.modes.ecb;
static if (BOTAN_HAS_MODE_CBC)        import botan.modes.cbc;
static if (BOTAN_HAS_MODE_XTS)        import botan.modes.xts;

static if (BOTAN_HAS_OFB)             import botan.stream.ofb;
static if (BOTAN_HAS_CTR_BE)          import botan.stream.ctr;

static if (BOTAN_HAS_AEAD_FILTER)     import botan.filters.aead_filt;
static if (BOTAN_HAS_AEAD_CCM)        import botan.modes.aead.ccm;
static if (BOTAN_HAS_AEAD_EAX)        import botan.modes.aead.eax;    
static if (BOTAN_HAS_AEAD_OCB)        import botan.modes.aead.ocb;
static if (BOTAN_HAS_AEAD_GCM)        import botan.modes.aead.gcm;
static if (BOTAN_HAS_RSA)             import botan.pubkey.algo.rsa;
static if (BOTAN_HAS_RW)              import botan.pubkey.algo.rw;
static if (BOTAN_HAS_DSA)             import botan.pubkey.algo.dsa;
static if (BOTAN_HAS_ECDSA)           import botan.pubkey.algo.ecdsa;
static if (BOTAN_HAS_ELGAMAL)         import botan.pubkey.algo.elgamal;
static if (BOTAN_HAS_GOST_34_10_2001) import botan.pubkey.algo.gost_3410;
static if (BOTAN_HAS_NYBERG_RUEPPEL)  import  botan.pubkey.algo.nr;
static if (BOTAN_HAS_DIFFIE_HELLMAN)  import botan.pubkey.algo.dh;
static if (BOTAN_HAS_ECDH)            import botan.pubkey.algo.ecdh;
/// Blocks
static if (BOTAN_HAS_AES)             import botan.block.aes;
static if (BOTAN_HAS_BLOWFISH)        import botan.block.blowfish;
static if (BOTAN_HAS_CAMELLIA)        import botan.block.camellia;
static if (BOTAN_HAS_CAST) {
                                      import botan.block.cast128;
                                      import botan.block.cast256;
}
static if (BOTAN_HAS_CASCADE)         import botan.block.cascade;
static if (BOTAN_HAS_DES){
                                      import botan.block.des;
                                      import botan.block.desx;
}
static if (BOTAN_HAS_GOST_28147_89)   import botan.block.gost_28147;
static if (BOTAN_HAS_IDEA)            import botan.block.idea;
static if (BOTAN_HAS_KASUMI)          import botan.block.kasumi;
static if (BOTAN_HAS_LION)            import botan.block.lion;
static if (BOTAN_HAS_MARS)            import botan.block.mars;
static if (BOTAN_HAS_MISTY1)          import botan.block.misty1;
static if (BOTAN_HAS_NOEKEON)         import botan.block.noekeon;
static if (BOTAN_HAS_RC2)             import botan.block.rc2;
static if (BOTAN_HAS_RC5)             import botan.block.rc5;
static if (BOTAN_HAS_RC6)             import botan.block.rc6;
static if (BOTAN_HAS_SAFER)           import botan.block.safer_sk;
static if (BOTAN_HAS_SEED)            import botan.block.seed;
static if (BOTAN_HAS_SERPENT)         import botan.block.serpent;
static if (BOTAN_HAS_TEA)             import botan.block.tea;
static if (BOTAN_HAS_TWOFISH)         import botan.block.twofish;
static if (BOTAN_HAS_THREEFISH_512)   import botan.block.threefish;
static if (BOTAN_HAS_XTEA)            import botan.block.xtea;

//Hash
static if (BOTAN_HAS_ADLER32)         import botan.checksum.adler32;
static if (BOTAN_HAS_CRC24)           import botan.checksum.crc24;
static if (BOTAN_HAS_CRC32)           import botan.checksum.crc32;
static if (BOTAN_HAS_GOST_34_11)      import botan.hash.gost_3411;
static if (BOTAN_HAS_HAS_160)         import botan.hash.has160;
static if (BOTAN_HAS_KECCAK)          import botan.hash.keccak;
static if (BOTAN_HAS_MD2)             import botan.hash.md2;
static if (BOTAN_HAS_MD4)             import botan.hash.md4;
static if (BOTAN_HAS_MD5)             import botan.hash.md5;
static if (BOTAN_HAS_RIPEMD_128)      import botan.hash.rmd128;
static if (BOTAN_HAS_RIPEMD_160)      import botan.hash.rmd160;
static if (BOTAN_HAS_SHA1)            import botan.hash.sha160;
static if (BOTAN_HAS_SHA2_32)         import botan.hash.sha2_32;
static if (BOTAN_HAS_SHA2_64)         import botan.hash.sha2_64;
static if (BOTAN_HAS_SKEIN_512)       import botan.hash.skein_512;
static if (BOTAN_HAS_TIGER)           import botan.hash.tiger;
static if (BOTAN_HAS_WHIRLPOOL)       import botan.hash.whrlpool;
static if (BOTAN_HAS_PARALLEL_HASH)   import botan.hash.par_hash;
static if (BOTAN_HAS_COMB4P)          import botan.hash.comb4p;

/// MAC
static if (BOTAN_HAS_CBC_MAC)         import botan.mac.cbc_mac;
static if (BOTAN_HAS_CMAC)            import botan.mac.cmac;
static if (BOTAN_HAS_HMAC)            import botan.mac.hmac;
static if (BOTAN_HAS_SSL3_MAC)        import botan.mac.ssl3_mac;
static if (BOTAN_HAS_ANSI_X919_MAC)   import botan.mac.x919_mac;

/// PBKDF
static if (BOTAN_HAS_PBKDF1)          import botan.pbkdf.pbkdf1;
static if (BOTAN_HAS_PBKDF2)          import botan.pbkdf.pbkdf2;

/// STREAM
static if (BOTAN_HAS_RC4)             import botan.stream.rc4;
static if (BOTAN_HAS_CHACHA)          import botan.stream.chacha;
static if (BOTAN_HAS_SALSA20)         import botan.stream.salsa20;

/**
* Core Engine
*/
final class CoreEngine : Engine
{
public:
    string providerName() const { return "core"; }

    override KeyedFilter getCipher(in string algo_spec,
                          CipherDir direction,
                          AlgorithmFactory af) const
    {
        Vector!string algo_parts = splitter(algo_spec, '/');
        if (algo_parts.empty)
            throw new InvalidAlgorithmName(algo_spec);
        
        const string cipher_name = algo_parts[0];
        
        // check if it is a stream cipher first (easy case)
        const StreamCipher stream_cipher = af.prototypeStreamCipher(cipher_name);
        if (stream_cipher)
            return new StreamCipherFilter(stream_cipher.clone());
        
        const BlockCipher block_cipher = af.prototypeBlockCipher(cipher_name);
        if (!block_cipher)
            return null;
        
        if (algo_parts.length >= 4)
            return null; // 4 part mode, not something we know about
        
        if (algo_parts.length < 2)
            throw new LookupError("Cipher specification '" ~ algo_spec ~ "' is missing mode identifier");
        
        string mode = algo_parts[1];
        
        string padding;
        if (algo_parts.length == 3)
            padding = algo_parts[2];
        else
            padding = (mode == "CBC") ? "PKCS7" : "NoPadding";
        
        if (mode == "ECB" && padding == "CTS")
            return null;
        else if ((mode != "CBC" && mode != "ECB") && padding != "NoPadding")
            throw new InvalidAlgorithmName(algo_spec);
        
        KeyedFilter filt = getCipherMode(block_cipher, direction, mode, padding);
        if (filt)
            return filt;
        
        if (padding != "NoPadding")
            throw new AlgorithmNotFound(cipher_name ~ "/" ~ mode ~ "/" ~ padding);
        else
            throw new AlgorithmNotFound(cipher_name ~ "/" ~ mode);
    }

    override BlockCipher findBlockCipher(in SCANToken request, AlgorithmFactory af) const
    {
        //logTrace("FindBlockCipher Core ", request.algoName);
        
        static if (BOTAN_HAS_AES) {
            if (request.algoName == "AES-128")
                return new AES128;
            if (request.algoName == "AES-192")
                return new AES192;
            if (request.algoName == "AES-256")
                return new AES256;
        }
        
        static if (BOTAN_HAS_BLOWFISH) {
            if (request.algoName == "Blowfish")
                return new Blowfish;
        }
        
        static if (BOTAN_HAS_CAMELLIA) {
            if (request.algoName == "Camellia-128")
                return new Camellia128;
            if (request.algoName == "Camellia-192")
                return new Camellia192;
            if (request.algoName == "Camellia-256")
                return new Camellia256;
        }
        
        static if (BOTAN_HAS_CAST) {
            if (request.algoName == "CAST-128")
                return new CAST128;
            if (request.algoName == "CAST-256")
                return new CAST256;
        }
        
        static if (BOTAN_HAS_DES) {
            if (request.algoName == "DES")
                return new DES;
            if (request.algoName == "DESX")
                return new DESX;
            if (request.algoName == "TripleDES")
                return new TripleDES;
        }
        
        static if (BOTAN_HAS_GOST_28147_89) {
            if (request.algoName == "GOST-28147-89")
                return new GOST_28147_89(request.arg(0, "R3411_94_TestParam"));
        }
        
        static if (BOTAN_HAS_IDEA) {
            if (request.algoName == "IDEA")
                return new IDEA;
        }
        
        static if (BOTAN_HAS_KASUMI) {
            if (request.algoName == "KASUMI")
                return new KASUMI;
        }
        
        static if (BOTAN_HAS_MARS) {
            if (request.algoName == "MARS")
                    return new MARS;
        }
        
        static if (BOTAN_HAS_MISTY1) {
            if (request.algoName == "MISTY1")
                return new MISTY1(request.argAsInteger(0, 8));
        }
        
        static if (BOTAN_HAS_NOEKEON) {
            if (request.algoName == "Noekeon")
                return new Noekeon;
        }
        
        static if (BOTAN_HAS_RC2) {
            if (request.algoName == "RC2")
                return new RC2;
        }
        
        static if (BOTAN_HAS_RC5) {
            if (request.algoName == "RC5")
                return new RC5(request.argAsInteger(0, 12));
        }
        
        static if (BOTAN_HAS_RC6) {
            if (request.algoName == "RC6")
                return new RC6;
        }
        
        static if (BOTAN_HAS_SAFER) {
            if (request.algoName == "SAFER-SK")
                return new SAFERSK(request.argAsInteger(0, 10));
        }
        
        static if (BOTAN_HAS_SEED) {
            if (request.algoName == "SEED")
                return new SEED;
        }
        
        static if (BOTAN_HAS_SERPENT) {
            if (request.algoName == "Serpent")
                return new Serpent;
        }
        
        static if (BOTAN_HAS_TEA) {
            if (request.algoName == "TEA")
                return new TEA;
        }
        
        static if (BOTAN_HAS_TWOFISH) {
            if (request.algoName == "Twofish")
                return new Twofish;
        }
        
        static if (BOTAN_HAS_TWOFISH) {
            if (request.algoName == "Threefish-512")
                return new Threefish512;
        }
        
        static if (BOTAN_HAS_XTEA) {
            if (request.algoName == "XTEA")
                return new XTEA;
        }
        
        static if (BOTAN_HAS_CASCADE) {
            if (request.algoName == "Cascade" && request.argCount() == 2)
            {
                const BlockCipher c1 = af.prototypeBlockCipher(request.arg(0));
                const BlockCipher c2 = af.prototypeBlockCipher(request.arg(1));
                
                if (c1 && c2)
                    return new CascadeCipher(c1.clone(), c2.clone());
            }
        }
        
        static if (BOTAN_HAS_LION) {
            if (request.algoName == "Lion" && request.argCountBetween(2, 3))
            {
                const size_t block_size = request.argAsInteger(2, 1024);
                
                const HashFunction hash = af.prototypeHashFunction(request.arg(0));
                
                const StreamCipher stream_cipher = af.prototypeStreamCipher(request.arg(1));
                
                if (!hash || !stream_cipher)
                    return null;
                
                return new Lion(hash.clone(), stream_cipher.clone(), block_size);
            }
        }
        
        return null;
    }

    override StreamCipher findStreamCipher(in SCANToken request, AlgorithmFactory af) const
    {
        //logTrace("FindStreamCipher Core ", request.algoName);
        static if (BOTAN_HAS_OFB) {
            if (request.algoName == "OFB" && request.argCount() == 1)
            {
                if (auto proto = af.prototypeBlockCipher(request.arg(0)))
                    return new OFB(proto.clone());
            }
        }
        
        static if (BOTAN_HAS_CTR_BE) {
            if (request.algoName == "CTR-BE" && request.argCount() == 1)
            {
                if (auto proto = af.prototypeBlockCipher(request.arg(0)))
                    return new CTRBE(proto.clone());
            }
        }
        
        static if (BOTAN_HAS_RC4) {
            if (request.algoName == "RC4")
                return new RC4(request.argAsInteger(0, 0));
            if (request.algoName == "RC4_drop")
                return new RC4(768);
        }
        
        static if (BOTAN_HAS_CHACHA) {
            if (request.algoName == "ChaCha")
                return new ChaCha;
        }
        
        static if (BOTAN_HAS_SALSA20) {
            if (request.algoName == "Salsa20")
                return new Salsa20;
        }
        
        return null;
    }

    override HashFunction findHash(in SCANToken request, AlgorithmFactory af) const
    {
        //logTrace("FindHash Core");
        static if (BOTAN_HAS_ADLER32) {
            if (request.algoName == "Adler32")
                return new Adler32;
        }
        
        static if (BOTAN_HAS_CRC24) {
            if (request.algoName == "CRC24")
                return new CRC24;
        }
        
        static if (BOTAN_HAS_CRC32) {
            if (request.algoName == "CRC32")
                return new CRC32;
        }
        
        static if (BOTAN_HAS_GOST_34_11) {
            if (request.algoName == "GOST-R-34.11-94")
                return new GOST3411;
        }
        
        static if (BOTAN_HAS_HAS_160) {
            if (request.algoName == "HAS-160")
                return new HAS160;
        }
        
        static if (BOTAN_HAS_KECCAK) {
            if (request.algoName == "Keccak-1600")
                return new Keccak1600(request.argAsInteger(0, 512));
        }
        
        static if (BOTAN_HAS_MD2) {
            if (request.algoName == "MD2")
                return new MD2;
        }
        
        static if (BOTAN_HAS_MD4) {
            if (request.algoName == "MD4")
                return new MD4;
        }
        
        static if (BOTAN_HAS_MD5) {
            if (request.algoName == "MD5")
                return new MD5;
        }
        
        static if (BOTAN_HAS_RIPEMD_128) {
            if (request.algoName == "RIPEMD-128")
                return new RIPEMD128;
        }
        
        static if (BOTAN_HAS_RIPEMD_160) {
            if (request.algoName == "RIPEMD-160")
                return new RIPEMD160;
        }
        
        static if (BOTAN_HAS_SHA1) {
            if (request.algoName == "SHA-160")
                return new SHA160;
        }
        
        static if (BOTAN_HAS_SHA2_32) {
            if (request.algoName == "SHA-224")
                return new SHA224;
            if (request.algoName == "SHA-256")
                return new SHA256;
        }
        
        static if (BOTAN_HAS_SHA2_64) {
            if (request.algoName == "SHA-384")
                return new SHA384;
            if (request.algoName == "SHA-512")
                return new SHA512;
        }
        
        static if (BOTAN_HAS_TIGER) {
            if (request.algoName == "Tiger")
                return new Tiger(request.argAsInteger(0, 24), // hash output
                                 request.argAsInteger(1, 3)); // # passes
        }
        
        static if (BOTAN_HAS_SKEIN_512) {
            if (request.algoName == "Skein-512")
                return new Skein512(request.argAsInteger(0, 512),
                                     request.arg(1, ""));
        }
        
        static if (BOTAN_HAS_WHIRLPOOL) {
            if (request.algoName == "Whirlpool")
                return new Whirlpool;
        }
        
        static if (BOTAN_HAS_COMB4P) {
            if (request.algoName == "Comb4P" && request.argCount() == 2)
            {
                const HashFunction h1 = af.prototypeHashFunction(request.arg(0));
                const HashFunction h2 = af.prototypeHashFunction(request.arg(1));
                
                if (h1 && h2)
                    return new Comb4P(h1.clone(), h2.clone());
            }
        }
        
        static if (BOTAN_HAS_PARALLEL_HASH) {
            
            if (request.algoName == "Parallel")
            {
                Vector!HashFunction hash_prototypes;
                
                /* First pass, just get the prototypes (no memory allocation). Then
                    if all were found, replace each prototype with a newly created clone
                */
                foreach (size_t i; 0 .. request.argCount())
                {
                    HashFunction hash = cast(HashFunction)af.prototypeHashFunction(request.arg(i));
                    if (!hash)
                        return null;
                    
                    hash_prototypes.pushBack(hash);
                }
                
                Vector!HashFunction hashes;
                foreach (hash_prototype; hash_prototypes[])
                    hashes.pushBack(hash_prototype.clone());
                
                return new Parallel(hashes.move());
            }
        }
        
        return null;
        
    }

    override MessageAuthenticationCode findMac(in SCANToken request, AlgorithmFactory af) const
    {
        //logTrace("FindMac Core");
        static if (BOTAN_HAS_CBC_MAC) {
            if (request.algoName == "CBC-MAC" && request.argCount() == 1)
                return new CBCMAC(af.makeBlockCipher(request.arg(0)));
        }
        
        static if (BOTAN_HAS_CMAC) {
            if (request.algoName == "CMAC" && request.argCount() == 1)
                return new CMAC(af.makeBlockCipher(request.arg(0)));
        }
        
        static if (BOTAN_HAS_HMAC) {
            if (request.algoName == "HMAC" && request.argCount() == 1) {
                return new HMAC(af.makeHashFunction(request.arg(0)));
            }
        }
        
        static if (BOTAN_HAS_SSL3_MAC) {
            if (request.algoName == "SSL3-MAC" && request.argCount() == 1)
                return new SSL3MAC(af.makeHashFunction(request.arg(0)));
        }
        
        static if (BOTAN_HAS_ANSI_X919_MAC) {
            if (request.algoName == "X9.19-MAC" && request.argCount() == 0)
                return new ANSIX919MAC(af.makeBlockCipher("DES"));
        }
        
        return null;
    }


    override PBKDF findPbkdf(in SCANToken algo_spec, AlgorithmFactory af) const
    {
        //logTrace("FindPbkdf Core");
        static if (BOTAN_HAS_PBKDF1) {
            if (algo_spec.algoName == "PBKDF1" && algo_spec.argCount() == 1)
                return new PKCS5_PBKDF1(af.makeHashFunction(algo_spec.arg(0)));
        }
        
        static if (BOTAN_HAS_PBKDF2) {
            if (algo_spec.algoName == "PBKDF2" && algo_spec.argCount() == 1)
            {
                if (const MessageAuthenticationCode mac_proto = af.prototypeMac(algo_spec.arg(0)))
                    return new PKCS5_PBKDF2(mac_proto.clone());
                
                return new PKCS5_PBKDF2(af.makeMac("HMAC(" ~ algo_spec.arg(0) ~ ")"));
            }
        }
        
        return null;
    }

    static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

    override ModularExponentiator modExp(const ref BigInt n, PowerMod.UsageHints hints) const
    {
        if (n.isOdd()) {
            //logTrace("Loading MontgomeryExponentiator");
            return new MontgomeryExponentiator(n, hints);
        }
        //logTrace("Loading FixedWindowExponentiator");
        return new FixedWindowExponentiator(n, hints);
    }

    override KeyAgreement getKeyAgreementOp(in PrivateKey key, RandomNumberGenerator rng) const
    {
        static if (BOTAN_HAS_DIFFIE_HELLMAN) {
            if (DHPrivateKey.algoName == key.algoName)
                return new DHKAOperation(key, rng);
        }
        
        static if (BOTAN_HAS_ECDH) {
            if (ECDHPrivateKey.algoName == key.algoName)
                return new ECDHKAOperation(key);
        }
        
        return null;
    }
    
    override Signature getSignatureOp(in PrivateKey key, RandomNumberGenerator rng) const
    {
        static if (BOTAN_HAS_RSA) {
            if (RSAPrivateKey.algoName == key.algoName) {
                return new RSAPrivateOperation(key, rng);
            }
        }
        
        static if (BOTAN_HAS_RW) {
            if (RWPrivateKey.algoName == key.algoName)
                return new RWSignatureOperation(key);
        }
        
        static if (BOTAN_HAS_DSA) {
            if (DSAPrivateKey.algoName == key.algoName)
                return new DSASignatureOperation(key);
        }
        
        static if (BOTAN_HAS_ECDSA) {
            if (ECDSAPrivateKey.algoName == key.algoName)
                return new ECDSASignatureOperation(key);
        }
        
        static if (BOTAN_HAS_GOST_34_10_2001) {
            if (GOST3410PrivateKey.algoName == key.algoName)
                return new GOST3410SignatureOperation(key);
        }
        
        static if (BOTAN_HAS_NYBERG_RUEPPEL) {
            if (NRPrivateKey.algoName == key.algoName)
                return new NRSignatureOperation(key);
        }
        
        return null;
    }
    
    override Verification getVerifyOp(in PublicKey key, RandomNumberGenerator rng) const
    {
        static if (BOTAN_HAS_RSA) {
            if (RSAPublicKey.algoName == key.algoName)
                return new RSAPublicOperation(key);
        }
        
        static if (BOTAN_HAS_RW) {
            if (RWPublicKey.algoName == key.algoName)
                return new RWVerificationOperation(key);
        }
        
        static if (BOTAN_HAS_DSA) {
            if (DSAPublicKey.algoName == key.algoName)
                return new DSAVerificationOperation(key);
        }
        
        static if (BOTAN_HAS_ECDSA) {
            if (ECDSAPublicKey.algoName == key.algoName)
                return new ECDSAVerificationOperation(key);
        }
        
        static if (BOTAN_HAS_GOST_34_10_2001) {
            if (GOST3410PublicKey.algoName == key.algoName)
                return new GOST3410VerificationOperation(key);
        }
        
        static if (BOTAN_HAS_NYBERG_RUEPPEL) {
            if (NRPublicKey.algoName == key.algoName)
                return new NRVerificationOperation(key);
        }
        
        return null;
    }
    
    
    override Encryption getEncryptionOp(in PublicKey key, RandomNumberGenerator) const
    {
        static if (BOTAN_HAS_RSA) {
            if (RSAPublicKey.algoName == key.algoName)
                return new RSAPublicOperation(key);
        }
        
        static if (BOTAN_HAS_ELGAMAL) {
            if (ElGamalPublicKey.algoName == key.algoName)
                return new ElGamalEncryptionOperation(key);
        }
        
        return null;
    }
    
    override Decryption getDecryptionOp(in PrivateKey key, RandomNumberGenerator rng) const
    {
        static if (BOTAN_HAS_RSA) {
            if (RSAPrivateKey.algoName == key.algoName)
                return new RSAPrivateOperation(key, rng);
        }
        
        static if (BOTAN_HAS_ELGAMAL) {
            if (ElGamalPrivateKey.algoName == key.algoName)
                return new ElGamalDecryptionOperation(key, rng);
        }
        
        return null;
    }
}

/**
* Create a cipher mode filter object
* Params:
*  block_cipher = a block cipher object
*  direction = are we encrypting or decrypting?
*  mode = the name of the cipher mode to use
*  padding = the mode padding to use (only used for ECB, CBC)
*/
KeyedFilter getCipherMode(const BlockCipher block_cipher,
                          CipherDir direction,
                          in string mode,
                          in string padding)
{
    static if (BOTAN_HAS_OFB) {
        if (mode == "OFB")
            return new StreamCipherFilter(new OFB(block_cipher.clone()));
    }
        
    static if (BOTAN_HAS_CTR_BE) {
        if (mode == "CTR-BE")
            return new StreamCipherFilter(new CTRBE(block_cipher.clone()));
    }
        
    static if (BOTAN_HAS_MODE_ECB) {
        if (mode == "ECB" || mode == "")
        {
            if (direction == ENCRYPTION)
                return new TransformationFilter(
                    new ECBEncryption(block_cipher.clone(), getBcPad(padding, "NoPadding")));
            else
                return new TransformationFilter(
                    new ECBDecryption(block_cipher.clone(), getBcPad(padding, "NoPadding")));
        }
    }
    
    if (mode == "CBC")
    {
        static if (BOTAN_HAS_MODE_CBC) {
                if (padding == "CTS")
                {
                    if (direction == ENCRYPTION)
                        return new TransformationFilter(new CTSEncryption(block_cipher.clone()));
                    else
                        return new TransformationFilter(new CTSDecryption(block_cipher.clone()));
                }
                
                if (direction == ENCRYPTION)
                    return new TransformationFilter(
                        new CBCEncryption(block_cipher.clone(), getBcPad(padding, "PKCS7")));
                else
                    return new TransformationFilter(
                        new CBCDecryption(block_cipher.clone(), getBcPad(padding, "PKCS7")));
        } else {
                return null;
        }
    }
    
    static if (BOTAN_HAS_MODE_XTS) {
        if (mode == "XTS")
        {
            if (direction == ENCRYPTION)
                return new TransformationFilter(new XTSEncryption(block_cipher.clone()));
            else
                return new TransformationFilter(new XTSDecryption(block_cipher.clone()));
        }
    }
    
    if (mode.canFind("CFB") ||
        mode.canFind("EAX") ||
        mode.canFind("GCM") ||
        mode.canFind("OCB") ||
        mode.canFind("CCM"))
    {
        Vector!string algo_info = parseAlgorithmName(mode);
        const string mode_name = algo_info[0];
        
        size_t bits = 8 * block_cipher.blockSize();
        if (algo_info.length > 1)
            bits = to!uint(algo_info[1]);
        
        static if (BOTAN_HAS_MODE_CFB) {
                if (mode_name == "CFB")
                {
                    if (direction == ENCRYPTION)
                        return new TransformationFilter(new CFBEncryption(block_cipher.clone(), bits));
                    else
                        return new TransformationFilter(new CFBDecryption(block_cipher.clone(), bits));
                }
        }
                
        if (bits % 8 != 0)
            throw new InvalidArgument("AEAD interface does not support non-octet length tags");
        
        static if (BOTAN_HAS_AEAD_FILTER) {
        
            const size_t tag_size = bits / 8;
            
            static if (BOTAN_HAS_AEAD_CCM) {
                    if (mode_name == "CCM")
                    {
                        const size_t L = (algo_info.length == 3) ? to!uint(algo_info[2]) : 3;
                        if (direction == ENCRYPTION)
                            return new AEADFilter(new CCMEncryption(block_cipher.clone(), tag_size, L));
                        else
                            return new AEADFilter(new CCMDecryption(block_cipher.clone(), tag_size, L));
                    }
            }
                    
            static if (BOTAN_HAS_AEAD_EAX) {
                    if (mode_name == "EAX")
                    {
                        if (direction == ENCRYPTION)
                            return new AEADFilter(new EAXEncryption(block_cipher.clone(), tag_size));
                        else
                            return new AEADFilter(new EAXDecryption(block_cipher.clone(), tag_size));
                    }
            }
                    
            static if (BOTAN_HAS_AEAD_OCB) {
                    if (mode_name == "OCB")
                    {
                        if (direction == ENCRYPTION)
                            return new AEADFilter(new OCBEncryption(block_cipher.clone(), tag_size));
                        else
                            return new AEADFilter(new OCBDecryption(block_cipher.clone(), tag_size));
                    }
            }
                    
            static if (BOTAN_HAS_AEAD_GCM) {
                    if (mode_name == "GCM")
                    {
                        if (direction == ENCRYPTION)
                            return new AEADFilter(new GCMEncryption(block_cipher.clone(), tag_size));
                        else
                            return new AEADFilter(new GCMDecryption(block_cipher.clone(), tag_size));
                    }
            }
            
        }
    }
    
    return null;
}

private {
    
    /**
    * Get a block cipher padding method by name
    */
    BlockCipherModePaddingMethod getBcPad(in string algo_spec, in string def_if_empty)
    {
        static if (BOTAN_HAS_CIPHER_MODE_PADDING) {
            if (algo_spec == "NoPadding" || (algo_spec == "" && def_if_empty == "NoPadding"))
                return new NullPadding;
            
            if (algo_spec == "PKCS7" || (algo_spec == "" && def_if_empty == "PKCS7"))
                return new PKCS7Padding;
            
            if (algo_spec == "OneAndZeros")
                return new OneAndZerosPadding;
            
            if (algo_spec == "X9.23")
                return new ANSIX923Padding;
            
        }
        
        throw new AlgorithmNotFound(algo_spec);
    }
    
}