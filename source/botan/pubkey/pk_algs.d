/**
* PK Key Factory
* 
* Copyright:
* (C) 1999-2010,2016 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.pk_algs;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

import botan.pubkey.pk_keys;
import botan.asn1.oids;
import botan.utils.types;
import botan.rng.rng;
import botan.pubkey.algo.ec_group;

static if (BOTAN_HAS_RSA)                  import botan.pubkey.algo.rsa;
static if (BOTAN_HAS_DSA)                  import botan.pubkey.algo.dsa;
static if (BOTAN_HAS_DIFFIE_HELLMAN)       import botan.pubkey.algo.dh;
static if (BOTAN_HAS_ECDSA)                import botan.pubkey.algo.ecdsa;
static if (BOTAN_HAS_GOST_34_10_2001)      import botan.pubkey.algo.gost_3410;
static if (BOTAN_HAS_NYBERG_RUEPPEL)       import botan.pubkey.algo.nr;
static if (BOTAN_HAS_RW)                   import botan.pubkey.algo.rw;
static if (BOTAN_HAS_ELGAMAL)              import botan.pubkey.algo.elgamal;
static if (BOTAN_HAS_ECDH)                 import botan.pubkey.algo.ecdh;
static if (BOTAN_HAS_CURVE25519)           import botan.pubkey.algo.curve25519;
static if (BOTAN_HAS_ED25519)              import botan.pubkey.algo.ed25519;
static if (BOTAN_HAS_ED448)                import botan.pubkey.algo.ed448;
static if (BOTAN_HAS_X448)                 import botan.pubkey.algo.x448;
static if (BOTAN_HAS_SM2)                  import botan.pubkey.algo.sm2;
static if (BOTAN_HAS_ML_KEM)               import botan.pubkey.algo.ml_kem;
static if (BOTAN_HAS_ML_DSA)               import botan.pubkey.algo.ml_dsa;
static if (BOTAN_HAS_SLH_DSA)              import botan.pubkey.algo.slh_dsa;
static if (BOTAN_HAS_FRODOKEM)             import botan.pubkey.algo.frodo_kem;
static if (BOTAN_HAS_XMSS)                 import botan.pubkey.algo.xmss;
static if (BOTAN_HAS_HSS_LMS)              import botan.pubkey.algo.hss_lms;
static if (BOTAN_HAS_HYBRID_KEM)           import botan.pubkey.algo.hybrid_kem;
static if (BOTAN_HAS_CLASSIC_MCELIECE)     import botan.pubkey.algo.classic_mceliece;
static if (BOTAN_HAS_ECGDSA)               import botan.pubkey.algo.ecgdsa;
static if (BOTAN_HAS_ECKCDSA)              import botan.pubkey.algo.eckcdsa;

PublicKey makePublicKey(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits)
{
    const string alg_name = OIDS.lookup(alg_id.oid);
    if (alg_name == "")
        throw new DecodingError("Unknown algorithm OID: " ~ alg_id.oid.toString());
    
    static if (BOTAN_HAS_RSA) {
        if (alg_name == "RSA")
            return RSAPublicKey(alg_id, key_bits).release();
    }
    
    static if (BOTAN_HAS_RW) {
        if (alg_name == "RW")
			return RWPublicKey(alg_id, key_bits).release();
    }
    
    static if (BOTAN_HAS_DSA) {
        if (alg_name == "DSA")
			return DSAPublicKey(alg_id, key_bits).release();
    }
    
    static if (BOTAN_HAS_DIFFIE_HELLMAN) {
        if (alg_name == "DH")
			return DHPublicKey(alg_id, key_bits).release();
    }
    
    static if (BOTAN_HAS_NYBERG_RUEPPEL) {
        if (alg_name == "NR")
			return NRPublicKey(alg_id, key_bits).release();
    }
    
    static if (BOTAN_HAS_ELGAMAL) {
        if (alg_name == "ElGamal")
			return ElGamalPublicKey(alg_id, key_bits).release();
    }
    
    static if (BOTAN_HAS_ECDSA) {
        if (alg_name == "ECDSA")
			return ECDSAPublicKey(alg_id, key_bits).release();
    }
    
    static if (BOTAN_HAS_GOST_34_10_2001) {
        if (alg_name == "GOST-34.10")
			return GOST3410PublicKey(alg_id, key_bits).release();
    }
    
    static if (BOTAN_HAS_ECDH) {
        if (alg_name == "ECDH")
			return ECDHPublicKey(alg_id, key_bits).release();
    }

	static if (BOTAN_HAS_CURVE25519) {
		if (alg_name == "Curve25519" || alg_name == "X25519")
			return Curve25519PublicKey(alg_id, key_bits).release();
	}

    static if (BOTAN_HAS_ED25519) {
        if (alg_name == "Ed25519")
            return Ed25519PublicKey(alg_id, key_bits).release();
    }

    static if (BOTAN_HAS_ED448) {
        if (alg_name == "Ed448")
            return Ed448PublicKey(alg_id, key_bits).release();
    }

    static if (BOTAN_HAS_X448) {
        if (alg_name == "X448")
            return X448PublicKey(alg_id, key_bits).release();
    }

    static if (BOTAN_HAS_SM2) {
        if (alg_name == "SM2" || alg_name == "SM2_Enc")
            return SM2PublicKey(alg_id, key_bits).release();
    }

    static if (BOTAN_HAS_ML_KEM) {
        if (isMlkemOrKyberName(alg_name))
            return new MLKEMPublicKey(alg_id, key_bits);
    }

    static if (BOTAN_HAS_ML_DSA) {
        if (isMldsaOrDilithiumName(alg_name))
            return new MLDSAPublicKey(alg_id, key_bits);
    }

    static if (BOTAN_HAS_SLH_DSA) {
        if (isSlhOrSphincsName(alg_name))
            return new SLHDSAPublicKey(alg_id, key_bits);
    }

    static if (BOTAN_HAS_FRODOKEM) {
        if (isFrodoName(alg_name))
            return new FrodoPublicKey(alg_id, key_bits);
    }

    static if (BOTAN_HAS_XMSS) {
        if (alg_name == "XMSS")
            return new XMSSPublicKey(alg_id, key_bits);
    }

    static if (BOTAN_HAS_HSS_LMS) {
        if (alg_name == "HSS-LMS")
            return new HSSLMSPublicKey(alg_id, key_bits);
    }

    static if (BOTAN_HAS_HYBRID_KEM) {
        if (alg_name == "Hybrid-ML-KEM-768-X25519")
            return new HybridPublicKey(alg_id, key_bits);
    }

    static if (BOTAN_HAS_CLASSIC_MCELIECE) {
        if (isCmceName(alg_name))
            return new ClassicMcEliecePublicKey(alg_id, key_bits);
    }

    static if (BOTAN_HAS_ECGDSA) {
        if (alg_name == "ECGDSA")
            return ECGDSAPublicKey(alg_id, key_bits).release();
    }

    static if (BOTAN_HAS_ECKCDSA) {
        if (alg_name == "ECKCDSA")
            return ECKCDSAPublicKey(alg_id, key_bits).release();
    }
    
    return null;
}

// TODO: use Embed!'s release() and make ~this delete the inner object if set
PrivateKey makePrivateKey(const ref AlgorithmIdentifier alg_id,
                          const ref SecureVector!ubyte key_bits,
                          RandomNumberGenerator rng)
{
    const string alg_name = OIDS.lookup(alg_id.oid);
    if (alg_name == "")
        throw new DecodingError("Unknown algorithm OID: " ~ alg_id.oid.toString());
    
    static if (BOTAN_HAS_RSA) {
        if (alg_name == "RSA")
			return RSAPrivateKey(alg_id, key_bits, rng).release();
    }
    
    static if (BOTAN_HAS_RW) {
        if (alg_name == "RW")
			return RWPrivateKey(alg_id, key_bits, rng).release();
    }
    
    static if (BOTAN_HAS_DSA) {
        if (alg_name == "DSA")
			return DSAPrivateKey(alg_id, key_bits, rng).release();
    }
    
    static if (BOTAN_HAS_DIFFIE_HELLMAN) {
        if (alg_name == "DH")
			return DHPrivateKey(alg_id, key_bits, rng).release();
    }
    
    static if (BOTAN_HAS_NYBERG_RUEPPEL) {
        if (alg_name == "NR")
			return NRPrivateKey(alg_id, key_bits, rng).release();
    }
    
    static if (BOTAN_HAS_ELGAMAL) {
        if (alg_name == "ElGamal")
			return ElGamalPrivateKey(alg_id, key_bits, rng).release();
    }
    
    static if (BOTAN_HAS_ECDSA) {
        if (alg_name == "ECDSA")
			return ECDSAPrivateKey(alg_id, key_bits).release();
    }
    
    static if (BOTAN_HAS_GOST_34_10_2001) {
        if (alg_name == "GOST-34.10")
			return GOST3410PrivateKey(alg_id, key_bits).release();
    }
    
    static if (BOTAN_HAS_ECDH) {
        if (alg_name == "ECDH")
			return ECDHPrivateKey(alg_id, key_bits).release();
    }
	
	static if (BOTAN_HAS_CURVE25519) {
		if (alg_name == "Curve25519" || alg_name == "X25519")
			return Curve25519PrivateKey(alg_id, key_bits, rng).release();
	}

    static if (BOTAN_HAS_ED25519) {
        if (alg_name == "Ed25519")
            return Ed25519PrivateKey(alg_id, key_bits, rng).release();
    }

    static if (BOTAN_HAS_ED448) {
        if (alg_name == "Ed448")
            return Ed448PrivateKey(alg_id, key_bits, rng).release();
    }

    static if (BOTAN_HAS_X448) {
        if (alg_name == "X448")
            return X448PrivateKey(alg_id, key_bits, rng).release();
    }

    static if (BOTAN_HAS_SM2) {
        if (alg_name == "SM2" || alg_name == "SM2_Enc")
            return SM2PrivateKey(alg_id, key_bits).release();
    }

    static if (BOTAN_HAS_ML_KEM) {
        if (isMlkemOrKyberName(alg_name))
            return new MLKEMPrivateKey(alg_id, key_bits, rng);
    }

    static if (BOTAN_HAS_ML_DSA) {
        if (isMldsaOrDilithiumName(alg_name))
            return new MLDSAPrivateKey(alg_id, key_bits, rng);
    }

    static if (BOTAN_HAS_SLH_DSA) {
        if (isSlhOrSphincsName(alg_name))
            return new SLHDSAPrivateKey(alg_id, key_bits, rng);
    }

    static if (BOTAN_HAS_FRODOKEM) {
        if (isFrodoName(alg_name))
            return new FrodoPrivateKey(alg_id, key_bits, rng);
    }

    static if (BOTAN_HAS_CLASSIC_MCELIECE) {
        if (isCmceName(alg_name))
            return new ClassicMcEliecePrivateKey(alg_id, key_bits, rng);
    }

    static if (BOTAN_HAS_XMSS) {
        if (alg_name == "XMSS")
            return new XMSSPrivateKey(alg_id, key_bits, rng);
    }

    static if (BOTAN_HAS_HSS_LMS) {
        if (alg_name == "HSS-LMS" || alg_name == "HSS-LMS-Private-Key")
            return new HSSLMSPrivateKey(alg_id, key_bits, rng);
    }

    static if (BOTAN_HAS_ECGDSA) {
        if (alg_name == "ECGDSA")
            return ECGDSAPrivateKey(alg_id, key_bits).release();
    }

    static if (BOTAN_HAS_ECKCDSA) {
        if (alg_name == "ECKCDSA")
            return ECKCDSAPrivateKey(alg_id, key_bits).release();
    }
    
    return null;
}

/**
* C++ `create_private_key(algo, rng, params)`. Returns null if the algorithm
* is unknown or the parameters are not available in this build.
*/
PrivateKey createPrivateKey(string alg_name, RandomNumberGenerator rng, string params = "")
{
    static if (BOTAN_HAS_RSA) {
        if (alg_name == "RSA")
        {
            import std.conv : to;
            const size_t bits = params.length ? to!size_t(params) : 3072;
            return RSAPrivateKey(rng, bits).release();
        }
    }
    static if (BOTAN_HAS_DSA) {
        if (alg_name == "DSA")
        {
            import botan.pubkey.algo.dl_group;
            auto grp = DLGroup(params.length ? params : "dsa/jce/1024");
            return DSAPrivateKey(rng, grp.move()).release();
        }
    }
    static if (BOTAN_HAS_ECDSA) {
        if (alg_name == "ECDSA")
        {
            auto group = ECGroup(params.length ? params : "secp256r1");
            return ECDSAPrivateKey(rng, group).release();
        }
    }
    static if (BOTAN_HAS_ECGDSA) {
        if (alg_name == "ECGDSA")
        {
            auto group = ECGroup(params.length ? params : "brainpool256r1");
            return ECGDSAPrivateKey(rng, group).release();
        }
    }
    static if (BOTAN_HAS_ECKCDSA) {
        if (alg_name == "ECKCDSA")
        {
            auto group = ECGroup(params.length ? params : "secp256r1");
            return ECKCDSAPrivateKey(rng, group).release();
        }
    }
    static if (BOTAN_HAS_ED25519) {
        if (alg_name == "Ed25519")
            return Ed25519PrivateKey(rng).release();
    }
    static if (BOTAN_HAS_ED448) {
        if (alg_name == "Ed448")
            return Ed448PrivateKey(rng).release();
    }
    static if (BOTAN_HAS_SM2) {
        if (alg_name == "SM2" || alg_name == "SM2_Sig" || alg_name == "SM2_Enc")
        {
            auto group = ECGroup(params.length ? params : "sm2p256v1");
            return SM2PrivateKey(rng, group).release();
        }
    }
    static if (BOTAN_HAS_GOST_34_10_2001) {
        if (alg_name == "GOST-34.10" || alg_name == "GOST-34.10-2012-256")
        {
            auto group = ECGroup(params.length ? params : "gost_256A");
            return GOST3410PrivateKey(rng, group).release();
        }
    }
    static if (BOTAN_HAS_ML_DSA) {
        if (alg_name == "Dilithium" || alg_name == "ML-DSA" ||
            (alg_name.length >= 10 && alg_name[0 .. 10] == "Dilithium-") ||
            (alg_name.length >= 7 && alg_name[0 .. 7] == "ML-DSA-"))
        {
            const string name = params.length ? params : (alg_name == "ML-DSA" ? "ML-DSA-6x5" : alg_name);
            return new MLDSAPrivateKey(name, rng);
        }
    }
    static if (BOTAN_HAS_SLH_DSA) {
        if (alg_name == "SLH-DSA" || alg_name == "SPHINCS+" || alg_name == "SphincsPlus")
            return new SLHDSAPrivateKey(params.length ? params : "SLH-DSA-SHA2-128f", rng);
    }
    static if (BOTAN_HAS_XMSS) {
        if (alg_name == "XMSS")
            return new XMSSPrivateKey(params.length ? params : "XMSS-SHA2_10_256", rng);
    }
    static if (BOTAN_HAS_HSS_LMS) {
        if (alg_name == "HSS-LMS")
            return new HSSLMSPrivateKey(params.length ? params : "SHA-256,HW(5,8)", rng);
    }
    return null;
}

static if (BOTAN_HAS_TESTS && !SKIP_X509_KEY_TEST) unittest
{
    import botan.test;
    import botan.libstate.global_state;
    import botan.rng.auto_rng;
    import botan.pubkey.pubkey;
    import botan.pubkey.x509_key;
    import botan.codec.hex;
    import memutils.hashmap;
    import std.stdio : File;
    import std.file : exists;

    auto state = globalState();
    logDebug("Testing pk_algs createPrivateKey / api_sign ...");
    size_t fails;

    string apiSignPadding(string alg, string sig_params)
    {
        if (alg == "SM2")
            return "Raw";
        if (alg == "Ed25519" && (sig_params == "Pure" || !sig_params.length))
            return "Raw";
        if (alg == "XMSS")
            return "Raw";
        if (!sig_params.length)
            return "Raw";
        return sig_params;
    }

    if (exists("test_data/pubkey/api_sign.vec"))
    {
        Unique!AutoSeededRNG rng = new AutoSeededRNG;
        File vec = File("test_data/pubkey/api_sign.vec", "r");
        fails += runTestsBb(vec, "Algo", "SigParams", true,
            (ref HashMap!(string, string) m)
            {
                const string alg = m["Algo"];
                const string params = ("AlgoParams" in m) ? m["AlgoParams"] : "";
                const string sigp = ("SigParams" in m) ? m["SigParams"] : "";
                PrivateKey created;
                try
                    created = createPrivateKey(alg, *rng, params);
                catch (Exception e)
                {
                    logTrace("api_sign skip ", alg, "(", params, "): ", e.msg);
                    return 0;
                }
                if (!created)
                {
                    logTrace("api_sign skip ", alg, "(", params, "): no factory");
                    return 0;
                }
                Unique!PrivateKey priv = created;
                try
                {
                    auto pub_bits = x509_key.BER_encode(*priv);
                    if (!pub_bits.length)
                    {
                        logError(alg, " public key BER empty");
                        return 1;
                    }
                    Unique!PublicKey pub = x509_key.loadKey(pub_bits);
                    if (!pub)
                    {
                        logError(alg, " public key reload failed");
                        return 1;
                    }
                    const string pad = apiSignPadding(alg, sigp);
                    auto sign = PKSigner(*priv, pad);
                    auto vfy = PKVerifier(*pub, pad);
                    ubyte[4] msg = [0xde, 0xad, 0xbe, 0xef];
                    auto sig = sign.signMessage(msg.ptr, msg.length, *rng);
                    if (!sig.length)
                    {
                        logError(alg, " empty signature");
                        return 1;
                    }
                    if (!vfy.verifyMessage(msg.ptr, msg.length, sig.ptr, sig.length))
                    {
                        logError(alg, "/", pad, " verify failed");
                        return 1;
                    }
                    return 0;
                }
                catch (Exception e)
                {
                    logError(alg, "/", sigp, ": ", e.msg);
                    return 1;
                }
            });
    }

    if (fails)
        logError("api_sign failures: ", fails);
    assert(fails == 0);
}