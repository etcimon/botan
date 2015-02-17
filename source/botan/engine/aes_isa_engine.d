/**
* Engine for AES instructions
* 
* Copyright:
* (C) 2009 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.engine.aes_isa_engine;

import botan.constants;
static if (BOTAN_HAS_ENGINE_AES_ISA):

import botan.engine.engine;
import botan.utils.cpuid;
static if (BOTAN_HAS_AES_NI) import botan.block.aes_ni;

/**
* Engine for implementations that hook into CPU-specific
* AES implementations (eg AES-NI, VIA C7, or AMD Geode)
*/
final class AESISAEngine : Engine
{
public:
    string providerName() const { return "aes_isa"; }

    BlockCipher findBlockCipher(in SCANToken request,
                                AlgorithmFactory af) const
    {
        static if (BOTAN_HAS_AES_NI) {
            if (CPUID.hasAesNi())
            {
                if (request.algoName == "AES-128")
                    return new AES128NI;
                if (request.algoName == "AES-192")
                    return new AES192NI;
                if (request.algoName == "AES-256")
                    return new AES256NI;
            }
            else { logDebug("AES-NI not supported"); }
        }
        return null;
    }

    HashFunction findHash(in SCANToken request, AlgorithmFactory af) const
    { return null; }

    StreamCipher findStreamCipher(in SCANToken algo_spec, AlgorithmFactory af) const
    { return null; }
    
    MessageAuthenticationCode findMac(in SCANToken algo_spec, AlgorithmFactory af) const
    { return null; }
    
    PBKDF findPbkdf(in SCANToken algo_spec, AlgorithmFactory af) const
    { return null; }
    
    
    KeyedFilter getCipher(in string algo_spec, CipherDir dir, AlgorithmFactory af) const
    { return null; }
    
    static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

    ModularExponentiator modExp(const ref BigInt n, PowerMod.UsageHints hints) const
    { return null; }

    KeyAgreement getKeyAgreementOp(in PrivateKey key, RandomNumberGenerator rng) const
    { return null; }
    
    Signature getSignatureOp(in PrivateKey key, RandomNumberGenerator rng) const
    { return null; }
    
    Verification getVerifyOp(in PublicKey key, RandomNumberGenerator rng) const
    { return null; }
    
    Encryption getEncryptionOp(in PublicKey key, RandomNumberGenerator rng) const
    { return null; }
    
    Decryption getDecryptionOp(in PrivateKey key, RandomNumberGenerator rng) const
    { return null; }
}