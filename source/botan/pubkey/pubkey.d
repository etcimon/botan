/**
* Public Key Interface
* 
* Copyright:
* (C) 1999-2010 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.pubkey;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

import botan.utils.types;
public import botan.pubkey.pk_keys;
public import botan.pubkey.pk_ops;
public import botan.algo_base.symkey;
public import botan.utils.types;
public import botan.rng.rng;
public import botan.pubkey.pkcs8;
public import botan.pubkey.algo.ec_group;
public import botan.pk_pad.emsa : EMSA;
import botan.pk_pad.eme;
import botan.pk_pad.emsa;
import botan.pk_pad.factory;
import botan.kdf.kdf;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.math.bigint.bigint;
import botan.utils.parsing;
import botan.libstate.libstate;
import botan.engine.engine;
import botan.utils.bit_ops;
import botan.utils.exceptn;
import botan.utils.mem_ops;

alias SignatureFormat = bool;
/**
* The two types of signature format supported by Botan.
*/
enum : SignatureFormat { IEEE_1363, DER_SEQUENCE }

alias FaultProtection = bool;
/**
* Enum marking if protection against fault attacks should be used
*/
enum : FaultProtection {
    ENABLE_FAULT_PROTECTION,
    DISABLE_FAULT_PROTECTION
}

/**
* Public Key Encryptor
*/
interface PKEncryptor
{
public:

    /**
    * Encrypt a message.
    *
    * Params:
    *  input = the message as a ubyte array
    *  length = the length of the above ubyte array
    *  rng = the random number source to use
    * Returns: encrypted message
    */
    final Vector!ubyte encrypt(const(ubyte)* input, size_t length, RandomNumberGenerator rng) const
    {
        return enc(input, length, rng);
    }

    /**
    * Encrypt a message.
    *
    * Params:
    *  input = the message
    * @param rng = the random number source to use
    * Returns: encrypted message
    */
    final Vector!ubyte encrypt(Alloc)(const ref Vector!( ubyte, Alloc ) input, RandomNumberGenerator rng) const
    {
        return enc(input.ptr, input.length, rng);
    }

    /**
    * Return the maximum allowed message size in bytes.
    * Returns: maximum message size in bytes
    */
    abstract size_t maximumInputSize() const;

protected:
    abstract Vector!ubyte enc(const(ubyte)*, size_t, RandomNumberGenerator) const;
}

/**
* Public Key Decryptor
*/
interface PKDecryptor
{
public:
    /**
    * Decrypt a ciphertext.
    *
    * Params:
    *  input = the ciphertext as a ubyte array
    *  length = the length of the above ubyte array
    * Returns: decrypted message
    */
    final SecureVector!ubyte decrypt(const(ubyte)* input, size_t length) const
    {
        return dec(input, length);
    }

    /**
    * Decrypt a ciphertext.
    *
    * Params:
    *  input = the ciphertext
    * Returns: decrypted message
    */
    final SecureVector!ubyte decrypt(Alloc)(auto const ref Vector!( ubyte, Alloc ) input) const
    {
        return dec(input.ptr, input.length);
    }

protected:
    abstract SecureVector!ubyte dec(const(ubyte)*, size_t) const;
}

/**
* Public Key Signer. Use the signMessage() functions for small
* messages. Use multiple calls update() to process large messages and
* generate the signature by finally calling signature().
*/
struct PKSigner
{
public:
    /**
    * Sign a message.
    *
    * Params:
    *  msg = the message to sign as a ubyte array
    *  length = the length of the above ubyte array
    *  rng = the rng to use
    * Returns: signature
    */
    Vector!ubyte signMessage(const(ubyte)* msg, size_t length, RandomNumberGenerator rng)
    {
        update(msg, length);
        return signature(rng);
    }

    /**
    * Sign a message.
    *
    * Params:
    *  input = the message to sign
    * @param rng = the rng to use
    * Returns: signature
    */
    Vector!ubyte signMessage(ALLOC)(auto const ref Vector!(ubyte, ALLOC) input, RandomNumberGenerator rng)
    { return signMessage(input.ptr, input.length, rng); }

    Vector!ubyte signMessage(ALLOC)(auto const ref RefCounted!(Vector!(ubyte, ALLOC), ALLOC) input, RandomNumberGenerator rng)
    { return signMessage(input.ptr, input.length, rng); }

    /**
    * Add a message part (single ubyte).
    *
    * Params:
    *  input = the ubyte to add
    */
    void update(ubyte input) { update(&input, 1); }

    /**
    * Add a message part.
    *
    * Params:
    *  input = the message part to add as a ubyte array
    *  length = the length of the above ubyte array
    */
    void update(const(ubyte)* input, size_t length)
    {
        m_emsa.update(input, length);
    }

    /**
    * Add a message part.
    *
    * Params:
    *  input = the message part to add
    */
    void update(ALLOC)(auto const ref RefCounted!(Vector!(ubyte, ALLOC), ALLOC) input) { update(input.ptr, input.length); }
    void update(ALLOC)(auto const ref Vector!(ubyte, ALLOC) input) { update(input.ptr, input.length); }

    /**
    * Get the signature of the so far processed message (provided by the
    * calls to update()).
    *
    * Params:
    *  rng = the rng to use
    * Returns: signature of the total message
    */
    Vector!ubyte signature(RandomNumberGenerator rng)
    {
        Vector!ubyte encoded = unlock(m_emsa.encodingOf(m_emsa.rawData(), m_op.maxInputBits(), rng));
        Vector!ubyte plain_sig = unlock(m_op.sign(encoded.ptr, encoded.length, rng));
        
        assert(selfTestSignature(encoded, plain_sig), "Signature was consistent");
        
        if (m_op.messageParts() == 1 || m_sig_format == IEEE_1363)
            return plain_sig.move();
        
        if (m_sig_format == DER_SEQUENCE)
        {
            if (plain_sig.length % m_op.messageParts())
                throw new EncodingError("PKSigner: strange signature size found");
            const size_t SIZE_OF_PART = plain_sig.length / m_op.messageParts();

            Vector!(RefCounted!BigInt) sig_parts = Vector!(RefCounted!BigInt)(m_op.messageParts());
            for (size_t j = 0; j != sig_parts.length; ++j)
                sig_parts[j].binaryDecode(&plain_sig[SIZE_OF_PART*j], SIZE_OF_PART);
            
            return DEREncoder()
                    .startCons(ASN1Tag.SEQUENCE)
                    .encodeList(sig_parts)
                    .endCons()
                    .getContentsUnlocked();
        }
        else
            throw new EncodingError("PKSigner: Unknown signature format " ~ to!string(m_sig_format));
    }

    /**
    * Set the output format of the signature.
    *
    * Params:
    *  format = the signature format to use
    */
    void setOutputFormat(SignatureFormat format) { m_sig_format = format; }

    /**
    * Construct a PK Signer.
    *
    * Params:
    *  key = the key to use inside this signer
    *  emsa_name = the EMSA to use, e.g. "EMSA1(SHA-224)".
    *  format = the signature format to use
    *  prot = says if fault protection should be enabled
    */
    this(in PrivateKey key, in string emsa_name,
         SignatureFormat format = IEEE_1363,
         FaultProtection prot = ENABLE_FAULT_PROTECTION)
    {
        AlgorithmFactory af = globalState().algorithmFactory();

        RandomNumberGenerator rng = globalState().globalRng();
        
        m_op = null;
        m_verify_op = null;

        foreach (Engine engine; af.engines[]) {
            if (!m_op)
                m_op = engine.getSignatureOp(key, rng);
            if (!m_verify_op && prot == ENABLE_FAULT_PROTECTION)
                m_verify_op = engine.getVerifyOp(key, rng);
            if (m_op && (m_verify_op || prot == DISABLE_FAULT_PROTECTION))
                break;
        }
        
        
        if (!m_op || (!m_verify_op && prot == ENABLE_FAULT_PROTECTION))
            throw new LookupError("Signing with " ~ key.algoName ~ " not supported");
        
        m_emsa = getEmsa(emsa_name);
        m_sig_format = format;
        assert(*m_op !is null && *m_verify_op !is null && *m_emsa !is null);
    }
private:
    /*
    * Check the signature we just created, to help prevent fault attacks
    */
    bool selfTestSignature()(auto const ref Vector!ubyte msg, auto const ref Vector!ubyte sig) const
    {
        if (!m_verify_op)
            return true; // checking disabled, assume ok
        
        if (m_verify_op.withRecovery())
        {
            Vector!ubyte recovered = unlock((cast(Verification)*m_verify_op).verifyMr(sig.ptr, sig.length));
            
            if (msg.length > recovered.length)
            {
                size_t extra_0s = msg.length - recovered.length;
                
                foreach (size_t i; 0 .. extra_0s)
                    if (msg[i] != 0)
                        return false;
                
                return sameMem(&msg[extra_0s], recovered.ptr, recovered.length);
            }
            
            return (recovered == msg);
        }
        else
            return (cast(Verification)*m_verify_op).verify(msg.ptr, msg.length, sig.ptr, sig.length);
    }

    Unique!Signature m_op;
    Unique!Verification m_verify_op;
    Unique!EMSA m_emsa;
    SignatureFormat m_sig_format;
}

/**
* Public Key Verifier. Use the verifyMessage() functions for small
* messages. Use multiple calls update() to process large messages and
* verify the signature by finally calling checkSignature().
*/
struct PKVerifier
{
public:
    /**
    * Verify a signature.
    *
    * Params:
    *  msg = the message that the signature belongs to, as a ubyte array
    *  msg_length = the length of the above ubyte array msg
    *  sig = the signature as a ubyte array
    *  sig_length = the length of the above ubyte array sig
    * Returns: true if the signature is valid
    */
    bool verifyMessage(const(ubyte)* msg, size_t msg_length,
                       const(ubyte)* sig, size_t sig_length)
    {
        update(msg, msg_length);
        //logTrace("Done update");
        return checkSignature(sig, sig_length);
    }

    /**
    * Verify a signature.
    *
    * Params:
    *  msg = the message that the signature belongs to
    *  sig = the signature
    * Returns: true if the signature is valid
    */
    bool verifyMessage(Alloc, Alloc2)(auto const ref Vector!( ubyte, Alloc ) msg, 
                                      auto const ref Vector!( ubyte, Alloc2 ) sig)
    {
        return verifyMessage(msg.ptr, msg.length, sig.ptr, sig.length);
    }

    /// ditto
    bool verifyMessage(Alloc, Alloc2)(auto const ref RefCounted!(Vector!( ubyte, Alloc ), Alloc) msg, 
                                      auto const ref RefCounted!(Vector!( ubyte, Alloc2 ), Alloc2) sig)
    {
        return verifyMessage(msg.ptr, msg.length, sig.ptr, sig.length);
    }

    /**
    * Add a message part (single ubyte) of the message corresponding to the
    * signature to be verified.
    *
    * Params:
    *  input = the ubyte to add
    */
    void update(ubyte input) { update(&input, 1); }

    /**
    * Add a message part of the message corresponding to the
    * signature to be verified.
    *
    * Params:
    *  msg_part = the new message part as a ubyte array
    *  length = the length of the above ubyte array
    */
    void update(const(ubyte)* input, size_t length)
    {
        m_emsa.update(input, length);
    }

    /**
    * Add a message part of the message corresponding to the
    * signature to be verified.
    *
    * Params:
    *  input = the new message part
    */
    void update(const ref Vector!ubyte input)
    { update(input.ptr, input.length); }

    /**
    * Check the signature of the buffered message, i.e. the one build
    * by successive calls to update.
    *
    * Params:
    *  sig = the signature to be verified as a ubyte array
    *  length = the length of the above ubyte array
    * Returns: true if the signature is valid, false otherwise
    */
    bool checkSignature(const(ubyte)* sig, size_t length)
    {
        try {
            if (m_sig_format == IEEE_1363)
                return validateSignature(m_emsa.rawData(), sig, length);
            else if (m_sig_format == DER_SEQUENCE)
            {
                BERDecoder decoder = BERDecoder(sig, length);
                BERDecoder ber_sig = decoder.startCons(ASN1Tag.SEQUENCE);
                
                size_t count = 0;
                SecureVector!ubyte real_sig;
                while (ber_sig.moreItems())
                {
                    BigInt sig_part;
                    ber_sig.decode(sig_part);
                    real_sig ~= BigInt.encode1363(sig_part, m_op.messagePartSize());
                    ++count;
                }
                
                if (count != m_op.messageParts())
                    throw new DecodingError("PKVerifier: signature size invalid");
                
                return validateSignature(m_emsa.rawData(), real_sig.ptr, real_sig.length);
            }
            else
                throw new DecodingError("PKVerifier: Unknown signature format " ~ to!string(m_sig_format));
        }
        catch(InvalidArgument) { return false; }
    }

    /**
    * Check the signature of the buffered message, i.e. the one build
    * by successive calls to update.
    *
    * Params:
    *  sig = the signature to be verified
    * Returns: true if the signature is valid, false otherwise
    */
    bool checkSignature(Alloc)(auto const ref Vector!( ubyte, Alloc ) sig)
    {
        return checkSignature(sig.ptr, sig.length);
    }

    /**
    * Set the format of the signatures fed to this verifier.
    *
    * Params:
    *  format = the signature format to use
    */
    void setInputFormat(SignatureFormat format)
    {
        if (m_op.messageParts() == 1 && format != IEEE_1363)
            throw new InvalidState("PKVerifier: This algorithm always uses IEEE 1363");
        m_sig_format = format;
    }

    /**
    * Construct a PK Verifier.
    *
    * Params:
    *  pub_key = the public key to verify against
    *  emsa_name = the EMSA to use (eg "EMSA3(SHA-1)")
    *  format = the signature format to use
    */
    this(in PublicKey key, in string emsa_name, SignatureFormat format = IEEE_1363)
    {
        AlgorithmFactory af = globalState().algorithmFactory();
        RandomNumberGenerator rng = globalState().globalRng();

        foreach (Engine engine; af.engines[]) {
            m_op = engine.getVerifyOp(key, rng);
            if (m_op)
                break;
        }
        
        if (!m_op)
            throw new LookupError("Verification with " ~ key.algoName ~ " not supported");
        m_emsa = getEmsa(emsa_name);
        m_sig_format = format;
    }

private:
    bool validateSignature()(auto const ref SecureVector!ubyte msg, const(ubyte)* sig, size_t sig_len)
    {
        if (m_op.withRecovery())
        {
            SecureVector!ubyte output_of_key = m_op.verifyMr(sig, sig_len);
            return m_emsa.verify(output_of_key, msg, m_op.maxInputBits());
        }
        else
        {
            RandomNumberGenerator rng = globalState().globalRng();
            
            SecureVector!ubyte encoded = m_emsa.encodingOf(msg, m_op.maxInputBits(), rng);
            
            return m_op.verify(encoded.ptr, encoded.length, sig, sig_len);
        }
    }

    Unique!Verification m_op;
    Unique!EMSA m_emsa;
    SignatureFormat m_sig_format;
}

/**
* Key used for key agreement
*/
class PKKeyAgreement
{
public:

    /*
    * Perform Key Agreement Operation
    * Params:
    *  key_len = the desired key output size
    *  input = the other parties key
    *  in_len = the length of in in bytes
    *  params = extra derivation params
    *  params_len = the length of params in bytes
    */
    SymmetricKey deriveKey(size_t key_len, const(ubyte)* input,
                           size_t in_len, const(ubyte)* params,
                           size_t params_len) const
    {
        SecureVector!ubyte z = (cast(KeyAgreement)*m_op).agree(input, in_len);

        if (!m_kdf)
            return SymmetricKey(z);
        
        return SymmetricKey(m_kdf.deriveKey(key_len, z, params, params_len));
    }

    /*
    * Perform Key Agreement Operation
    * Params:
    *  key_len = the desired key output size
    *  input = the other parties key
    *  in_len = the length of in in bytes
    *  params = extra derivation params
    *  params_len = the length of params in bytes
    */
    SymmetricKey deriveKey()(size_t key_len, auto const ref Vector!ubyte input, 
                             const(ubyte)* params, size_t params_len) const
    {
        return deriveKey(key_len, input.ptr, input.length, params, params_len);
    }

    /*
    * Perform Key Agreement Operation
    * Params:
    *  key_len = the desired key output size
    *  input = the other parties key
    *  in_len = the length of in in bytes
    *  params = extra derivation params
    */
    SymmetricKey deriveKey(size_t key_len, const(ubyte)* input, size_t in_len, in string params = "") const
    {
        return deriveKey(key_len, input, in_len, cast(const(ubyte)*)(params.ptr), params.length);
    }

    /*
    * Perform Key Agreement Operation
    * Params:
    *  key_len = the desired key output size
    *  input = the other parties key
    *  params = extra derivation params
    */
    SymmetricKey deriveKey()(size_t key_len,
                             auto const ref Vector!ubyte input,
                             in string params = "") const
    {
        return deriveKey(key_len, input.ptr, input.length,
                                cast(const(ubyte)*)(params.ptr),
                                params.length);
    }

    /**
    * Construct a PK Key Agreement.
    *
    * Params:
    *  key = the key to use
    *  kdf_name = name of the KDF to use (or 'Raw' for no KDF)
    */
    this(in PKKeyAgreementKey key, in string kdf_name)
    {
        AlgorithmFactory af = globalState().algorithmFactory();
        RandomNumberGenerator rng = globalState().globalRng();

        foreach (Engine engine; af.engines[])
        {
            m_op = engine.getKeyAgreementOp(key, rng);
            if (m_op)
                break;
        }
        
        if (!m_op)
            throw new LookupError("Key agreement with " ~ key.algoName ~ " not supported");
        
        m_kdf = getKdf(kdf_name);
    }
private:
    Unique!KeyAgreement m_op;
    Unique!KDF m_kdf;
}

/**
* Encryption with an MR algorithm and an EME.
*/
class PKEncryptorEME : PKEncryptor
{
public:
    /*
    * Return the max size, in bytes, of a message
    */
    override size_t maximumInputSize() const
    {
        if (!m_eme)
            return (m_op.maxInputBits() / 8);
        else
            return m_eme.maximumInputSize(m_op.maxInputBits());
    }

    /**
    * Construct an instance.
    *
    * Params:
    *  key = the key to use inside the decryptor
    *  eme_name = the EME to use
    */
    this(in PublicKey key, in string eme_name)
    {
        
        AlgorithmFactory af = globalState().algorithmFactory();
        RandomNumberGenerator rng = globalState().globalRng();

        foreach (Engine engine; af.engines[]) {
            m_op = engine.getEncryptionOp(key, rng);
            if (m_op)
                break;
        }
        
        if (!m_op)
            throw new LookupError("Encryption with " ~ key.algoName ~ " not supported");
        
        m_eme = getEme(eme_name);
    }

protected:
    override Vector!ubyte enc(const(ubyte)* input, size_t length, RandomNumberGenerator rng) const
    {
        if (m_eme)
        {
            SecureVector!ubyte encoded = m_eme.encode(input, length, m_op.maxInputBits(), rng);
            
            if (8*(encoded.length - 1) + highBit(encoded[0]) > m_op.maxInputBits())
                throw new InvalidArgument("PKEncryptorEME: Input is too large");
            
            return unlock((cast(Encryption)*m_op).encrypt(encoded.ptr, encoded.length, rng));
        }
        else
        {
            if (8*(length - 1) + highBit(input[0]) > m_op.maxInputBits())
                throw new InvalidArgument("PKEncryptorEME: Input is too large");
            
            return unlock((cast(Encryption)*m_op).encrypt(input, length, rng));
        }
    }

private:
    Unique!Encryption m_op;
    Unique!EME m_eme;
}

/**
* Decryption with an MR algorithm and an EME.
*/
class PKDecryptorEME : PKDecryptor
{
public:
  /**
    * Construct an instance.
    *
    * Params:
    *  key = the key to use inside the encryptor
    *  eme_name = the EME to use
    */
    this(in PrivateKey key, in string eme_name)
    {
        AlgorithmFactory af = globalState().algorithmFactory();
        RandomNumberGenerator rng = globalState().globalRng();

        foreach (Engine engine; af.engines[])
        {
            m_op = engine.getDecryptionOp(key, rng);
            if (m_op)
                break;
        }
        
        if (!m_op)
            throw new LookupError("Decryption with " ~ key.algoName ~ " not supported");
        
        m_eme = getEme(eme_name);
    }

protected:
    /*
    * Decrypt a message
    */
    override SecureVector!ubyte dec(const(ubyte)* msg, size_t length) const
    {
        try {
            SecureVector!ubyte decrypted = (cast(Decryption)*m_op).decrypt(msg, length);
            if (m_eme)
                return m_eme.decode(decrypted, m_op.maxInputBits());
            else
                return decrypted.move();
        }
        catch(InvalidArgument)
        {
            throw new DecodingError("PKDecryptorEME: Input is invalid");
        }
    }
   
private:
    Unique!Decryption m_op;
    Unique!EME m_eme;
}