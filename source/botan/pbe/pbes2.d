/**
* PKCS #5 v2.0 PBE
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pbe.pbes2;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO && BOTAN_HAS_PBE_PKCS_V20):

import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.asn1.alg_id;
import botan.asn1.oids;
import botan.pbe.pbe;
import botan.block.block_cipher;
import botan.mac.mac;
import botan.filters.pipe;
import botan.pbkdf.pbkdf2;
import botan.algo_factory.algo_factory;
import botan.libstate.libstate;
import botan.libstate.lookup;
import botan.utils.parsing;
import botan.utils.types;
import std.datetime;
import std.algorithm;
import std.array : split;

/**
* PKCS #5 v2.0 PBE
*/
final class PBEPKCS5v20 : PBE, Filterable
{
public:
    /*
    * Return an OID for PBES2
    */
    override OID getOid() const
    {
        return OIDS.lookup("PBE-PKCS5v20");
    }

    /*
    * Encode PKCS#5 PBES2 parameters
    */
    override Vector!ubyte encodeParams() const
    {
        return DEREncoder()
                   .startCons(ASN1Tag.SEQUENCE)
                   .encode(AlgorithmIdentifier("PKCS5.PBKDF2",
                        DEREncoder()
                               .startCons(ASN1Tag.SEQUENCE)
                               .encode(m_salt, ASN1Tag.OCTET_STRING)
                               .encode(m_iterations)
                               .encode(m_key_length)
                               .encodeIf (m_prf.name != "HMAC(SHA-160)",
                                          AlgorithmIdentifier(m_prf.name,
                                                              AlgorithmIdentifierImpl.USE_NULL_PARAM))
                               .endCons()
                               .getContentsUnlocked()
                         )
                 )
                .encode(
                    AlgorithmIdentifier(m_block_cipher.name ~ "/CBC",
                                        DEREncoder().encode(m_iv, ASN1Tag.OCTET_STRING).getContentsUnlocked())
                 )
                .endCons()
                .getContentsUnlocked();
    }

    override @property string name() const
    {
        return "PBE-PKCS5v20(" ~ m_block_cipher.name ~ "," ~ m_prf.name ~ ")";
    }

    /*
    * Encrypt some bytes using PBES2
    */
    override void write(const(ubyte)* input, size_t length)
    {
        //logTrace("write to pipe with: ", name());
        m_pipe.write(input, length);
        flushPipe(true);
    }

    /*
    * Start encrypting with PBES2
    */
    override void startMsg()
    {
        //logTrace("Append to: ", m_block_cipher.name);
        m_pipe.append(getCipher(m_block_cipher.name ~ "/CBC/PKCS7", SymmetricKey(m_key), InitializationVector(m_iv), cast(CipherDir)m_direction));
        
        m_pipe.startMsg();
        if (m_pipe.messageCount() > 1)
            m_pipe.setDefaultMsg(m_pipe.defaultMsg() + 1);
    }

    /*
    * Finish encrypting with PBES2
    */
    override void endMsg()
    {
        m_pipe.endMsg();
        flushPipe(false);
        m_pipe.reset();
    }

    /**
    * Load a PKCS #5 v2.0 encrypted stream
    * Params:
    *  params = the PBES2 parameters
    *  passphrase = the passphrase to use for decryption
    */
    this(const ref Vector!ubyte params, in string passphrase) 
    {
        m_direction = DECRYPTION;
        AlgorithmIdentifier kdf_algo, enc_algo;
        
        BERDecoder(params)
                .startCons(ASN1Tag.SEQUENCE)
                .decode(kdf_algo)
                .decode(enc_algo)
                .verifyEnd()
                .endCons();
        //logTrace("KDF: ", OIDS.lookup(kdf_algo.oid));
        //logTrace("ENC: ", OIDS.lookup(enc_algo.oid));
        //logTrace("pass: ", passphrase);
        auto prf_algo = AlgorithmIdentifier();
        
        if (kdf_algo.oid != OIDS.lookup("PKCS5.PBKDF2"))
            throw new DecodingError("PBE-PKCS5 v2.0: Unknown KDF algorithm " ~ kdf_algo.oid.toString());
        
        BERDecoder(kdf_algo.parameters)
                .startCons(ASN1Tag.SEQUENCE)
                .decode(m_salt, ASN1Tag.OCTET_STRING)
                .decode(m_iterations)
                .decodeOptional(m_key_length, ASN1Tag.INTEGER, ASN1Tag.UNIVERSAL)
                .decodeOptional(prf_algo, ASN1Tag.SEQUENCE, ASN1Tag.CONSTRUCTED,
                                 AlgorithmIdentifier("HMAC(SHA-160)", AlgorithmIdentifierImpl.USE_NULL_PARAM))
                .verifyEnd()
                .endCons();
        
        AlgorithmFactory af = globalState().algorithmFactory();
        
        string cipher = OIDS.lookup(enc_algo.oid);
        Vector!string cipher_spec = botan.utils.parsing.splitter(cipher, '/');
        if (cipher_spec.length != 2)
            throw new DecodingError("PBE-PKCS5 v2.0: Invalid cipher spec " ~ cipher);
        
        if (cipher_spec[1] != "CBC")
            throw new DecodingError("PBE-PKCS5 v2.0: Don't know param format for " ~ cipher);

        //logTrace("m_iv len 1: ", m_iv.length);
        BERDecoder(enc_algo.parameters).decode(m_iv, ASN1Tag.OCTET_STRING).verifyEnd();

        //logTrace("m_iv len 2: ", m_iv.length);
        
        m_block_cipher = af.makeBlockCipher(cipher_spec[0]);
        //logTrace("PRF: ", prf_algo.toString(), " => ", OIDS.lookup(prf_algo.oid));
        m_prf = af.makeMac(OIDS.lookup(prf_algo.oid));
        
        if (m_key_length == 0)
            m_key_length = m_block_cipher.maximumKeylength();
        
        if (m_salt.length < 8)
            throw new DecodingError("PBE-PKCS5 v2.0: Encoded salt is too small");
        
        // TODO: study broader use of scoped
        Unique!PKCS5_PBKDF2 pbkdf = new PKCS5_PBKDF2(m_prf.clone());
        
        m_key = pbkdf.deriveKey(m_key_length, passphrase,
                                m_salt.ptr, m_salt.length,
                                m_iterations).bitsOf();
    }

    /**
    * Params:
    *  cipher = the block cipher to use
    *  mac = the MAC to use
    *  passphrase = the passphrase to use for encryption
    *  msec = how many milliseconds to run the PBKDF
    *  rng = a random number generator
    */
    this(BlockCipher cipher,
         MessageAuthenticationCode mac,
         in string passphrase,
         Duration msec,
         RandomNumberGenerator rng) 
    {
        m_direction = ENCRYPTION;
        m_block_cipher = cipher;
        m_prf = mac;
        m_salt = rng.randomVec(12);
        m_iv = rng.randomVec(m_block_cipher.blockSize());
        m_iterations = 0;
        m_key_length = m_block_cipher.maximumKeylength();
        auto pbkdf = scoped!PKCS5_PBKDF2(m_prf.clone());
        
        m_key = pbkdf.deriveKey(m_key_length, passphrase,
                                m_salt.ptr, m_salt.length,
                                msec, m_iterations).bitsOf();
    }

    // Interface fallthrough
    override bool attachable() { return super.attachable(); }
    override void setNext(Filter* filters, size_t size) {
        super.setNext(filters, size);
    }
private:
    /*
    * Flush the pipe
    */
    void flushPipe(bool safe_to_skip)
    {
        if (safe_to_skip && m_pipe.remaining() < 64)
            return;
        
        SecureVector!ubyte buffer = SecureVector!ubyte(DEFAULT_BUFFERSIZE);
        while (m_pipe.remaining())
        {
            const size_t got = m_pipe.read(buffer.ptr, buffer.length);
            send(buffer, got);
        }
    }

    CipherDir m_direction;
    Unique!BlockCipher m_block_cipher;
    Unique!MessageAuthenticationCode m_prf;
    SecureVector!ubyte m_salt, m_key, m_iv;
    size_t m_iterations, m_key_length;
    Pipe m_pipe;
}