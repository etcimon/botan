/**
* X.509 SIGNED Object
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.cert.x509.x509_obj;

import botan.constants;
static if (BOTAN_HAS_X509_CERTIFICATES):

import botan.asn1.asn1_obj;
import botan.filters.pipe;
import botan.rng.rng;
import botan.pubkey.x509_key;
import botan.pubkey.pubkey;
import botan.asn1.oids;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.utils.parsing;
import botan.codec.pem;
import std.algorithm;
import botan.utils.types;
import botan.utils.types;

/**
* This class represents abstract X.509 signed objects as
* in the X.500 SIGNED macro
*/
class X509Object : ASN1Object
{
public:
    /**
    * The underlying data that is to be or was signed
    * Returns: data that is or was signed
    */
    final const(Vector!ubyte) tbsData() const
    {
        return putInSequence(m_tbs_bits);
    }

    /**
    * Returns: signature on tbsData()
    */
    final ref const(Vector!ubyte) signature() const
    {
        return m_sig;
    }

    /**
    * Returns: signature algorithm that was used to generate signature
    */
    final const(AlgorithmIdentifier) signatureAlgorithm() const
    {
        return m_sig_algo;
    }

    /**
    * Returns: hash algorithm that was used to generate signature
    */
    final string hashUsedForSignature() const
    {
        Vector!string sig_info = botan.utils.parsing.splitter(OIDS.lookup(m_sig_algo.oid), '/');
        
        if (sig_info.length != 2)
            throw new InternalError("Invalid name format found for " ~ m_sig_algo.oid.toString());
        
        Vector!string pad_and_hash = parseAlgorithmName(sig_info[1]);
        
        if (pad_and_hash.length != 2)
            throw new InternalError("Invalid name format " ~ sig_info[1]);
        
        return pad_and_hash[1];
    }


    /**
    * Create a signed X509 object.
    *
    * Params:
    *  signer = the signer used to sign the object
    *  rng = the random number generator to use
    *  algo= the algorithm identifier of the signature scheme
    *  tbs_bits = the tbs bits to be signed
    * Returns: signed X509 object
    */
    static Vector!ubyte makeSigned(ALLOC)(ref PKSigner signer,
                                               RandomNumberGenerator rng,
                                              in AlgorithmIdentifier algo,
                                              auto const ref Vector!(ubyte, ALLOC) tbs_bits)
    {
        return DEREncoder()
                .startCons(ASN1Tag.SEQUENCE)
                .rawBytes(tbs_bits)
                .encode(algo)
                .encode(signer.signMessage(tbs_bits, rng), ASN1Tag.BIT_STRING)
                .endCons()
                .getContentsUnlocked();
    }

    /// ditto
    static Vector!ubyte makeSigned(ALLOC)(ref PKSigner signer,
                                          RandomNumberGenerator rng,
                                          in AlgorithmIdentifier algo,
                                          auto const ref RefCounted!(Vector!(ubyte, ALLOC), ALLOC) tbs_bits)
    {
        return makeSigned(signer, rng, algo, *tbs_bits);
    }


    /**
    * Check the signature on this data
    * Params:
    *  key = the public key purportedly used to sign this data
    * Returns: true if the signature is valid, otherwise false
    */
    final bool checkSignature(in PublicKey pub_key) const
    {
        assert(pub_key);
        try {
            Vector!string sig_info = botan.utils.parsing.splitter(OIDS.lookup(m_sig_algo.oid), '/');
            
            if (sig_info.length != 2 || sig_info[0] != pub_key.algoName)
                return false;
            
            string padding = sig_info[1];
            SignatureFormat format = (pub_key.messageParts() >= 2) ? DER_SEQUENCE : IEEE_1363;
            PKVerifier verifier = PKVerifier(pub_key, padding, format);
            auto tbs = tbsData();
            auto sig = signature().dup;
            return verifier.verifyMessage(tbs, sig);
        }
        catch(Exception e)
        {
            return false;
        }
    }

    override void encodeInto(ref DEREncoder to) const
    {
        to.startCons(ASN1Tag.SEQUENCE)
                .startCons(ASN1Tag.SEQUENCE)
                .rawBytes(m_tbs_bits)
                .endCons()
                .encode(m_sig_algo)
                .encode(m_sig, ASN1Tag.BIT_STRING)
                .endCons();
    }

    /*
    * Read a BER encoded X.509 object
    */
    override void decodeFrom(ref BERDecoder from)
    {
        //logTrace("decodeFrom X509Object");
        from.startCons(ASN1Tag.SEQUENCE)
                .startCons(ASN1Tag.SEQUENCE)
                .rawBytes(m_tbs_bits)
                .endCons()
                .decode(m_sig_algo)
                .decode(m_sig, ASN1Tag.BIT_STRING)
                .verifyEnd()
                .endCons();
    }


    /**
    * Returns: BER encoding of this
    */
    final Vector!ubyte BER_encode() const
    {
        auto der = DEREncoder.init;
        encodeInto(der);
        return der.getContentsUnlocked();
    }


    /**
    * Returns: PEM encoding of this
    */
    final string PEM_encode() const
    {
        return PEM.encode(BER_encode(), m_PEM_label_pref);
    }

    ~this() {}
protected:
    /*
    * Create a generic X.509 object
    */
    this(DataSource stream, in string labels)
    {
        init(stream, labels);
    }

    /*
    * Create a generic X.509 object
    */
    this(in string file, in string labels)
    {
        DataSource stream = cast(DataSource)DataSourceStream(file, true);
        init(stream, labels);
    }

    /*
    * Create a generic X.509 object
    */
    this(ALLOC)(auto const ref Vector!(ubyte, ALLOC) vec, in string labels)
    {
        auto stream = DataSourceMemory(vec.ptr, vec.length);
        init(cast(DataSource)stream, labels);
    }

    /*
    * Create a generic X.509 object
    */
    this(ALLOC)(auto const ref RefCounted!(Vector!(ubyte, ALLOC), ALLOC) vec, in string labels)
    {
        auto stream = DataSourceMemory(vec.ptr, vec.length);
        init(cast(DataSource)stream, labels);
    }

    /*
    * Try to decode the actual information
    */
    final void doDecode()
    {
        try {
            forceDecode();
        }
        catch(DecodingError e)
        {
            throw new DecodingError(m_PEM_label_pref ~ " decoding failed (" ~ e.msg ~ ")");
        }
        catch(InvalidArgument e)
        {
            throw new DecodingError(m_PEM_label_pref ~ " decoding failed (" ~ e.msg ~ ")");
        }
    }
    this() { }
    AlgorithmIdentifier m_sig_algo;
    Vector!ubyte m_tbs_bits, m_sig;

protected:
    abstract void forceDecode();

private:
    /*
    * Read a PEM or BER X.509 object
    */
    final void init(DataSource input, in string labels)
    {
        m_sig_algo = AlgorithmIdentifier();
        m_PEM_labels_allowed = botan.utils.parsing.splitter(labels, '/');
        if (m_PEM_labels_allowed.length < 1)
            throw new InvalidArgument("Bad labels argument to X509Object");
        
        //logTrace("Initialize PEM/BER X.509 Object");
        m_PEM_label_pref = m_PEM_labels_allowed[0];
        
        try {
            if (maybeBER(input) && !PEM.matches(input))
            {
                auto dec = BERDecoder(input);
                decodeFrom(dec);
            }
            else
            {
                string got_label;
                auto ber = DataSourceMemory(PEM.decode(input, got_label));
                if (m_PEM_labels_allowed[].canFind(got_label))
                    throw new DecodingError("Invalid PEM label: " ~ got_label);
                
                auto dec = BERDecoder(cast(DataSource)ber);
                decodeFrom(dec);
            }
        }
        catch(DecodingError e)
        {
            throw new DecodingError(m_PEM_label_pref ~ " decoding failed: " ~ e.msg);
        }
    }

    Vector!string m_PEM_labels_allowed;
    string m_PEM_label_pref;
}
