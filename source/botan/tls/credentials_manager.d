/**
* Credentials Manager
* 
* Copyright:
* (C) 2011,2012 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.credentials_manager;

import botan.constants;
static if (BOTAN_HAS_TLS):
import botan.cert.x509.x509cert;
import botan.cert.x509.certstor;
import botan.math.bigint.bigint;
import botan.pubkey.pk_keys;
import botan.algo_base.symkey;
import botan.tls.credentials_manager;
import botan.cert.x509.x509path;
import botan.utils.types;
import botan.pubkey.algo.ecdsa;

/**
* Interface for a credentials manager.
*
* A type is a fairly static value that represents the general nature
* of the transaction occuring. Currently used values are "tls-client"
* and "tls-server". Context represents a hostname, email address,
* username, or other identifier.
*/
abstract class TLSCredentialsManager
{
public:

    /**
    * Return a list of the certificates of CAs that we trust in this
    * type/context.
    *
    * Params:
    *  type = specifies the type of operation occuring
    *
    *  context = specifies a context relative to type. For instance
    *          for type "tls-client", context specifies the servers name.
    */
    abstract Vector!CertificateStore 
        trustedCertificateAuthorities(in string type, in string context)
    {
        return Vector!CertificateStore();
    }

    /**
    * Check the certificate chain is valid up to a trusted root, and
    * optionally (if hostname != "") that the hostname given is
    * consistent with the leaf certificate.
    *
    * This function should throw new an exception derived from
    * $(D Exception) with an informative what() result if the
    * certificate chain cannot be verified.

    * Params:
    *  type = specifies the type of operation occuring
    *  purported_hostname = specifies the purported hostname
    *  cert_chain = specifies a certificate chain leading to a
    *          trusted root CA certificate.
    */
    abstract void verifyCertificateChain(in string type,
                                         in string purported_hostname,
                                         const ref Vector!X509Certificate cert_chain)
    {
		if (cert_chain.empty)
            throw new InvalidArgument("Certificate chain was empty");
        
        auto trusted_CAs = trustedCertificateAuthorities(type, purported_hostname);
        
        PathValidationRestrictions restrictions;
        
        auto result = x509PathValidate(cert_chain,
                                       restrictions,
                                       trusted_CAs);
        
        if (!result.successfulValidation())
            throw new Exception("Certificate validation failure: " ~ result.resultString());
        
        if (!certInSomeStore(trusted_CAs, result.trustRoot()))
            throw new Exception("Certificate chain roots in unknown/untrusted CA");
        
        if (purported_hostname != "" && !cert_chain[0].matchesDnsName(purported_hostname))
            throw new Exception("Certificate did not match hostname");
    }

    /**
    * Return a cert chain we can use, ordered from leaf to root,
    * or else an empty vector.
    *
    * It is assumed that the caller can get the private key of the
    * leaf with privateKeyFor
    *
    * Params:
    *  cert_key_types = specifies the key types desired ("RSA",
    *                              "DSA", "ECDSA", etc), or empty if there
    *                              is no preference by the caller.
    *
    *  type = specifies the type of operation occuring
    *
    *  context = specifies a context relative to type.
    */
    abstract Vector!X509Certificate certChain(const ref Vector!string cert_key_types,
                                              in string type,
                                              in string context)
    {
        return Vector!X509Certificate();
    }

    /// ditto
    final Vector!X509Certificate certChain(T : string[])(auto ref T cert_key_types, in string type, in string context)
    {
        return certChain(Vector!string(cert_key_types), type, context);
    }

    /**
    * Return a cert chain we can use, ordered from leaf to root,
    * or else an empty vector.
    *
    * It is assumed that the caller can get the private key of the
    * leaf with privateKeyFor
    *
    * Params:
    *  cert_key_type = specifies the type of key requested
    *                             ("RSA", "DSA", "ECDSA", etc)
    *
    *  type = specifies the type of operation occuring
    *
    *  context = specifies a context relative to type.
    */
    abstract Vector!X509Certificate certChainSingleType(in string cert_key_type,
                                                        in string type,
                                                        in string context)
    {
        Vector!string cert_types;
        cert_types.pushBack(cert_key_type);
        return certChain(cert_types, type, context);
    }

    /**
    * 
    * Params: 
    *  cert = as returned by cert_chain
    *  type = specifies the type of operation occuring
    *  context = specifies a context relative to type.
    * 
    * Returns: private key associated with this certificate if we should
    *            use it with this context. 
    * 
    * Notes: this object should retain ownership of the returned key;
    *         it should not be deleted by the caller.
    */
    abstract PrivateKey privateKeyFor(in X509Certificate cert, in string type, in string context)
    {
        return null;
    }

    /**
    * Params:
    *  type = specifies the type of operation occuring
    *  context = specifies a context relative to type.
    * Returns: true if we should attempt SRP authentication
    */
    abstract bool attemptSrp(in string type, in string context)
    {
        return false;
    }

    /**
    * Params:
    *  type = specifies the type of operation occuring
    *  context = specifies a context relative to type.
    * Returns: identifier for client-side SRP auth, if available
                 for this type/context. Should return empty string
                 if password auth not desired/available.
    */
    abstract string srpIdentifier(in string type, in string context)
    {
        return "";
    }

    /**
    * Params:
    *  type = specifies the type of operation occuring
    *  context = specifies a context relative to type.
    *  identifier = specifies what identifier we want the
    *          password for. This will be a value previously returned
    *          by srp_identifier.
    * Returns: password for client-side SRP auth, if available
                 for this identifier/type/context.
    */
    abstract string srpPassword(in string type,
                                 in string context,
                                 in string identifier)
    {
        return "";
    }

    /**
    * Retrieve SRP verifier parameters
    */
    abstract bool srpVerifier(in string type,
                              in string context,
                              in string identifier,
                              ref string group_name,
                              ref BigInt verifier,
                              ref Vector!ubyte salt,
                              bool generate_fake_on_unknown)
    {
        return false;
    }

    /**
    * Params:
    *  type = specifies the type of operation occuring
    *  context = specifies a context relative to type.
    * Returns: the PSK identity hint for this type/context
    */
    abstract string pskIdentityHint(in string type, in string context)
    {
        return "";
    }

    /**
    * Params:
    *  type = specifies the type of operation occuring
    *  context = specifies a context relative to type.
    *  identity_hint = was passed by the server (but may be empty)
    * Returns: the PSK identity we want to use
    */
    abstract string pskIdentity(in string type, in string context, in string identity_hint)
    {
        return "";
    }

	/// Override and return true to signal PSK usage
	abstract bool hasPsk() {
		return false;
	}
        
    /// In TLSClient, identifies this machine with the server
    PrivateKey channelPrivateKey(string hostname)
    {
        import botan.rng.auto_rng;
        static ECDSAPrivateKey[string] pkey_saved;
        if (hostname !in pkey_saved) {
            auto rng = scoped!AutoSeededRNG();
            pkey_saved[hostname] = ECDSAPrivateKey(rng, ECGroup("secp256r1"));
        }
        return *pkey_saved[hostname];
    }

    /**
    * Params:
    *  type = specifies the type of operation occuring
    *  context = specifies a context relative to type.
    *  identity = is a PSK identity previously returned by
                psk_identity for the same type and context.
    * Returns: the PSK used for identity, or throw new an exception if no
    * key exists
    */
    abstract SymmetricKey psk(in string type, in string context, in string identity)
    {
        throw new InternalError("No PSK set for identity " ~ identity);
    }
}

bool certInSomeStore(const ref Vector!CertificateStore trusted_CAs, in X509Certificate trust_root)
{
    foreach (const ref CertificateStore CAs; trusted_CAs[])
        if (CAs.certificateKnown(trust_root))
            return true;
    return false;
}
