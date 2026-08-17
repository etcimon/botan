/**
* PKCS#12 / PFX
*
* Copyright:
* (C) 2026 Damiano Mazzella
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.constructs.pkcs12;

import botan.constants;
static if (BOTAN_HAS_PKCS12):

import botan.asn1.alg_id;
import botan.asn1.asn1_obj;
import botan.asn1.asn1_oid;
import botan.asn1.asn1_str;
import botan.asn1.ber_dec;
import botan.asn1.der_enc;
import botan.asn1.oids;
import botan.cert.x509.x509cert;
import botan.constructs.pkcs12_pbe;
import botan.filters.data_src;
import botan.hash.hash;
import botan.pbkdf.pbkdf;
import botan.libstate.lookup;
import botan.mac.mac;
import botan.pbkdf.pkcs12_kdf;
import botan.pubkey.pk_keys;
import botan.pubkey.pkcs8;
import botan.pubkey.x509_key;
import botan.rng.auto_rng;
import botan.utils.charset;
import botan.utils.ct;
import botan.utils.exceptn;
import botan.utils.types;
import botan.utils.mem_ops;

enum size_t PKCS12_MAX_NESTING = 10;

/**
* Options controlling PKCS#12/PFX export.
*
* Use the static helpers for the common cases:
*  - modern        — PBES2-SHA256-AES256, SHA-256 MAC, 100 000 iterations
*  - legacyCompat  — PBE-SHA1-3DES, SHA-1 MAC, 2 048 iterations
*/
struct PKCS12ExportOptions
{
    this(string password, string friendly_name = null)
    {
        m_password = password;
        if (friendly_name !is null)
        {
            m_has_fn = true;
            m_fn = friendly_name;
        }
    }

    static PKCS12ExportOptions modern(string password, string friendly_name = null)
    {
        return PKCS12ExportOptions(password, friendly_name);
    }

    static PKCS12ExportOptions legacyCompat(string password, string friendly_name = null)
    {
        auto opts = PKCS12ExportOptions(password, friendly_name);
        opts.m_iterations = 2048;
        opts.m_key_enc = "PBE-SHA1-3DES";
        opts.m_mac_digest = "SHA-1";
        return opts;
    }

    ref PKCS12ExportOptions withFriendlyName(string name) return
    {
        m_has_fn = true;
        m_fn = name;
        return this;
    }

    ref PKCS12ExportOptions withIterations(size_t n) return
    {
        m_iterations = n;
        return this;
    }

    ref PKCS12ExportOptions withKeyEncryptionAlgo(string algo) return
    {
        m_key_enc = algo;
        return this;
    }

    ref PKCS12ExportOptions withCertEncryptionAlgo(string algo) return
    {
        m_cert_enc = algo;
        return this;
    }

    ref PKCS12ExportOptions withMacDigest(string algo) return
    {
        m_mac_digest = algo;
        return this;
    }

    ref PKCS12ExportOptions withoutMac() return
    {
        m_include_mac = false;
        return this;
    }

    string password() const { return m_password; }
    bool hasFriendlyName() const { return m_has_fn; }
    string friendlyName() const { return m_fn; }
    size_t iterations() const { return m_iterations; }
    string keyEncryptionAlgo() const { return m_key_enc; }
    string certEncryptionAlgo() const { return m_cert_enc; }
    string macDigest() const { return m_mac_digest; }
    bool includeMac() const { return m_include_mac; }

private:
    string m_password;
    bool m_has_fn;
    string m_fn;
    size_t m_iterations = 100_000;
    string m_key_enc = "PBES2-SHA256-AES256";
    string m_cert_enc;
    string m_mac_digest = "SHA-256";
    bool m_include_mac = true;
}

private string canonicalMacHash(string name)
{
    if (name == "SHA-1" || name == "SHA-160")
        return "SHA-160";
    return name;
}

private bool isSupportedPbeAlgo(string algo)
{
    if (algo == "PBE-SHA1-3DES" || algo == "PBE-SHA1-2DES")
        return true;
    static if (BOTAN_HAS_PBE_PKCS_V20)
    {
        if (algo == "PBES2-SHA256-AES256" || algo == "PBES2-SHA256-AES128")
            return true;
    }
    return false;
}

private void validateExportOptions()(const auto ref PKCS12ExportOptions opts)
{
    if (opts.iterations() == 0 || opts.iterations() > PKCS12_MAX_ITERATIONS)
        throw new InvalidArgument("PKCS#12: iteration count must be between 1 and 100000000");
    if (!isSupportedPbeAlgo(opts.keyEncryptionAlgo()))
        throw new InvalidArgument("PKCS#12: unsupported key encryption algorithm '"
                                  ~ opts.keyEncryptionAlgo() ~ "'");
    if (opts.certEncryptionAlgo().length && !isSupportedPbeAlgo(opts.certEncryptionAlgo()))
        throw new InvalidArgument("PKCS#12: unsupported cert encryption algorithm '"
                                  ~ opts.certEncryptionAlgo() ~ "'");
    if (opts.includeMac())
    {
        const string hash_name = canonicalMacHash(opts.macDigest());
        if (hash_name != "SHA-160" && hash_name != "SHA-224" && hash_name != "SHA-256"
            && hash_name != "SHA-384" && hash_name != "SHA-512" && hash_name != "SHA-512-256")
            throw new InvalidArgument("PKCS#12: unsupported MAC digest '" ~ opts.macDigest() ~ "'");
        retrieveHash(hash_name);
    }
}

private void encodeBmpstring(ref DEREncoder enc, string str)
{
    auto utf16be = utf8ToUcs2(cast(const(ubyte)[]) str);
    enc.addObject(ASN1Tag.BMP_STRING, ASN1Tag.UNIVERSAL, utf16be);
}

private void writeBagAttributes(ref DEREncoder enc, bool has_fn, string friendly_name,
                                const ref Vector!ubyte local_key_id)
{
    const bool write_fn = has_fn && friendly_name.length != 0;
    const bool write_id = local_key_id.length != 0;
    if (!write_fn && !write_id)
        return;
    const OID fn_oid = OIDS.lookup("PKCS9.FriendlyName");
    const OID lki_oid = OIDS.lookup("PKCS9.LocalKeyId");
    enc.startCons(ASN1Tag.SET);
    if (write_fn)
    {
        enc.startCons(ASN1Tag.SEQUENCE);
        enc.encode(fn_oid);
        enc.startCons(ASN1Tag.SET);
        encodeBmpstring(enc, friendly_name);
        enc.endCons();
        enc.endCons();
    }
    if (write_id)
    {
        enc.startCons(ASN1Tag.SEQUENCE);
        enc.encode(lki_oid);
        enc.startCons(ASN1Tag.SET);
        enc.encode(local_key_id, ASN1Tag.OCTET_STRING);
        enc.endCons();
        enc.endCons();
    }
    enc.endCons();
}

private Vector!ubyte sha1Of(const(ubyte)* data, size_t len)
{
    Unique!HashFunction sha1 = retrieveHash("SHA-160").clone();
    sha1.update(data, len);
    auto dig = sha1.finished();
    return Vector!ubyte(dig[]);
}

private struct ParsedCert
{
    X509Certificate cert;
    ubyte[] local_key_id;
    string friendly_name;
}

private struct ParsedKey
{
    PrivateKey key;
    ubyte[] local_key_id;
    string friendly_name;
}

private string resolveMacHash(OID oid)
{
    const string name = OIDS.lookup(oid);
    if (name == "SHA-160" || name == "SHA-1")
        return "SHA-160";
    if (name == "SHA-224" || name == "SHA-256" || name == "SHA-384"
        || name == "SHA-512" || name == "SHA-512-256")
        return name;
    throw new DecodingError("Unsupported PKCS#12 MAC digest: " ~ oid.toString());
}

private void verifyMac(const(ubyte)* auth_safe, size_t auth_len,
                       const ref Vector!ubyte mac_value,
                       const ref Vector!ubyte mac_salt,
                       size_t iterations, in string hash_name,
                       in string password, bool openssl_empty)
{
    Unique!MessageAuthenticationCode hmac = retrieveMac("HMAC(" ~ hash_name ~ ")").clone();
    const size_t mac_key_len = hmac.outputLength;
    auto mac_key = SecureVector!ubyte(mac_key_len);
    Unique!HashFunction hash = retrieveHash(hash_name).clone();
    if (openssl_empty && password.length == 0)
        pkcs12Kdf(mac_key.ptr, mac_key_len, null, 0, mac_salt.ptr, mac_salt.length,
                  iterations, 3, *hash);
    else
    {
        Unique!PBKDF kdf = getPbkdf("PKCS12-KDF(" ~ hash_name ~ ",3)");
        auto k = kdf.deriveKey(mac_key_len, password, mac_salt.ptr, mac_salt.length, iterations);
        mac_key[] = k.bitsOf()[];
    }
    hmac.setKey(mac_key.ptr, mac_key.length);
    hmac.update(auth_safe, auth_len);
    auto got = hmac.finished();
    if (got.length != mac_value.length || !constantTimeCompare(got.ptr, mac_value.ptr, got.length))
        throw new InvalidAuthenticationTag("PKCS#12 MAC verification failed");
}

private void parseBagAttributes(ref BERDecoder decoder, ref string friendly_name, ref ubyte[] local_key_id)
{
    if (!decoder.moreItems())
        return;
    const OID fn_oid = OIDS.lookup("PKCS9.FriendlyName");
    const OID lki_oid = OIDS.lookup("PKCS9.LocalKeyId");
    BERDecoder attrs = decoder.startCons(ASN1Tag.SET);
    while (attrs.moreItems())
    {
        OID attr_oid;
        BERDecoder attr_seq = attrs.startCons(ASN1Tag.SEQUENCE);
        attr_seq.decode(attr_oid);
        BERDecoder values = attr_seq.startCons(ASN1Tag.SET);
        if (attr_oid == fn_oid)
        {
            BERObject obj = values.getNextObject();
            if (obj.type_tag == ASN1Tag.BMP_STRING)
            {
                auto u8 = ucs2ToUtf8(obj.value[]);
                friendly_name = cast(string) u8[].idup;
            }
            else if (obj.type_tag == ASN1Tag.UTF8_STRING)
                friendly_name = cast(string) obj.value[].idup;
            else
                friendly_name = obj.toString();
        }
        else if (attr_oid == lki_oid)
        {
            Vector!ubyte tmp;
            values.decode(tmp, ASN1Tag.OCTET_STRING);
            local_key_id = tmp[].dup;
        }
        values.discardRemaining().endCons();
        attr_seq.discardRemaining().endCons();
    }
    attrs.endCons();
}

private void parseSafeContents(ref BERDecoder decoder, in string password,
                               ref ParsedCert[] cert_entries, ref ParsedKey[] key_entries,
                               ref OID[] unknown_bag_types, bool openssl_empty, size_t depth,
                               RandomNumberGenerator rng)
{
    if (depth >= PKCS12_MAX_NESTING)
        throw new DecodingError("PKCS#12: SafeContentsBag nesting too deep");
    const OID cert_bag_oid = OIDS.lookup("PKCS12.CertBag");
    const OID shrouded_oid = OIDS.lookup("PKCS12.PKCS8ShroudedKeyBag");
    const OID key_bag_oid = OIDS.lookup("PKCS12.KeyBag");
    const OID sc_bag_oid = OIDS.lookup("PKCS12.SafeContentsBag");
    const OID x509_cert_oid = OIDS.lookup("PKCS9.X509Certificate");

    while (decoder.moreItems())
    {
        OID bag_type;
        string bag_fn;
        ubyte[] bag_lki;
        BERDecoder bag_seq = decoder.startCons(ASN1Tag.SEQUENCE);
        bag_seq.decode(bag_type);
        BERDecoder bag_value = bag_seq.startCons(cast(ASN1Tag)0, ASN1Tag.CONTEXT_SPECIFIC);
        bool pushed_cert, pushed_key;

        if (bag_type == cert_bag_oid)
        {
            OID cert_type;
            BERDecoder cert_bag = bag_value.startCons(ASN1Tag.SEQUENCE);
            cert_bag.decode(cert_type);
            if (cert_type == x509_cert_oid)
            {
                Vector!ubyte cert_data;
                BERDecoder cert_value = cert_bag.startCons(cast(ASN1Tag)0, ASN1Tag.CONTEXT_SPECIFIC);
                cert_value.decode(cert_data, ASN1Tag.OCTET_STRING);
                cert_value.verifyEnd();
                cert_entries ~= ParsedCert(X509Certificate(cert_data), null, "");
                pushed_cert = true;
            }
            else
                cert_bag.discardRemaining();
            cert_bag.endCons();
            bag_value.verifyEnd();
        }
        else if (bag_type == shrouded_oid)
        {
            AlgorithmIdentifier pbe_algo;
            Vector!ubyte encrypted_key;
            BERDecoder shrouded = bag_value.startCons(ASN1Tag.SEQUENCE);
            shrouded.decode(pbe_algo);
            shrouded.decode(encrypted_key, ASN1Tag.OCTET_STRING);
            shrouded.verifyEnd();
            auto decrypted = pkcs12PbeDecrypt(encrypted_key.ptr, encrypted_key.length,
                                              password, pbe_algo, openssl_empty);
            auto src = DataSourceMemory(decrypted);
            key_entries ~= ParsedKey(pkcs8.loadKey(cast(DataSource)src, rng), null, "");
            pushed_key = true;
        }
        else if (bag_type == key_bag_oid)
        {
            SecureVector!ubyte key_data;
            bag_value.rawBytes(key_data);
            bag_value.verifyEnd();
            auto src = DataSourceMemory(key_data);
            key_entries ~= ParsedKey(pkcs8.loadKey(cast(DataSource)src, rng), null, "");
            pushed_key = true;
        }
        else if (bag_type == sc_bag_oid)
        {
            BERDecoder nested = bag_value.startCons(ASN1Tag.SEQUENCE);
            parseSafeContents(nested, password, cert_entries, key_entries,
                              unknown_bag_types, openssl_empty, depth + 1, rng);
            nested.verifyEnd();
            bag_value.verifyEnd();
        }
        else
        {
            unknown_bag_types ~= bag_type.clone;
            bag_value.discardRemaining();
        }
        bag_value.endCons();
        parseBagAttributes(bag_seq, bag_fn, bag_lki);
        if (pushed_cert && cert_entries.length)
        {
            if (bag_lki.length)
                cert_entries[$ - 1].local_key_id = bag_lki.dup;
            if (bag_fn.length)
                cert_entries[$ - 1].friendly_name = bag_fn;
        }
        else if (pushed_key && key_entries.length)
        {
            if (bag_lki.length)
                key_entries[$ - 1].local_key_id = bag_lki.dup;
            if (bag_fn.length)
                key_entries[$ - 1].friendly_name = bag_fn;
        }
        bag_seq.verifyEnd();
    }
}

private void parseAuthenticatedSafe(const(ubyte)* data, size_t data_len, in string password,
                                    ref ParsedCert[] cert_entries, ref ParsedKey[] key_entries,
                                    ref OID[] unknown_bag_types, bool openssl_empty,
                                    RandomNumberGenerator rng)
{
    const OID pkcs7_data = OIDS.lookup("PKCS7.Data");
    const OID pkcs7_enc = OIDS.lookup("PKCS7.EncryptedData");
    BERDecoder auth_safe = BERDecoder(data, data_len);
    BERDecoder seq = auth_safe.startCons(ASN1Tag.SEQUENCE);
    while (seq.moreItems())
    {
        OID content_type;
        BERDecoder content_info = seq.startCons(ASN1Tag.SEQUENCE);
        content_info.decode(content_type);
        if (content_type == pkcs7_data)
        {
            Vector!ubyte sc_data;
            BERDecoder content = content_info.startCons(cast(ASN1Tag)0, ASN1Tag.CONTEXT_SPECIFIC);
            content.decode(sc_data, ASN1Tag.OCTET_STRING);
            content.verifyEnd();
            BERDecoder safe_contents = BERDecoder(sc_data);
            BERDecoder sc_seq = safe_contents.startCons(ASN1Tag.SEQUENCE);
            parseSafeContents(sc_seq, password, cert_entries, key_entries,
                              unknown_bag_types, openssl_empty, 0, rng);
            sc_seq.verifyEnd();
            safe_contents.verifyEnd();
            content_info.verifyEnd();
        }
        else if (content_type == pkcs7_enc)
        {
            BERDecoder content = content_info.startCons(cast(ASN1Tag)0, ASN1Tag.CONTEXT_SPECIFIC);
            BERDecoder enc_data = content.startCons(ASN1Tag.SEQUENCE);
            size_t version_;
            enc_data.decode(version_);
            if (version_ != 0)
                throw new DecodingError("PKCS#12: unsupported EncryptedData version");
            BERDecoder enc_ci = enc_data.startCons(ASN1Tag.SEQUENCE);
            OID enc_content_type;
            AlgorithmIdentifier enc_algo;
            enc_ci.decode(enc_content_type);
            enc_ci.decode(enc_algo);
            if (enc_content_type != pkcs7_data)
                throw new DecodingError("PKCS#12: EncryptedData contentType must be Data");
            Vector!ubyte encrypted_content;
            BERObject enc_obj = enc_ci.getNextObject();
            if (enc_obj.type_tag == cast(ASN1Tag)0
                && enc_obj.class_tag == (ASN1Tag.CONTEXT_SPECIFIC | ASN1Tag.CONSTRUCTED))
            {
                BERDecoder chunks = BERDecoder(enc_obj.value);
                while (chunks.moreItems())
                {
                    Vector!ubyte chunk;
                    chunks.decode(chunk, ASN1Tag.OCTET_STRING);
                    encrypted_content ~= chunk[];
                }
                chunks.verifyEnd();
            }
            else if (enc_obj.type_tag == cast(ASN1Tag)0
                     && enc_obj.class_tag == ASN1Tag.CONTEXT_SPECIFIC)
                encrypted_content ~= enc_obj.value[];
            else
                throw new DecodingError("PKCS#12: Expected [0] context-specific for encrypted content");
            enc_ci.verifyEnd();
            enc_data.verifyEnd();
            auto decrypted = pkcs12PbeDecrypt(encrypted_content.ptr, encrypted_content.length,
                                              password, enc_algo, openssl_empty);
            BERDecoder safe_contents = BERDecoder(decrypted);
            BERDecoder sc_seq = safe_contents.startCons(ASN1Tag.SEQUENCE);
            parseSafeContents(sc_seq, password, cert_entries, key_entries,
                              unknown_bag_types, openssl_empty, 0, rng);
            sc_seq.verifyEnd();
            safe_contents.verifyEnd();
            content.verifyEnd();
            content_info.verifyEnd();
        }
        else
            throw new DecodingError("PKCS#12: unsupported AuthenticatedSafe content type "
                                    ~ content_type.toString());
    }
    seq.verifyEnd();
    auth_safe.verifyEnd();
}

/**
* PKCS#12/PFX bundle. Parse via `this(bytes, password)`.
*/
final class PKCS12
{
public:
    this() {}

    ~this()
    {
        foreach (k; m_keys)
            botanDestroyIfLive(k);
        m_keys.length = 0;
    }

    this(const(ubyte)* data, size_t data_len, in string password)
    {
        if (data_len == 0)
            throw new DecodingError("PKCS#12: empty input");
        Unique!AutoSeededRNG rng = new AutoSeededRNG;
        ParsedCert[] cert_entries;
        ParsedKey[] key_entries;
        BERDecoder pfx = BERDecoder(data, data_len);
        BERDecoder pfx_seq = pfx.startCons(ASN1Tag.SEQUENCE);
        size_t version_;
        pfx_seq.decode(version_);
        if (version_ != 3)
            throw new DecodingError("Unsupported PKCS#12 version");

        OID auth_safe_type;
        Vector!ubyte auth_safe_content;
        BERDecoder auth_safe_info = pfx_seq.startCons(ASN1Tag.SEQUENCE);
        auth_safe_info.decode(auth_safe_type);
        if (auth_safe_type != OIDS.lookup("PKCS7.Data"))
            throw new DecodingError("PKCS#12 authSafe must be of type Data");
        BERDecoder auth_wrap = auth_safe_info.startCons(cast(ASN1Tag)0, ASN1Tag.CONTEXT_SPECIFIC);
        auth_wrap.decode(auth_safe_content, ASN1Tag.OCTET_STRING);
        auth_wrap.verifyEnd();
        auth_safe_info.verifyEnd();

        bool openssl_empty = false;
        if (pfx_seq.moreItems())
        {
            BERDecoder mac_data = pfx_seq.startCons(ASN1Tag.SEQUENCE);
            BERDecoder digest_info = mac_data.startCons(ASN1Tag.SEQUENCE);
            AlgorithmIdentifier digest_algo;
            Vector!ubyte mac_value;
            digest_info.decode(digest_algo);
            digest_info.decode(mac_value, ASN1Tag.OCTET_STRING);
            digest_info.verifyEnd();
            Vector!ubyte mac_salt;
            size_t iterations = 1;
            mac_data.decode(mac_salt, ASN1Tag.OCTET_STRING);
            if (mac_data.moreItems())
                mac_data.decode(iterations);
            mac_data.verifyEnd();
            if (iterations == 0 || iterations > PKCS12_MAX_ITERATIONS)
                throw new DecodingError("PKCS#12 MAC has invalid iteration count");
            auto digest_oid = digest_algo.oid.clone;
            const string hash_name = resolveMacHash(digest_oid);
            try
                verifyMac(auth_safe_content.ptr, auth_safe_content.length, mac_value,
                          mac_salt, iterations, hash_name, password, false);
            catch (InvalidAuthenticationTag e)
            {
                if (password.length)
                    throw e;
                verifyMac(auth_safe_content.ptr, auth_safe_content.length, mac_value,
                          mac_salt, iterations, hash_name, password, true);
                openssl_empty = true;
            }
        }

        parseAuthenticatedSafe(auth_safe_content.ptr, auth_safe_content.length, password,
                               cert_entries, key_entries, m_unknown_bags, openssl_empty, *rng);

        foreach (ref ke; key_entries)
            m_keys ~= ke.key;

        if (key_entries.length)
        {
            if (key_entries[0].friendly_name.length)
            {
                m_has_fn = true;
                m_fn = key_entries[0].friendly_name;
            }
            if (key_entries[0].local_key_id.length || true)
            {
                if (key_entries[0].local_key_id.length)
                {
                    m_has_lki = true;
                    m_lki = Vector!ubyte(key_entries[0].local_key_id);
                }
            }
        }

        int ee_idx = -1;
        if (cert_entries.length && m_keys.length)
        {
            const first_lki = key_entries.length ? key_entries[0].local_key_id : null;
            if (first_lki.length)
            {
                foreach (i, ref ce; cert_entries)
                {
                    if (ce.local_key_id[] == first_lki[])
                    {
                        ee_idx = cast(int) i;
                        break;
                    }
                }
            }
            if (ee_idx < 0)
            {
                auto key_spki = x509_key.BER_encode(m_keys[0]);
                foreach (i, ref ce; cert_entries)
                {
                    try
                    {
                        if (x509_key.BER_encode(ce.cert.subjectPublicKey())[] == key_spki[])
                        {
                            ee_idx = cast(int) i;
                            break;
                        }
                    }
                    catch (Exception) {}
                }
            }
        }

        if (ee_idx >= 0)
        {
            m_certs ~= cert_entries[ee_idx].cert;
            if (!m_has_fn && cert_entries[ee_idx].friendly_name.length)
            {
                m_has_fn = true;
                m_fn = cert_entries[ee_idx].friendly_name;
            }
            if (!m_has_lki && cert_entries[ee_idx].local_key_id.length)
            {
                m_has_lki = true;
                m_lki = Vector!ubyte(cert_entries[ee_idx].local_key_id);
            }
            foreach (i, ref ce; cert_entries)
            {
                if (cast(int) i == ee_idx)
                    continue;
                if (!m_has_fn && ce.friendly_name.length)
                {
                    m_has_fn = true;
                    m_fn = ce.friendly_name;
                }
                m_certs ~= ce.cert;
            }
        }
        else
        {
            foreach (ref ce; cert_entries)
            {
                if (!m_has_fn && ce.friendly_name.length)
                {
                    m_has_fn = true;
                    m_fn = ce.friendly_name;
                }
                m_certs ~= ce.cert;
            }
        }

        pfx_seq.verifyEnd();
        pfx_seq.endCons();
        try
            pfx.verifyEnd();
        catch (InvalidState)
            throw new DecodingError("PKCS#12: trailing data after PFX");
    }

    this(const(ubyte)[] data, in string password)
    {
        this(data.ptr, data.length, password);
    }

    const(PrivateKey[]) privateKeys() const { return m_keys; }
    const(X509Certificate[]) certificates() const { return m_certs; }

    bool hasEndEntityCertificate()
    {
        return endEntityCertificate() !is X509Certificate.init;
    }

    X509Certificate endEntityCertificate()
    {
        if (!m_certs.length || !m_keys.length)
            return X509Certificate.init;
        try
        {
            auto key_spki = x509_key.BER_encode(m_keys[0]);
            foreach (c; m_certs)
            {
                try
                {
                    if (x509_key.BER_encode(c.subjectPublicKey())[] == key_spki[])
                        return c;
                }
                catch (Exception) {}
            }
        }
        catch (Exception) {}
        return X509Certificate.init;
    }

    X509Certificate[] caCertificates()
    {
        X509Certificate[] result;
        if (m_certs.length < 2)
            return result;
        auto ee = endEntityCertificate();
        if (ee !is X509Certificate.init)
        {
            auto ee_spki = x509_key.BER_encode(ee.subjectPublicKey());
            bool skipped;
            foreach (c; m_certs)
            {
                try
                {
                    if (!skipped && x509_key.BER_encode(c.subjectPublicKey())[] == ee_spki[])
                    {
                        skipped = true;
                        continue;
                    }
                }
                catch (Exception) {}
                result ~= c;
            }
        }
        else
        {
            foreach (i; 1 .. m_certs.length)
                result ~= m_certs[i];
        }
        return result;
    }

    bool hasFriendlyName() const { return m_has_fn; }
    string friendlyName() const { return m_fn; }
    bool hasLocalKeyId() const { return m_has_lki; }
    Vector!ubyte localKeyId() const { return m_lki.clone; }
    const(OID[]) unknownBagTypes() const { return m_unknown_bags; }

    void addKey(PrivateKey key)
    {
        if (key is null)
            throw new InvalidArgument("PKCS12.add_key: null key");
        m_keys ~= key;
    }

    void addCertificate(X509Certificate cert)
    {
        m_certs ~= cert;
    }

    void setFriendlyName(string name)
    {
        m_has_fn = true;
        m_fn = name;
    }

    void clearFriendlyName()
    {
        m_has_fn = false;
        m_fn = "";
    }

    void setLocalKeyId(const(ubyte)[] id)
    {
        m_has_lki = true;
        m_lki = Vector!ubyte(id);
    }

    void clearLocalKeyId()
    {
        m_has_lki = false;
        m_lki.clear();
    }

    /**
    * Serialize the bundle as a PKCS#12/PFX file.
    */
    Vector!ubyte exportTo(PKCS12ExportOptions options, RandomNumberGenerator rng)
    {
        if (!m_keys.length && !m_certs.length)
            throw new InvalidArgument("PKCS#12.export_to requires at least a key or certificate");

        validateExportOptions(options);

        int ee_idx = -1;
        if (m_keys.length && m_certs.length)
        {
            auto key_spki = x509_key.BER_encode(m_keys[0]);
            foreach (i, ref c; m_certs)
            {
                try
                {
                    if (x509_key.BER_encode(c.subjectPublicKey())[] == key_spki[])
                    {
                        ee_idx = cast(int) i;
                        break;
                    }
                }
                catch (Exception) {}
            }
            if (ee_idx < 0)
                throw new InvalidArgument("PKCS#12.export_to: private key does not match any certificate");
        }

        const OID cert_bag_oid = OIDS.lookup("PKCS12.CertBag");
        const OID shrouded_key_oid = OIDS.lookup("PKCS12.PKCS8ShroudedKeyBag");
        const OID x509_cert_oid = OIDS.lookup("PKCS9.X509Certificate");
        const OID pkcs7_data_oid = OIDS.lookup("PKCS7.Data");
        const OID pkcs7_enc_data_oid = OIDS.lookup("PKCS7.EncryptedData");

        const bool opt_fn = options.hasFriendlyName();
        const string friendly_name = opt_fn ? options.friendlyName() : m_fn;
        const bool has_fn = opt_fn ? options.friendlyName().length != 0 : m_has_fn;

        Vector!ubyte local_key_id;
        if (m_has_lki)
            local_key_id = m_lki.clone;
        else if (ee_idx >= 0 || m_keys.length)
        {
            auto pub_bits = m_keys[0].x509SubjectPublicKey();
            local_key_id = sha1Of(pub_bits.ptr, pub_bits.length);
        }

        Vector!ubyte cert_safe_contents;
        if (m_certs.length)
        {
            auto cert_bags = DEREncoder();
            cert_bags.startCons(ASN1Tag.SEQUENCE);

            void addCertBag(X509Certificate c, bool add_attrs)
            {
                auto cert_ber = c.BER_encode();
                cert_bags.startCons(ASN1Tag.SEQUENCE);
                cert_bags.encode(cert_bag_oid);
                cert_bags.startExplicit(0);
                cert_bags.startCons(ASN1Tag.SEQUENCE);
                cert_bags.encode(x509_cert_oid);
                cert_bags.startExplicit(0);
                cert_bags.encode(cert_ber, ASN1Tag.OCTET_STRING);
                cert_bags.endCons();
                cert_bags.endCons();
                cert_bags.endCons();
                if (add_attrs)
                    writeBagAttributes(cert_bags, has_fn, friendly_name, local_key_id);
                cert_bags.endCons();
            }

            if (ee_idx >= 0)
            {
                addCertBag(m_certs[ee_idx], true);
                foreach (i, ref c; m_certs)
                {
                    if (cast(int) i != ee_idx)
                        addCertBag(c, false);
                }
            }
            else
            {
                foreach (ref c; m_certs)
                    addCertBag(c, false);
            }
            cert_bags.endCons();
            cert_safe_contents = cert_bags.getContentsUnlocked();
        }

        Vector!ubyte key_safe_contents;
        if (m_keys.length)
        {
            auto key_bags = DEREncoder();
            key_bags.startCons(ASN1Tag.SEQUENCE);
            foreach (i, key; m_keys)
            {
                auto pkcs8_key = pkcs8.BER_encode(key);
                auto enc = pkcs12PbeEncrypt(pkcs8_key.ptr, pkcs8_key.length,
                                            options.password(), options.keyEncryptionAlgo(),
                                            options.iterations(), rng);
                key_bags.startCons(ASN1Tag.SEQUENCE);
                key_bags.encode(shrouded_key_oid);
                key_bags.startExplicit(0);
                key_bags.startCons(ASN1Tag.SEQUENCE);
                key_bags.encode(enc.first);
                key_bags.encode(enc.second, ASN1Tag.OCTET_STRING);
                key_bags.endCons();
                key_bags.endCons();
                if (i == 0)
                    writeBagAttributes(key_bags, has_fn, friendly_name, local_key_id);
                key_bags.endCons();
            }
            key_bags.endCons();
            key_safe_contents = key_bags.getContentsUnlocked();
        }

        auto auth_safe = DEREncoder();
        auth_safe.startCons(ASN1Tag.SEQUENCE);
        if (cert_safe_contents.length)
        {
            if (options.certEncryptionAlgo().length)
            {
                auto enc = pkcs12PbeEncrypt(cert_safe_contents.ptr, cert_safe_contents.length,
                                            options.password(), options.certEncryptionAlgo(),
                                            options.iterations(), rng);
                auth_safe.startCons(ASN1Tag.SEQUENCE);
                auth_safe.encode(pkcs7_enc_data_oid);
                auth_safe.startExplicit(0);
                auth_safe.startCons(ASN1Tag.SEQUENCE);
                auth_safe.encode(cast(size_t) 0);
                auth_safe.startCons(ASN1Tag.SEQUENCE);
                auth_safe.encode(pkcs7_data_oid);
                auth_safe.encode(enc.first);
                auth_safe.addObject(cast(ASN1Tag) 0, ASN1Tag.CONTEXT_SPECIFIC, enc.second);
                auth_safe.endCons();
                auth_safe.endCons();
                auth_safe.endCons();
                auth_safe.endCons();
            }
            else
            {
                auth_safe.startCons(ASN1Tag.SEQUENCE);
                auth_safe.encode(pkcs7_data_oid);
                auth_safe.startExplicit(0);
                auth_safe.encode(cert_safe_contents, ASN1Tag.OCTET_STRING);
                auth_safe.endCons();
                auth_safe.endCons();
            }
        }
        if (key_safe_contents.length)
        {
            auth_safe.startCons(ASN1Tag.SEQUENCE);
            auth_safe.encode(pkcs7_data_oid);
            auth_safe.startExplicit(0);
            auth_safe.encode(key_safe_contents, ASN1Tag.OCTET_STRING);
            auth_safe.endCons();
            auth_safe.endCons();
        }
        auth_safe.endCons();
        Vector!ubyte auth_safe_content = auth_safe.getContentsUnlocked();

        auto pfx = DEREncoder();
        pfx.startCons(ASN1Tag.SEQUENCE);
        pfx.encode(cast(size_t) 3);
        pfx.startCons(ASN1Tag.SEQUENCE);
        pfx.encode(pkcs7_data_oid);
        pfx.startExplicit(0);
        pfx.encode(auth_safe_content, ASN1Tag.OCTET_STRING);
        pfx.endCons();
        pfx.endCons();

        if (options.includeMac())
        {
            const string mac_hash = canonicalMacHash(options.macDigest());
            Unique!MessageAuthenticationCode hmac = retrieveMac("HMAC(" ~ mac_hash ~ ")").clone();
            Vector!ubyte mac_salt;
            mac_salt.length = hmac.outputLength;
            rng.randomize(mac_salt.ptr, mac_salt.length);
            const size_t mac_key_len = hmac.outputLength;
            auto mac_key = SecureVector!ubyte(mac_key_len);
            Unique!PBKDF kdf = getPbkdf("PKCS12-KDF(" ~ mac_hash ~ ",3)");
            auto k = kdf.deriveKey(mac_key_len, options.password(),
                                   mac_salt.ptr, mac_salt.length, options.iterations());
            mac_key[] = k.bitsOf()[];
            hmac.setKey(mac_key.ptr, mac_key.length);
            hmac.update(auth_safe_content.ptr, auth_safe_content.length);
            auto mac_value = hmac.finished();

            pfx.startCons(ASN1Tag.SEQUENCE);
            pfx.startCons(ASN1Tag.SEQUENCE);
            if (mac_hash == "SHA-160")
            {
                auto digest_aid = AlgorithmIdentifier(OIDS.lookup(mac_hash),
                                                      AlgorithmIdentifierImpl.USE_NULL_PARAM);
                pfx.encode(digest_aid);
            }
            else
            {
                Vector!ubyte empty_params;
                auto digest_aid = AlgorithmIdentifier(OIDS.lookup(mac_hash), empty_params);
                pfx.encode(digest_aid);
            }
            pfx.encode(mac_value, ASN1Tag.OCTET_STRING);
            pfx.endCons();
            pfx.encode(mac_salt, ASN1Tag.OCTET_STRING);
            if (options.iterations() != 1)
                pfx.encode(options.iterations());
            pfx.endCons();
        }

        pfx.endCons();
        return pfx.getContentsUnlocked();
    }

private:
    PrivateKey[] m_keys;
    X509Certificate[] m_certs;
    bool m_has_fn, m_has_lki;
    string m_fn;
    Vector!ubyte m_lki;
    OID[] m_unknown_bags;
}

static if (BOTAN_HAS_TESTS && !SKIP_PKCS12_TEST) unittest
{
    import botan.test;
    import botan.libstate.global_state;
    import std.file : read, exists;

    auto state = globalState();
    logDebug("Testing pkcs12.d ...");
    size_t fails = 0;

    void expectThrow(string tag, void delegate() dg)
    {
        bool threw;
        try { dg(); } catch (Exception) { threw = true; }
        if (!threw)
        {
            logError("pkcs12 expected throw: ", tag);
            ++fails;
        }
    }

    X509Certificate copyCert(const X509Certificate c)
    {
        return X509Certificate(c.BER_encode());
    }

    expectThrow("empty", { Unique!PKCS12 p = new PKCS12(cast(const(ubyte)[])[], "pass"); });

    Unique!PKCS12 emptyb = new PKCS12;
    bool add_null;
    try { emptyb.addKey(null); } catch (InvalidArgument) { add_null = true; }
    if (!add_null)
    {
        logError("pkcs12 add_key null");
        ++fails;
    }
    if (emptyb.hasLocalKeyId())
        ++fails;
    emptyb.setLocalKeyId([]);
    if (!emptyb.hasLocalKeyId() || emptyb.localKeyId().length != 0)
        ++fails;
    emptyb.clearLocalKeyId();
    if (emptyb.hasLocalKeyId())
        ++fails;

    size_t parseFile(string filename, string password,
                     bool has_cert, bool has_key, bool has_ca, bool has_fn)
    {
        const string path = "test_data/pkcs12/" ~ filename;
        if (!exists(path))
        {
            logError("missing fixture ", path);
            return 1;
        }
        auto raw = cast(ubyte[]) read(path);
        Unique!PKCS12 parsed;
        try
            parsed = new PKCS12(raw, password);
        catch (Exception e)
        {
            logError(filename, " parse: ", e.msg);
            return 1;
        }
        if ((parsed.privateKeys().length != 0) != has_key)
        {
            logError(filename, " key=", parsed.privateKeys().length, " want ", has_key);
            return 1;
        }
        if ((parsed.certificates().length != 0) != has_cert)
        {
            logError(filename, " cert=", parsed.certificates().length, " want ", has_cert);
            return 1;
        }
        if ((parsed.caCertificates().length != 0) != has_ca)
        {
            logError(filename, " ca=", parsed.caCertificates().length, " want ", has_ca);
            return 1;
        }
        if (parsed.hasFriendlyName() != has_fn)
        {
            logError(filename, " fn=", parsed.hasFriendlyName(), " want ", has_fn,
                     " val=", parsed.friendlyName());
            return 1;
        }
        if (has_key && parsed.privateKeys().length && parsed.privateKeys()[0].algoName.length == 0)
            return 1;
        if (has_cert && parsed.certificates().length)
        {
            auto cn = parsed.certificates()[0].subjectInfo("X520.CommonName");
            if (cn.length == 0 || cn[0].length == 0)
            {
                auto cn2 = parsed.certificates()[0].subjectInfo("CN");
                if (cn2.length == 0 || cn2[0].length == 0)
                {
                    logError(filename, " empty CN");
                    return 1;
                }
            }
        }
        return 0;
    }

    void expectAuth(string filename, string password)
    {
        auto raw = cast(ubyte[]) read("test_data/pkcs12/" ~ filename);
        bool threw;
        try { Unique!PKCS12 p = new PKCS12(raw, password); } catch (InvalidAuthenticationTag) { threw = true; }
        if (!threw)
        {
            logError(filename, " expected InvalidAuthenticationTag");
            ++fails;
        }
    }

    void expectDecode(string filename, string password)
    {
        auto raw = cast(ubyte[]) read("test_data/pkcs12/" ~ filename);
        bool threw;
        try { Unique!PKCS12 p = new PKCS12(raw, password); } catch (DecodingError) { threw = true; }
        if (!threw)
        {
            logError(filename, " expected DecodingError");
            ++fails;
        }
    }

    expectDecode("nesting_too_deep.pfx", "");
    expectDecode("pfx_version_2.pfx", "");
    expectDecode("envelopeddata_content.pfx", "");

    {
        auto raw = cast(ubyte[]) read("test_data/pkcs12/key_bag_unencrypted.pfx");
        Unique!PKCS12 p = new PKCS12(raw, "");
        if (p.privateKeys().length != 1 || !p.hasEndEntityCertificate())
        {
            logError("key_bag_unencrypted");
            ++fails;
        }
    }
    {
        auto raw = cast(ubyte[]) read("test_data/pkcs12/safe_contents_bag_nested.pfx");
        Unique!PKCS12 p = new PKCS12(raw, "");
        if (p.privateKeys().length != 0 || p.certificates().length == 0)
        {
            logError("safe_contents_bag_nested");
            ++fails;
        }
    }
    {
        auto raw = cast(ubyte[]) read("test_data/pkcs12/key_cert_spki_mismatch.pfx");
        Unique!PKCS12 p = new PKCS12(raw, "");
        if (p.privateKeys().length == 0 || p.certificates().length == 0
            || p.hasEndEntityCertificate() || p.caCertificates().length != 0)
        {
            logError("key_cert_spki_mismatch");
            ++fails;
        }
    }
    {
        auto raw = cast(ubyte[]) read("test_data/pkcs12/unknown_bag_secret.pfx");
        Unique!PKCS12 p = new PKCS12(raw, "");
        if (p.unknownBagTypes().length != 1
            || OIDS.lookup(p.unknownBagTypes()[0]) != "PKCS12.SecretBag"
            || p.certificates().length == 0)
        {
            logError("unknown_bag_secret");
            ++fails;
        }
    }
    {
        auto raw = cast(ubyte[]) read("test_data/pkcs12/unknown_bag_crl.pfx");
        Unique!PKCS12 p = new PKCS12(raw, "");
        if (p.unknownBagTypes().length != 1
            || OIDS.lookup(p.unknownBagTypes()[0]) != "PKCS12.CRLBag")
        {
            logError("unknown_bag_crl got ", p.unknownBagTypes().length,
                     p.unknownBagTypes().length ? OIDS.lookup(p.unknownBagTypes()[0]) : "");
            ++fails;
        }
    }

    fails += parseFile("openssl_3des.p12", "test123", true, true, false, false);
    fails += parseFile("cert-none-key-none.p12", "cryptography", true, true, false, false);
    fails += parseFile("name-1-pwd.p12", "password", true, true, true, true);
    fails += parseFile("name-2-3-pwd.p12", "password", true, true, true, true);
    fails += parseFile("name-2-pwd.p12", "password", true, true, true, true);
    fails += parseFile("name-3-pwd.p12", "password", true, true, true, true);
    fails += parseFile("name-all-pwd.p12", "password", true, true, true, true);
    fails += parseFile("name-unicode-pwd.p12", "password", true, true, true, true);
    fails += parseFile("no-cert-name-2-pwd.p12", "password", true, false, true, true);
    fails += parseFile("no-cert-name-3-pwd.p12", "password", true, false, true, true);
    fails += parseFile("no-cert-name-all-pwd.p12", "password", true, false, true, true);
    fails += parseFile("no-cert-name-unicode-pwd.p12", "password", true, false, true, true);
    fails += parseFile("no-cert-no-name-pwd.p12", "password", true, false, true, false);
    fails += parseFile("no-name-pwd.p12", "password", true, true, true, false);
    fails += parseFile("java-truststore.p12", "", true, false, true, true);
    fails += parseFile("name-1-no-pwd.p12", "", true, true, true, true);
    fails += parseFile("name-2-3-no-pwd.p12", "", true, true, true, true);
    fails += parseFile("name-2-no-pwd.p12", "", true, true, true, true);
    fails += parseFile("no-cert-no-name-no-pwd.p12", "", true, false, true, false);
    fails += parseFile("no-name-no-pwd.p12", "", true, true, true, false);
    fails += parseFile("name-3-no-pwd.p12", "", true, true, true, true);
    fails += parseFile("no-cert-name-all-no-pwd.p12", "", true, false, true, true);
    fails += parseFile("name-all-no-pwd.p12", "", true, true, true, true);
    fails += parseFile("name-unicode-no-pwd.p12", "", true, true, true, true);
    fails += parseFile("no-cert-name-2-no-pwd.p12", "", true, false, true, true);
    fails += parseFile("no-cert-name-3-no-pwd.p12", "", true, false, true, true);
    fails += parseFile("no-cert-name-unicode-no-pwd.p12", "", true, false, true, true);
    expectDecode("no-password.p12", "");
    expectAuth("name-1-pwd.p12", "wrongpassword");
    expectDecode("cert-rc2-key-3des.p12", "cryptography");

    static if (BOTAN_HAS_PBE_PKCS_V20)
    {
        fails += parseFile("openssl_aes256.p12", "test123", true, true, false, false);
        fails += parseFile("cert-aes256cbc-no-key.p12", "cryptography", true, false, false, false);
        fails += parseFile("cert-key-aes256cbc.p12", "cryptography", true, true, false, false);
        fails += parseFile("no-cert-key-aes256cbc.p12", "cryptography", false, true, false, false);
    }

    fails += checkMemutilsRepeat("pkcs12", {
        auto raw = cast(ubyte[]) read("test_data/pkcs12/openssl_3des.p12");
        Unique!PKCS12 p = new PKCS12(raw, "test123");
        if (p.privateKeys().length == 0)
            throw new Exception("pkcs12 leak probe");
    });

    {
        Unique!AutoSeededRNG rng = new AutoSeededRNG;
        Unique!PKCS12 empty_exp = new PKCS12;
        expectThrow("empty export", {
            empty_exp.exportTo(PKCS12ExportOptions.legacyCompat("pw"), *rng);
        });

        {
            auto zopts = PKCS12ExportOptions("test");
            zopts.withIterations(0);
            expectThrow("zero iter", {
                Unique!PKCS12 b = new PKCS12;
                auto raw = cast(ubyte[]) read("test_data/pkcs12/openssl_3des.p12");
                Unique!PKCS12 src = new PKCS12(raw, "test123");
                b.addCertificate(copyCert(src.certificates()[0]));
                b.exportTo(zopts, *rng);
            });
        }
        {
            auto mopts = PKCS12ExportOptions("test");
            mopts.withIterations(100_000_001);
            expectThrow("max iter", {
                Unique!PKCS12 b = new PKCS12;
                auto raw = cast(ubyte[]) read("test_data/pkcs12/openssl_3des.p12");
                Unique!PKCS12 src = new PKCS12(raw, "test123");
                b.addCertificate(copyCert(src.certificates()[0]));
                b.exportTo(mopts, *rng);
            });
        }
        {
            auto uopts = PKCS12ExportOptions("test");
            uopts.withKeyEncryptionAlgo("no-such-pbe");
            expectThrow("bad key algo", {
                Unique!PKCS12 b = new PKCS12;
                auto raw = cast(ubyte[]) read("test_data/pkcs12/openssl_3des.p12");
                Unique!PKCS12 src = new PKCS12(raw, "test123");
                b.addCertificate(copyCert(src.certificates()[0]));
                b.exportTo(uopts, *rng);
            });
        }

        auto raw_a = cast(ubyte[]) read("test_data/pkcs12/openssl_3des.p12");
        Unique!PKCS12 src = new PKCS12(raw_a, "test123");
        if (!src.privateKeys().length || !src.certificates().length)
        {
            logError("pkcs12 export: fixture empty");
            ++fails;
        }
        else
        {
            src.setFriendlyName("Export Roundtrip");
            auto leg = PKCS12ExportOptions.legacyCompat("export-pass");
            auto pfx = src.exportTo(leg, *rng);
            if (!pfx.length)
            {
                logError("pkcs12 export: empty PFX");
                ++fails;
            }
            else
            {
                Unique!PKCS12 parsed = new PKCS12(pfx[], "export-pass");
                if (parsed.privateKeys().length != 1 || !parsed.hasEndEntityCertificate()
                    || parsed.friendlyName() != "Export Roundtrip")
                {
                    logError("pkcs12 export legacy roundtrip fn=", parsed.friendlyName(),
                             " keys=", parsed.privateKeys().length);
                    ++fails;
                }
                else
                {
                    auto a_ber = pkcs8.BER_encode(src.privateKeys()[0]);
                    auto b_ber = pkcs8.BER_encode(parsed.privateKeys()[0]);
                    if (a_ber[] != b_ber[])
                    {
                        logError("pkcs12 export: key BER mismatch");
                        ++fails;
                    }
                    if (parsed.endEntityCertificate().BER_encode()[]
                        != src.certificates()[0].BER_encode()[])
                    {
                        logError("pkcs12 export: cert BER mismatch");
                        ++fails;
                    }
                }
                bool wrong_pw;
                try { Unique!PKCS12 w = new PKCS12(pfx[], "wrong"); }
                catch (InvalidAuthenticationTag) { wrong_pw = true; }
                if (!wrong_pw)
                {
                    logError("pkcs12 export: wrong password accepted");
                    ++fails;
                }
            }

            {
                Unique!PKCS12 nofn = new PKCS12;
                auto key_ber = pkcs8.BER_encode(src.privateKeys()[0]);
                auto key_src = DataSourceMemory(key_ber);
                nofn.addKey(pkcs8.loadKey(cast(DataSource)key_src, *rng));
                nofn.addCertificate(copyCert(src.certificates()[0]));
                auto pfx2 = nofn.exportTo(PKCS12ExportOptions.legacyCompat("noname"), *rng);
                Unique!PKCS12 parsed2 = new PKCS12(pfx2[], "noname");
                if (!parsed2.privateKeys().length || !parsed2.hasEndEntityCertificate()
                    || parsed2.hasFriendlyName())
                {
                    logError("pkcs12 export: no-fn unexpected fn=", parsed2.hasFriendlyName());
                    ++fails;
                }
            }

            {
                Unique!PKCS12 nomac = new PKCS12;
                auto key_ber = pkcs8.BER_encode(src.privateKeys()[0]);
                auto key_src = DataSourceMemory(key_ber);
                nomac.addKey(pkcs8.loadKey(cast(DataSource)key_src, *rng));
                nomac.addCertificate(copyCert(src.certificates()[0]));
                auto opts_nm = PKCS12ExportOptions.legacyCompat("nomactest");
                opts_nm.withoutMac();
                auto pfx_nm = nomac.exportTo(opts_nm, *rng);
                Unique!PKCS12 parsed_nm = new PKCS12(pfx_nm[], "nomactest");
                if (!parsed_nm.privateKeys().length || !parsed_nm.hasEndEntityCertificate())
                {
                    logError("pkcs12 export: without mac");
                    ++fails;
                }
            }

            {
                Unique!PKCS12 emptypw = new PKCS12;
                auto key_ber = pkcs8.BER_encode(src.privateKeys()[0]);
                auto key_src = DataSourceMemory(key_ber);
                emptypw.addKey(pkcs8.loadKey(cast(DataSource)key_src, *rng));
                emptypw.addCertificate(copyCert(src.certificates()[0]));
                auto pfx_e = emptypw.exportTo(PKCS12ExportOptions.legacyCompat(""), *rng);
                Unique!PKCS12 parsed_e = new PKCS12(pfx_e[], "");
                if (!parsed_e.privateKeys().length || !parsed_e.hasEndEntityCertificate())
                {
                    logError("pkcs12 export: empty password");
                    ++fails;
                }
            }

            {
                Unique!PKCS12 keyonly = new PKCS12;
                auto key_ber = pkcs8.BER_encode(src.privateKeys()[0]);
                auto key_src = DataSourceMemory(key_ber);
                keyonly.addKey(pkcs8.loadKey(cast(DataSource)key_src, *rng));
                auto pfx_k = keyonly.exportTo(PKCS12ExportOptions.legacyCompat("keyonly"), *rng);
                Unique!PKCS12 parsed_k = new PKCS12(pfx_k[], "keyonly");
                if (parsed_k.privateKeys().length != 1 || parsed_k.certificates().length != 0)
                {
                    logError("pkcs12 export: key-only");
                    ++fails;
                }
            }

            {
                Unique!PKCS12 certonly = new PKCS12;
                certonly.addCertificate(copyCert(src.certificates()[0]));
                auto pfx_c = certonly.exportTo(PKCS12ExportOptions.legacyCompat("certonly"), *rng);
                Unique!PKCS12 parsed_c = new PKCS12(pfx_c[], "certonly");
                if (parsed_c.privateKeys().length != 0 || parsed_c.certificates().length == 0
                    || parsed_c.hasEndEntityCertificate())
                {
                    logError("pkcs12 export: cert-only");
                    ++fails;
                }
            }

            {
                Unique!PKCS12 cenc = new PKCS12;
                auto key_ber = pkcs8.BER_encode(src.privateKeys()[0]);
                auto key_src = DataSourceMemory(key_ber);
                cenc.addKey(pkcs8.loadKey(cast(DataSource)key_src, *rng));
                cenc.addCertificate(copyCert(src.certificates()[0]));
                auto opts_ce = PKCS12ExportOptions.legacyCompat("certenctest");
                opts_ce.withCertEncryptionAlgo("PBE-SHA1-3DES");
                auto pfx_ce = cenc.exportTo(opts_ce, *rng);
                Unique!PKCS12 parsed_ce = new PKCS12(pfx_ce[], "certenctest");
                if (!parsed_ce.privateKeys().length || !parsed_ce.hasEndEntityCertificate())
                {
                    logError("pkcs12 export: cert enc 3des");
                    ++fails;
                }
            }

            {
                Unique!PKCS12 ovr = new PKCS12;
                auto key_ber = pkcs8.BER_encode(src.privateKeys()[0]);
                auto key_src = DataSourceMemory(key_ber);
                ovr.addKey(pkcs8.loadKey(cast(DataSource)key_src, *rng));
                ovr.addCertificate(copyCert(src.certificates()[0]));
                ovr.setFriendlyName("Bundle Name");
                auto opts_ovr = PKCS12ExportOptions.legacyCompat("ovrpw");
                opts_ovr.withFriendlyName("Options Name");
                auto pfx_ovr = ovr.exportTo(opts_ovr, *rng);
                Unique!PKCS12 parsed_ovr = new PKCS12(pfx_ovr[], "ovrpw");
                if (parsed_ovr.friendlyName() != "Options Name")
                {
                    logError("pkcs12 export: fn override got ", parsed_ovr.friendlyName());
                    ++fails;
                }
            }

            static if (BOTAN_HAS_PBE_PKCS_V20)
            {
                Unique!PKCS12 pbes2 = new PKCS12;
                auto key_ber = pkcs8.BER_encode(src.privateKeys()[0]);
                auto key_src = DataSourceMemory(key_ber);
                pbes2.addKey(pkcs8.loadKey(cast(DataSource)key_src, *rng));
                pbes2.addCertificate(copyCert(src.certificates()[0]));
                pbes2.setFriendlyName("PBES2 Test");
                auto opts_m = PKCS12ExportOptions.modern("pbes2pw");
                opts_m.withIterations(2048);
                auto pfx_m = pbes2.exportTo(opts_m, *rng);
                Unique!PKCS12 parsed_m = new PKCS12(pfx_m[], "pbes2pw");
                if (parsed_m.privateKeys().length != 1 || !parsed_m.hasEndEntityCertificate()
                    || parsed_m.friendlyName() != "PBES2 Test")
                {
                    logError("pkcs12 export: PBES2 modern");
                    ++fails;
                }
            }

            {
                auto raw_b = cast(ubyte[]) read("test_data/pkcs12/name-1-pwd.p12");
                Unique!PKCS12 other = new PKCS12(raw_b, "password");
                if (other.certificates().length)
                {
                    Unique!PKCS12 mismatch = new PKCS12;
                    auto key_ber_m = pkcs8.BER_encode(src.privateKeys()[0]);
                    auto key_src_m = DataSourceMemory(key_ber_m);
                    mismatch.addKey(pkcs8.loadKey(cast(DataSource)key_src_m, *rng));
                    mismatch.addCertificate(copyCert(other.certificates()[0]));
                    bool threw;
                    try
                        mismatch.exportTo(PKCS12ExportOptions.legacyCompat("mismatch"), *rng);
                    catch (InvalidArgument) { threw = true; }
                    if (!threw)
                    {
                        logError("pkcs12 export: mismatch accepted");
                        ++fails;
                    }
                }
            }
        }

        fails += checkMemutilsRepeat("pkcs12-export", {
            auto raw = cast(ubyte[]) read("test_data/pkcs12/openssl_3des.p12");
            Unique!PKCS12 p = new PKCS12(raw, "test123");
            Unique!AutoSeededRNG r = new AutoSeededRNG;
            auto outp = p.exportTo(PKCS12ExportOptions.legacyCompat("probe"), *r);
            if (!outp.length)
                throw new Exception("pkcs12 export leak probe");
        });
    }

    if (fails)
        logError("pkcs12 failures: ", fails);
    testReport("pkcs12", 54, fails);
    assert(fails == 0);
}
