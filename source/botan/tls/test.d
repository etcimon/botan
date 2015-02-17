/**
* TLS Unit tests
* 
* Copyright:
* (C) 2014-2015 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.test;
import botan.constants;
static if (BOTAN_TEST && BOTAN_HAS_TLS):

import botan.test;
import botan.rng.auto_rng;
import botan.tls.server;
import botan.tls.client;
import botan.cert.x509.pkcs10;
import botan.cert.x509.x509self;
import botan.cert.x509.x509_ca;
import botan.pubkey.algo.rsa;
import botan.codec.hex;
import botan.utils.types;
import std.stdio;
import std.datetime;

class TLSCredentialsManagerTest : TLSCredentialsManager
{
public:
    this(X509Certificate server_cert, X509Certificate ca_cert, PrivateKey server_key) 
    {
        m_server_cert = server_cert;
        m_ca_cert = ca_cert;
        m_key = server_key;
        auto store = new CertificateStoreInMemory;
        store.addCertificate(m_ca_cert);
        m_stores.pushBack(store);
    }
    
    override Vector!CertificateStore trustedCertificateAuthorities(in string, in string)
    {
        return m_stores.dup;
    }

    override Vector!X509Certificate certChain(const ref Vector!string cert_key_types, in string type, in string) 
    {
        Vector!X509Certificate chain;
        
        if (type == "tls-server")
        {
            bool have_match = false;
            foreach (cert_key_type; cert_key_types[])
                if (cert_key_type == m_key.algoName)
                    have_match = true;
            
            if (have_match)
            {
                chain.pushBack(m_server_cert);
                chain.pushBack(m_ca_cert);
            }
        }
        
        return chain.move();
    }
    
    override void verifyCertificateChain(in string type, in string purported_hostname,
                                         const ref Vector!X509Certificate cert_chain)
    {
        try
        {
            super.verifyCertificateChain(type, purported_hostname, cert_chain);
        }
        catch(Exception e)
        {
            logTrace("Certificate verification failed - " ~ e.msg ~ " - but will ignore");
        }
    }
    
    override PrivateKey privateKeyFor(in X509Certificate, in string, in string)
    {
        return m_key;
    }

    // Interface fallthrough

    override Vector!X509Certificate certChainSingleType(in string cert_key_type,
                                                        in string type,
                                                        in string context)
    { return super.certChainSingleType(cert_key_type, type, context); }

    override bool attemptSrp(in string type, in string context)
    { return super.attemptSrp(type, context); }

    override string srpIdentifier(in string type, in string context)
    { return super.srpIdentifier(type, context); }

    override string srpPassword(in string type, in string context, in string identifier)
    { return super.srpPassword(type, context, identifier); }

    override bool srpVerifier(in string type,
                              in string context,
                              in string identifier,
                              ref string group_name,
                              ref BigInt verifier,
                              ref Vector!ubyte salt,
                              bool generate_fake_on_unknown)
    { return super.srpVerifier(type, context, identifier, group_name, verifier, salt, generate_fake_on_unknown); }

    override string pskIdentityHint(in string type, in string context)
    { return super.pskIdentityHint(type, context); }

    override string pskIdentity(in string type, in string context, in string identity_hint)
    { return super.pskIdentity(type, context, identity_hint); }

    override SymmetricKey psk(in string type, in string context, in string identity)
    { return super.psk(type, context, identity); }

public:
    X509Certificate m_server_cert, m_ca_cert;
    PrivateKey m_key;
    Vector!CertificateStore m_stores;
}

TLSCredentialsManager createCreds(RandomNumberGenerator rng)
{
    PrivateKey ca_key = RSAPrivateKey(rng, 1024);
    
    X509CertOptions ca_opts;
    ca_opts.common_name = "Test CA";
    ca_opts.country = "US";
    ca_opts.cAKey(1);
    
    X509Certificate ca_cert = x509self.createSelfSignedCert(ca_opts, ca_key, "SHA-256", rng);
    
    PrivateKey server_key = RSAPrivateKey(rng, 1024);
    
    X509CertOptions server_opts;
    server_opts.common_name = "localhost";
    server_opts.country = "US";
    
    PKCS10Request req = x509self.createCertReq(server_opts, server_key, "SHA-256", rng);
    
    X509CA ca = X509CA(ca_cert, ca_key, "SHA-256");
    
    auto now = Clock.currTime(UTC());
    X509Time start_time = X509Time(now);
    X509Time end_time = X509Time(now + 365.days);
    
    X509Certificate server_cert = ca.signRequest(req, rng, start_time, end_time);
    
    return new TLSCredentialsManagerTest(server_cert, ca_cert, server_key);
}

size_t basicTestHandshake(RandomNumberGenerator rng,
                            TLSProtocolVersion offer_version,
                            TLSCredentialsManager creds,
                            TLSPolicy policy)
{
    auto server_sessions = new TLSSessionManagerInMemory(rng);
    auto client_sessions = new TLSSessionManagerInMemory(rng);
    
    Vector!ubyte c2s_q, s2c_q, c2s_data, s2c_data;
    
    auto handshake_complete = delegate(const ref TLSSession session) {
        if (session.Version() != offer_version)
            logTrace("Wrong version negotiated");
        return true;
    };
    
    auto print_alert = delegate(in TLSAlert alert, in ubyte[])
    {
        if (alert.isValid())
            logTrace("TLSServer recvd alert " ~ alert.typeString());
    };
    
    auto save_server_data = delegate(in ubyte[] buf) {
        c2s_data.insert(buf);
    };
    
    auto save_client_data = delegate(in ubyte[] buf) {
        s2c_data.insert(buf);
    };
    
    auto server = new TLSServer((in ubyte[] buf) { s2c_q.insert(buf); },
                                save_server_data,
                                print_alert,
                                handshake_complete,
                                server_sessions,
                                creds,
                                policy,
                                rng,
                                Vector!string(["test/1", "test/2"]));
    
    auto next_protocol_chooser = delegate(const ref Vector!string protos) {
        if (protos.length != 2)
            logTrace("Bad protocol size");
        if (protos[0] != "test/1" || protos[1] != "test/2")
            logTrace("Bad protocol values");
        return "test/3";
    };
    
    auto client = new TLSClient((in ubyte[] buf) { c2s_q.insert(buf); },
                                    save_client_data,
                                    print_alert,
                                    handshake_complete,
                                    client_sessions,
                                    creds,
                                    policy,
                                    rng,
                                    TLSServerInformation(),
                                    offer_version,
                                    next_protocol_chooser);
    
    while(true)
    {
        if (client.isActive())
            client.send("1");
        if (server.isActive())
        {
            if (server.nextProtocol() != "test/3")
                logTrace("Wrong protocol " ~ server.nextProtocol());
            server.send("2");
        }
        
        /*
        * Use this as a temp value to hold the queues as otherwise they
        * might end up appending more in response to messages during the
        * handshake.
        */
        Vector!ubyte input;

        c2s_q.swap(input);
        
        try
        {
            server.receivedData(input.ptr, input.length);
        }
        catch(Exception e)
        {
            logTrace("TLSServer error - " ~ e.msg);
            break;
        }
        
        input.clear();
        s2c_q.swap(input);
        
        try
        {
            client.receivedData(input.ptr, input.length);
        }
        catch(Exception e)
        {
            logTrace("TLSClient error - " ~ e.msg);
            break;
        }
        
        if (c2s_data.length)
        {
            if (c2s_data[0] != '1')
            {
                logTrace("Error");
                return 1;
            }
        }
        
        if (s2c_data.length)
        {
            if (s2c_data[0] != '2')
            {
                logTrace("Error");
                return 1;
            }
        }
        
        if (s2c_data.length && c2s_data.length)
            break;
    }
    
    return 0;
}

class TestPolicy : TLSPolicy
{
public:
    override bool acceptableProtocolVersion(TLSProtocolVersion) const { return true; }
}

static if (!SKIP_TLS_TEST) unittest
{
    logDebug("Testing tls/test.d ...");
    size_t errors = 0;
    
    TestPolicy default_policy = new TestPolicy;
    auto rng = AutoSeededRNG();
    TLSCredentialsManager basic_creds = createCreds(rng);
    
    errors += basicTestHandshake(rng, TLSProtocolVersion(TLSProtocolVersion.SSL_V3), basic_creds, default_policy);
    errors += basicTestHandshake(rng, TLSProtocolVersion(TLSProtocolVersion.TLS_V10), basic_creds, default_policy);
    errors += basicTestHandshake(rng, TLSProtocolVersion(TLSProtocolVersion.TLS_V11), basic_creds, default_policy);
    errors += basicTestHandshake(rng, TLSProtocolVersion(TLSProtocolVersion.TLS_V12), basic_creds, default_policy);
    
    testReport("TLS", 4, errors);

}