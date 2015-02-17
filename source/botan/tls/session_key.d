/**
* TLS Session Key
* 
* Copyright:
* (C) 2004-2006,2011 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.session_key;

import botan.constants;
static if (BOTAN_HAS_TLS):
package:

import botan.algo_base.symkey;
import botan.tls.handshake_state;
import botan.tls.messages;

/**
* TLS TLSSession Keys
*/
struct TLSSessionKeys
{
public:
    const(SymmetricKey) clientCipherKey() const { return m_c_cipher; }
    const(SymmetricKey) serverCipherKey() const { return m_s_cipher; }

    const(SymmetricKey) clientMacKey() const { return m_c_mac; }
    const(SymmetricKey) serverMacKey() const { return m_s_mac; }

    const(InitializationVector) clientIv() const { return m_c_iv; }
    const(InitializationVector) serverIv() const { return m_s_iv; }

    ref const(SecureVector!ubyte) masterSecret() const { return m_master_sec; }

    @disable this();

    /**
    * TLSSessionKeys Constructor
    */
    this()(in HandshakeState state, auto ref SecureVector!ubyte pre_master_secret, bool resuming)
    {
        const size_t cipher_keylen = state.ciphersuite().cipherKeylen();
        const size_t mac_keylen = state.ciphersuite().macKeylen();
        const size_t cipher_ivlen = state.ciphersuite().cipherIvlen();
        
        const size_t prf_gen = 2 * (mac_keylen + cipher_keylen + cipher_ivlen);
        
        __gshared immutable immutable(ubyte)[] MASTER_SECRET_MAGIC = [
            0x6D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74 ];
        
        __gshared immutable immutable(ubyte)[] KEY_GEN_MAGIC = [
            0x6B, 0x65, 0x79, 0x20, 0x65, 0x78, 0x70, 0x61, 0x6E, 0x73, 0x69, 0x6F, 0x6E ];
        
        Unique!KDF prf = state.protocolSpecificPrf();
        
        if (resuming)
        {
            m_master_sec = pre_master_secret.dup;
        }
        else
        {
            SecureVector!ubyte salt;
            
            if (state.Version() != TLSProtocolVersion.SSL_V3)
                salt ~= cast(ubyte[])MASTER_SECRET_MAGIC;
            
            salt ~= state.clientHello().random()[];
            salt ~= state.serverHello().random()[];
            
            m_master_sec = prf.deriveKey(48, pre_master_secret, salt);
        }
        
        SecureVector!ubyte salt;
        if (state.Version() != TLSProtocolVersion.SSL_V3)
            salt ~= cast(ubyte[])KEY_GEN_MAGIC;
        salt ~= state.serverHello().random()[];
        salt ~= state.clientHello().random()[];
        
        SymmetricKey keyblock = prf.deriveKey(prf_gen, m_master_sec, salt);
        
        const(ubyte)* key_data = keyblock.ptr;
        
        m_c_mac = SymmetricKey(key_data, mac_keylen);
        key_data += mac_keylen;
        
        m_s_mac = SymmetricKey(key_data, mac_keylen);
        key_data += mac_keylen;
        
        m_c_cipher = SymmetricKey(key_data, cipher_keylen);
        key_data += cipher_keylen;
        
        m_s_cipher = SymmetricKey(key_data, cipher_keylen);
        key_data += cipher_keylen;
        
        m_c_iv = InitializationVector(key_data, cipher_ivlen);
        key_data += cipher_ivlen;
        
        m_s_iv = InitializationVector(key_data, cipher_ivlen);
    }

private:
    SecureVector!ubyte m_master_sec;
    SymmetricKey m_c_cipher, m_s_cipher, m_c_mac, m_s_mac;
    InitializationVector m_c_iv, m_s_iv;
}