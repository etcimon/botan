/**
* GMAC
*
* Copyright:
* (C) 2016 Matthias Gierlings, René Korthaus
* (C) 2017 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.mac.gmac;

import botan.constants;
static if (BOTAN_HAS_GMAC && BOTAN_HAS_AEAD_GCM):

import botan.mac.mac;
import botan.block.block_cipher;
import botan.modes.aead.gcm;
import botan.utils.types;
import botan.utils.exceptn;
import botan.utils.mem_ops;

/**
* GMAC (NIST SP 800-38D). Requires `start(nonce)` before each message.
* SCAN: "GMAC(AES-128)".
*/
final class GMAC : MessageAuthenticationCode, BufferedComputation, SymmetricAlgorithm, MacStart
{
public:
    /**
    * Params:
    *  cipher = 128-bit block cipher (typically AES-128)
    */
    this(BlockCipher cipher)
    {
        if (cipher.blockSize() != BS)
            throw new InvalidArgument("Invalid block cipher " ~ cipher.name ~ " for GMAC");
        m_cipher = cipher;
        m_ghash = new GHASH;
        m_H = SecureVector!ubyte(BS);
    }

    override @property string name() const { return "GMAC(" ~ m_cipher.name ~ ")"; }
    override @property size_t outputLength() const { return BS; }
    override MessageAuthenticationCode clone() const { return new GMAC(m_cipher.clone()); }
    override KeyLengthSpecification keySpec() const { return m_cipher.keySpec(); }

    override void clear()
    {
        m_cipher.clear();
        m_ghash.clear();
        zeroise(m_H);
        m_buf.clear();
        m_initialized = false;
    }

    override void start(const(ubyte)* nonce, size_t nonce_len)
    {
        if (nonce_len == 0)
            throw new InvalidIVLength(name, nonce_len);
        m_nonce = SecureVector!ubyte(nonce[0 .. nonce_len]);
        m_buf.clear();
        m_initialized = true;
    }

protected:
    override void keySchedule(const(ubyte)* key, size_t length)
    {
        clear();
        m_cipher.setKey(key, length);
        zeroise(m_H);
        m_H.resize(BS);
        m_cipher.encrypt(m_H);
        m_ghash.setKey(m_H);
    }

    override void addData(const(ubyte)* input, size_t length)
    {
        if (!m_initialized)
            throw new InvalidState("GMAC was not used with a fresh nonce");
        if (length)
            m_buf ~= input[0 .. length];
    }

    override void finalResult(ubyte* mac)
    {
        if (!m_initialized)
            throw new InvalidState("GMAC was not used with a fresh nonce");

        m_ghash.setAssociatedData(m_buf.ptr, m_buf.length);

        SecureVector!ubyte y0;
        if (m_nonce.length == 12)
        {
            y0 = SecureVector!ubyte(BS);
            y0[0 .. 12] = m_nonce[];
            y0[15] = 1;
        }
        else
            y0 = m_ghash.nonceHash(m_nonce.ptr, m_nonce.length);

        m_cipher.encrypt(y0);
        m_ghash.start(y0.ptr, y0.length);
        auto tag = m_ghash.finished();
        copyMem(mac, tag.ptr, BS);
        m_buf.clear();
        m_initialized = false;
    }

private:
    enum size_t BS = 16;
    Unique!BlockCipher m_cipher;
    Unique!GHASH m_ghash;
    SecureVector!ubyte m_H;
    SecureVector!ubyte m_nonce;
    SecureVector!ubyte m_buf;
    bool m_initialized;
}
