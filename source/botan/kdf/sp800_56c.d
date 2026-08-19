/**
* NIST SP 800-56C r2 Two-Step KDF
*
* Copyright:
* (C) 2016 Kai Michaelis
* (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.kdf.sp800_56c;

import botan.constants;
static if (BOTAN_HAS_SP800_56C && BOTAN_HAS_SP800_108):

import botan.kdf.kdf;
import botan.mac.mac;
import botan.utils.types;

/**
* Two-step KDF: HMAC extract then SP 800-108 Feedback expand.
* SCAN: "SP800-56C(HMAC(SHA-256))"
*/
final class SP800_56C_TwoStep : KDF
{
    /**
    * Params:
    *  mac = HMAC used for extract
    *  exp = SP 800-108 expander
    */
    this(MessageAuthenticationCode mac, KDF exp)
    {
        m_prf = mac;
        m_exp = exp;
    }

    override @property string name() const { return "SP800-56C(" ~ m_prf.name ~ ")"; }
    override KDF clone() const { return new SP800_56C_TwoStep(m_prf.clone(), m_exp.clone()); }

    override SecureVector!ubyte derive(size_t key_len,
                                       const(ubyte)* secret, size_t secret_len,
                                       const(ubyte)* salt, size_t salt_len) const
    {
        return derive(key_len, secret, secret_len, salt, salt_len, null, 0);
    }

    override SecureVector!ubyte derive(size_t key_len,
                                       const(ubyte)* secret, size_t secret_len,
                                       const(ubyte)* salt, size_t salt_len,
                                       const(ubyte)* label, size_t label_len) const
    {
        auto prf = cast(MessageAuthenticationCode)*m_prf;
        prf.setKey(salt, salt_len);
        if (secret_len)
            prf.update(secret, secret_len);
        auto k_dk = prf.finished();
        return m_exp.deriveKey(key_len, k_dk.ptr, k_dk.length, null, 0, label, label_len);
    }

private:
    Unique!MessageAuthenticationCode m_prf;
    Unique!KDF m_exp;
}
