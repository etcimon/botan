/**
* X9.42 PRF
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.kdf.prf_x942;

import botan.constants;
static if (BOTAN_HAS_TLS || BOTAN_HAS_PUBLIC_KEY_CRYPTO):

import botan.kdf.kdf;
import botan.asn1.der_enc;
import botan.asn1.oids;
import botan.hash.sha160;
import botan.utils.loadstor;
import std.algorithm;
import botan.utils.types;

/**
* PRF from ANSI X9.42
*/
class X942PRF : KDF
{
public:
    /*
    * X9.42 PRF
    */
    override SecureVector!ubyte derive(size_t key_len,
                                       const(ubyte)* secret, size_t secret_len,
                                       const(ubyte)* salt, size_t salt_len) const
    {
        auto hash = scoped!SHA160();
        const OID kek_algo = OID(m_key_wrap_oid);
        
        SecureVector!ubyte key;
        uint counter = 1;
        
        while (key.length != key_len && counter)
        {
            hash.update(secret, secret_len);
            
            hash.update(
                DEREncoder().startCons(ASN1Tag.SEQUENCE)
                            .startCons(ASN1Tag.SEQUENCE)
                            .encode(kek_algo)
                            .rawBytes(encodeX942Int(counter))
                            .endCons()
                            
                            .encodeIf (salt_len != 0,
                                    DEREncoder()
                                    .startExplicit(0)
                                    .encode(salt, salt_len, ASN1Tag.OCTET_STRING)
                                    .endExplicit()
                                    )
                            
                            .startExplicit(2)
                            .rawBytes(encodeX942Int(cast(uint)(8 * key_len)))
                            .endExplicit()
                            
                            .endCons().getContents()
                );
            
            SecureVector!ubyte digest = hash.finished();
            const size_t needed = std.algorithm.min(digest.length, key_len - key.length);
            key ~= digest.ptr[0 .. needed];
            
            ++counter;
        }
        
        return key;
    }


    override @property string name() const { return "X942_PRF(" ~ m_key_wrap_oid ~ ")"; }
    override KDF clone() const { return new X942PRF(m_key_wrap_oid); }
    /*
    * X9.42 Constructor
    */
    this(in string oid)
    {
        if (OIDS.haveOid(oid))
            m_key_wrap_oid = OIDS.lookup(oid).toString();
        else
            m_key_wrap_oid = oid;
    }
private:
    string m_key_wrap_oid;
}

private:

/*
* Encode an integer as an OCTET STRING
*/
Vector!ubyte encodeX942Int(uint n)
{
    ubyte[4] n_buf;
    storeBigEndian(n, &n_buf);
    return DEREncoder().encode(n_buf.ptr, 4, ASN1Tag.OCTET_STRING).getContentsUnlocked();
}