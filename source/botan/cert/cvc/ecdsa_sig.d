/**
* ECDSA Signature
* 
* Copyright:
* (C) 2007 Falko Strenzke, FlexSecure GmbH
* (C) 2008-2010 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.cert.cvc.ecdsa_sig;

import botan.constants;
static if (BOTAN_HAS_CARD_VERIFIABLE_CERTIFICATES):

import botan.math.bigint.bigint;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.utils.mem_ops;

/**
* Class representing an ECDSA signature
*/
class ECDSASignature
{
public:
    this() {}

    this()(auto const ref BigInt r, auto const ref BigInt s) {
        m_r = r.dup;
        m_s = s.dup;
    }

    this(const ref Vector!ubyte ber)
    {
        BERDecoder(ber)
                .startCons(ASN1Tag.SEQUENCE)
                .decode(m_r)
                .decode(m_s)
                .endCons()
                .verifyEnd();
    }

    @property ECDSASignature dup() const
    {
        return new ECDSASignature(m_r.dup, m_s.dup);
    }

    ref const(BigInt) getR() const { return m_r; }
    ref const(BigInt) getS() const { return m_s; }

    /**
    * return the r||s
    */
    const(Vector!ubyte) getConcatenation() const
    {
        // use the larger
        const size_t enc_len = m_r > m_s ? m_r.bytes() : m_s.bytes();
        
        
        SecureVector!ubyte result = BigInt.encode1363(m_r, enc_len);
        result ~= BigInt.encode1363(m_s, enc_len);
        return unlock(result);
    }

    Vector!ubyte DER_encode() const
    {
        return DEREncoder()
                .startCons(ASN1Tag.SEQUENCE)
                .encode(getR())
                .encode(getS())
                .endCons()
                .getContentsUnlocked();
    }


    bool opEquals(in ECDSASignature other) const
    {
        return (getR() == other.getR() && getS() == other.getS());
    }

    int opCmp(in ECDSASignature rhs) const
    {
        if (this == rhs) return 0;
        else return -1;
    }

private:
    BigInt m_r;
    BigInt m_s;
}

ECDSASignature decodeConcatenation(const ref Vector!ubyte concat)
{
    if (concat.length % 2 != 0)
        throw new InvalidArgument("Erroneous length of signature");
    
    const size_t rs_len = concat.length / 2;
    
    BigInt r = BigInt.decode(concat.ptr, rs_len);
    BigInt s = BigInt.decode(&concat[rs_len], rs_len);
    
    return new ECDSASignature(r, s);
}