/**
* CRL Entry
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.cert.x509.crl_ent;

import botan.constants;
static if (BOTAN_HAS_X509_CERTIFICATES):

import botan.cert.x509.x509cert;
import botan.asn1.asn1_time;
import botan.cert.x509.x509_ext;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.math.bigint.bigint;
import botan.asn1.oids;
import botan.utils.types;
import std.datetime;

alias CRLEntry = RefCounted!CRLEntryImpl;

alias CRLCode = uint;
/**
* X.509v2 CRL Reason Code.
*/
enum : CRLCode {
    UNSPECIFIED             = 0,
    KEY_COMPROMISE          = 1,
    CA_COMPROMISE           = 2,
    AFFILIATION_CHANGED     = 3,
    SUPERSEDED              = 4,
    CESSATION_OF_OPERATION  = 5,
    CERTIFICATE_HOLD        = 6,
    REMOVE_FROM_CRL         = 8,
    PRIVLEDGE_WITHDRAWN     = 9,
    AA_COMPROMISE           = 10,

    DELETE_CRL_ENTRY        = 0xFF00,
    OCSP_GOOD               = 0xFF01,
    OCSP_UNKNOWN            = 0xFF02
}

/**
* This class represents CRL entries
*/
final class CRLEntryImpl : ASN1Object
{
public:
    /*
    * DER encode a CRLEntry
    */
    override void encodeInto(ref DEREncoder to_) const
    {
        X509Extensions extensions;
        
        extensions.add(new CRLReasonCode(m_reason));
        
        to_.startCons(ASN1Tag.SEQUENCE)
                .encode(BigInt.decode(m_serial))
                .encode(m_time)
                .startCons(ASN1Tag.SEQUENCE)
                .encode(extensions)
                .endCons()
                .endCons();
    }
    

    /*
    * Decode a BER encoded CRLEntry
    */
    override void decodeFrom(ref BERDecoder source)
    {
        BigInt serial_number_bn;
        m_reason = UNSPECIFIED;
        
        BERDecoder entry = source.startCons(ASN1Tag.SEQUENCE);

        entry.decode(serial_number_bn).decode(m_time);
        
        if (entry.moreItems())
        {
            X509Extensions extensions = X509Extensions(m_throw_on_unknown_critical);
            entry.decode(extensions);
            DataStore info;
            extensions.contentsTo(info, info);
            m_reason = cast(CRLCode)(info.get1Uint("X509v3.CRLReasonCode"));
        }

        entry.endCons();
        
        m_serial = BigInt.encode(serial_number_bn);
    }

    /**
    * Get the serial number of the certificate associated with this entry.
    * Returns: certificate's serial number
    */
    ref const(Vector!ubyte) serialNumber() const { return m_serial; }

    /**
    * Get the revocation date of the certificate associated with this entry
    * Returns: certificate's revocation date
    */
    const(X509Time) expireTime() const { return m_time; }

    /**
    * Get the entries reason code
    * Returns: reason code
    */
    CRLCode reasonCode() const { return m_reason; }

    /**
    * Construct an empty CRL entry.
    */
    this(bool throw_on_unknown_critical_extension)
    {
        m_throw_on_unknown_critical = throw_on_unknown_critical_extension;
        m_reason = UNSPECIFIED;
    }

    /**
    * Construct an CRL entry.
    *
    * Params:
    *  cert = the certificate to revoke
    *  reason = the reason code to set in the entry
    */
    this(in X509CertificateImpl cert, CRLCode why = UNSPECIFIED)
    {
        m_throw_on_unknown_critical = false;
        m_serial = cert.serialNumber().dup;
        m_time = X509Time(Clock.currTime());
        m_reason = why;
    }

    /*
    * Compare two CRL_Entrys for equality
    */
    bool opEquals(in CRLEntry a2) const
    {
        if (serialNumber() != a2.serialNumber())
            return false;
        if (expireTime() != a2.expireTime())
            return false;
        if (reasonCode() != a2.reasonCode())
            return false;
        return true;
    }

    /*
    * Compare two CRL_Entrys for inequality
    */
    int opCmp(in CRLEntry a2) const
    {
        if (this == a2) return 0;
        else return -1;
    }


private:
    bool m_throw_on_unknown_critical;
    Vector!ubyte m_serial;
    X509Time m_time;
    CRLCode m_reason;
}