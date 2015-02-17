/**
* TLS Alert Message
* 
* Copyright:
* (C) 2004-2006,2011,2012 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.alert;

import botan.constants;
static if (BOTAN_HAS_TLS):

import memutils.vector;
import botan.utils.exceptn;
import botan.utils.types;
import std.conv : to;

alias ushort TLSAlertType;
/**
* SSL/TLS TLSAlert Message
*/
struct TLSAlert
{
public:
    /**
    * Type codes for TLS alerts
    */
    enum : TLSAlertType {
        CLOSE_NOTIFY                        = 0,
        UNEXPECTED_MESSAGE                  = 10,
        BAD_RECORD_MAC                      = 20,
        DECRYPTION_FAILED                   = 21,
        RECORD_OVERFLOW                     = 22,
        DECOMPRESSION_FAILURE               = 30,
        HANDSHAKE_FAILURE                   = 40,
        NO_CERTIFICATE                      = 41, // SSLv3 only
        BAD_CERTIFICATE                     = 42,
        UNSUPPORTED_CERTIFICATE             = 43,
        CERTIFICATE_REVOKED                 = 44,
        CERTIFICATE_EXPIRED                 = 45,
        CERTIFICATE_UNKNOWN                 = 46,
        ILLEGAL_PARAMETER                   = 47,
        UNKNOWN_CA                          = 48,
        ACCESS_DENIED                       = 49,
        DECODE_ERROR                        = 50,
        DECRYPT_ERROR                       = 51,
        EXPORT_RESTRICTION                  = 60,
        PROTOCOL_VERSION                    = 70,
        INSUFFICIENT_SECURITY               = 71,
        INTERNAL_ERROR                      = 80,
        USER_CANCELED                       = 90,
        NO_RENEGOTIATION                    = 100,
        UNSUPPORTED_EXTENSION               = 110,
        CERTIFICATE_UNOBTAINABLE            = 111,
        UNRECOGNIZED_NAME                   = 112,
        BAD_CERTIFICATE_STATUS_RESPONSE     = 113,
        BAD_CERTIFICATE_HASH_VALUE          = 114,
        UNKNOWN_PSK_IDENTITY                = 115,

        // pseudo alert values
        NULL_ALERT                          = 256,
        HEARTBEAT_PAYLOAD                   = 257
    }

    /**
    * Returns: true iff this alert is non-empty
    */
    bool isValid() const { return (m_type_code != NULL_ALERT); }

    /**
    * Returns: if this alert is a fatal one or not
    */
    bool isFatal() const { return m_fatal; }

    /**
    * Returns: type of alert
    */
    TLSAlertType type() const { return m_type_code; }

    /**
    * Returns: type of alert
    */
    string typeString() const
    {
        final switch(type())
        {
            case CLOSE_NOTIFY:
                return "close_notify";
            case UNEXPECTED_MESSAGE:
                return "unexpected_message";
            case BAD_RECORD_MAC:
                return "bad_record_mac";
            case DECRYPTION_FAILED:
                return "decryption_failed";
            case RECORD_OVERFLOW:
                return "record_overflow";
            case DECOMPRESSION_FAILURE:
                return "decompression_failure";
            case HANDSHAKE_FAILURE:
                return "handshake_failure";
            case NO_CERTIFICATE:
                return "no_certificate";
            case BAD_CERTIFICATE:
                return "bad_certificate";
            case UNSUPPORTED_CERTIFICATE:
                return "unsupported_certificate";
            case CERTIFICATE_REVOKED:
                return "certificate_revoked";
            case CERTIFICATE_EXPIRED:
                return "certificate_expired";
            case CERTIFICATE_UNKNOWN:
                return "certificate_unknown";
            case ILLEGAL_PARAMETER:
                return "illegal_parameter";
            case UNKNOWN_CA:
                return "unknown_ca";
            case ACCESS_DENIED:
                return "access_denied";
            case DECODE_ERROR:
                return "decode_error";
            case DECRYPT_ERROR:
                return "decrypt_error";
            case EXPORT_RESTRICTION:
                return "export_restriction";
            case PROTOCOL_VERSION:
                return "protocol_version";
            case INSUFFICIENT_SECURITY:
                return "insufficient_security";
            case INTERNAL_ERROR:
                return "internal_error";
            case USER_CANCELED:
                return "user_canceled";
            case NO_RENEGOTIATION:
                return "no_renegotiation";
                
            case UNSUPPORTED_EXTENSION:
                return "unsupported_extension";
            case CERTIFICATE_UNOBTAINABLE:
                return "certificate_unobtainable";
            case UNRECOGNIZED_NAME:
                return "unrecognized_name";
            case BAD_CERTIFICATE_STATUS_RESPONSE:
                return "bad_certificate_status_response";
            case BAD_CERTIFICATE_HASH_VALUE:
                return "bad_certificate_hash_value";
            case UNKNOWN_PSK_IDENTITY:
                return "unknown_psk_identity";
                
            case NULL_ALERT:
                return "none";
                
            case HEARTBEAT_PAYLOAD:
                return "heartbeat_payload";
        }

    }

    /**
    * Serialize an alert
    */
    Vector!ubyte serialize() const
    {
        return Vector!ubyte([
            cast(ubyte)(isFatal() ? 2 : 1),
            cast(ubyte)(type())
        ]);
    }

    /**
    * Deserialize an TLSAlert message
    * Params:
    *  buf = the serialized alert
    */
    this(const ref SecureVector!ubyte buf)
    {
        if (buf.length != 2)
            throw new DecodingError("TLSAlert: Bad size " ~ to!string(buf.length) ~ " for alert message");
        
        if (buf[0] == 1)          m_fatal = false;
        else if (buf[0] == 2)     m_fatal = true;
        else
            throw new DecodingError("TLSAlert: Bad code for alert level");
        
        const ubyte dc = buf[1];
        
        m_type_code = cast(TLSAlertType)(dc);
    }

    /**
    * Create a new TLSAlert
    * Params:
    *  type_code = the type of alert
    *  fatal = specifies if this is a fatal alert
    */
    this(TLSAlertType type_code = NULL_ALERT, bool fatal = false)
    {
        m_fatal = fatal;
        m_type_code = type_code;
    }

private:
    bool m_fatal;
    TLSAlertType m_type_code;
}