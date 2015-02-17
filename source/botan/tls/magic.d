/**
* SSL/TLS Protocol Constants
* 
* Copyright:
* (C) 2004-2010 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.magic;

import botan.constants;
static if (BOTAN_HAS_TLS):
package:

/**
* Protocol Constants for SSL/TLS
*/
alias SizeLimits = size_t;
enum : SizeLimits {
    TLS_HEADER_SIZE     = 5,
    DTLS_HEADER_SIZE    = TLS_HEADER_SIZE + 8,

    MAX_PLAINTEXT_SIZE  = 16*1024,
    MAX_COMPRESSED_SIZE = MAX_PLAINTEXT_SIZE + 1024,
    MAX_CIPHERTEXT_SIZE = MAX_COMPRESSED_SIZE + 1024,
}

alias ConnectionSide = ubyte;
enum : ConnectionSide { CLIENT = 1, SERVER = 2 }

alias RecordType = ubyte;
enum : RecordType {
    NO_RECORD             = 0,

    CHANGE_CIPHER_SPEC    = 20,
    ALERT                 = 21,
    HANDSHAKE             = 22,
    APPLICATION_DATA      = 23,
    HEARTBEAT             = 24,
}

alias HandshakeType = ubyte;
enum : HandshakeType {
    HELLO_REQUEST         = 0,
    CLIENT_HELLO          = 1,
    CLIENT_HELLO_SSLV2    = 253, // Not a wire value
    SERVER_HELLO          = 2,
    HELLO_VERIFY_REQUEST  = 3,
    NEW_SESSION_TICKET    = 4, // RFC 5077
    CERTIFICATE           = 11,
    SERVER_KEX            = 12,
    CERTIFICATE_REQUEST   = 13,
    SERVER_HELLO_DONE     = 14,
    CERTIFICATE_VERIFY    = 15,
    CLIENT_KEX            = 16,
    FINISHED              = 20,

    CERTIFICATE_URL       = 21,
    CERTIFICATE_STATUS    = 22,

    NEXT_PROTOCOL         = 67,

    HANDSHAKE_CCS         = 254, // Not a wire value
    HANDSHAKE_NONE        = 255  // Null value
}

alias CompressionMethod = ubyte;
enum : CompressionMethod {
    NO_COMPRESSION        = 0x00,
    DEFLATE_COMPRESSION   = 0x01
}