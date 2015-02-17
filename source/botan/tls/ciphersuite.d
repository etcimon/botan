/**
* TLS Cipher Suites
* 
* Copyright:
* (C) 2004-2011,2012 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.ciphersuite;

import botan.constants;
static if (BOTAN_HAS_TLS):

import botan.utils.types;
import botan.libstate.libstate;
import botan.utils.parsing;
import std.array : Appender;
import std.exception;

/**
* TLSCiphersuite Information
*/
struct TLSCiphersuite
{
public:
    /**
    * Convert an SSL/TLS ciphersuite to algorithm fields
    * Params:
    *  suite = the ciphersuite code number
    * Returns: ciphersuite object
    */
    static TLSCiphersuite byId(ushort suite)
    {
        switch(suite)
        {
            case 0x0013: // DHE_DSS_WITH_3DES_EDE_CBC_SHA
                return TLSCiphersuite(0x0013, "DSA", "DH", "3DES", 24, 8, "SHA-1", 20);
                
            case 0x0032: // DHE_DSS_WITH_AES_128_CBC_SHA
                return TLSCiphersuite(0x0032, "DSA", "DH", "AES-128", 16, 16, "SHA-1", 20);
                
            case 0x0040: // DHE_DSS_WITH_AES_128_CBC_SHA256
                return TLSCiphersuite(0x0040, "DSA", "DH", "AES-128", 16, 16, "SHA-256", 32);
                
            case 0x00A2: // DHE_DSS_WITH_AES_128_GCM_SHA256
                return TLSCiphersuite(0x00A2, "DSA", "DH", "AES-128/GCM", 16, 4, "AEAD", 0, "SHA-256");
                
            case 0x0038: // DHE_DSS_WITH_AES_256_CBC_SHA
                return TLSCiphersuite(0x0038, "DSA", "DH", "AES-256", 32, 16, "SHA-1", 20);
                
            case 0x006A: // DHE_DSS_WITH_AES_256_CBC_SHA256
                return TLSCiphersuite(0x006A, "DSA", "DH", "AES-256", 32, 16, "SHA-256", 32);
                
            case 0x00A3: // DHE_DSS_WITH_AES_256_GCM_SHA384
                return TLSCiphersuite(0x00A3, "DSA", "DH", "AES-256/GCM", 32, 4, "AEAD", 0, "SHA-384");
                
            case 0x0044: // DHE_DSS_WITH_CAMELLIA_128_CBC_SHA
                return TLSCiphersuite(0x0044, "DSA", "DH", "Camellia-128", 16, 16, "SHA-1", 20);
                
            case 0x00BD: // DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256
                return TLSCiphersuite(0x00BD, "DSA", "DH", "Camellia-128", 16, 16, "SHA-256", 32);
                
            case 0xC080: // DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256
                return TLSCiphersuite(0xC080, "DSA", "DH", "Camellia-128/GCM", 16, 4, "AEAD", 0, "SHA-256");
                
            case 0x0087: // DHE_DSS_WITH_CAMELLIA_256_CBC_SHA
                return TLSCiphersuite(0x0087, "DSA", "DH", "Camellia-256", 32, 16, "SHA-1", 20);
                
            case 0x00C3: // DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256
                return TLSCiphersuite(0x00C3, "DSA", "DH", "Camellia-256", 32, 16, "SHA-256", 32);
                
            case 0xC081: // DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384
                return TLSCiphersuite(0xC081, "DSA", "DH", "Camellia-256/GCM", 32, 4, "AEAD", 0, "SHA-384");
                
            case 0x0066: // DHE_DSS_WITH_RC4_128_SHA
                return TLSCiphersuite(0x0066, "DSA", "DH", "RC4", 16, 0, "SHA-1", 20);
                
            case 0x0099: // DHE_DSS_WITH_SEED_CBC_SHA
                return TLSCiphersuite(0x0099, "DSA", "DH", "SEED", 16, 16, "SHA-1", 20);
                
            case 0x008F: // DHE_PSK_WITH_3DES_EDE_CBC_SHA
                return TLSCiphersuite(0x008F, "", "DHE_PSK", "3DES", 24, 8, "SHA-1", 20);
                
            case 0x0090: // DHE_PSK_WITH_AES_128_CBC_SHA
                return TLSCiphersuite(0x0090, "", "DHE_PSK", "AES-128", 16, 16, "SHA-1", 20);
                
            case 0x00B2: // DHE_PSK_WITH_AES_128_CBC_SHA256
                return TLSCiphersuite(0x00B2, "", "DHE_PSK", "AES-128", 16, 16, "SHA-256", 32);
                
            case 0xC0A6: // DHE_PSK_WITH_AES_128_CCM
                return TLSCiphersuite(0xC0A6, "", "DHE_PSK", "AES-128/CCM", 16, 4, "AEAD", 0, "SHA-256");
                
            case 0x00AA: // DHE_PSK_WITH_AES_128_GCM_SHA256
                return TLSCiphersuite(0x00AA, "", "DHE_PSK", "AES-128/GCM", 16, 4, "AEAD", 0, "SHA-256");
                
            case 0x0091: // DHE_PSK_WITH_AES_256_CBC_SHA
                return TLSCiphersuite(0x0091, "", "DHE_PSK", "AES-256", 32, 16, "SHA-1", 20);
                
            case 0x00B3: // DHE_PSK_WITH_AES_256_CBC_SHA384
                return TLSCiphersuite(0x00B3, "", "DHE_PSK", "AES-256", 32, 16, "SHA-384", 48);
                
            case 0xC0A7: // DHE_PSK_WITH_AES_256_CCM
                return TLSCiphersuite(0xC0A7, "", "DHE_PSK", "AES-256/CCM", 32, 4, "AEAD", 0, "SHA-256");
                
            case 0x00AB: // DHE_PSK_WITH_AES_256_GCM_SHA384
                return TLSCiphersuite(0x00AB, "", "DHE_PSK", "AES-256/GCM", 32, 4, "AEAD", 0, "SHA-384");
                
            case 0xC096: // DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
                return TLSCiphersuite(0xC096, "", "DHE_PSK", "Camellia-128", 16, 16, "SHA-256", 32);
                
            case 0xC090: // DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256
                return TLSCiphersuite(0xC090, "", "DHE_PSK", "Camellia-128/GCM", 16, 4, "AEAD", 0, "SHA-256");
                
            case 0xC097: // DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
                return TLSCiphersuite(0xC097, "", "DHE_PSK", "Camellia-256", 32, 16, "SHA-384", 48);
                
            case 0xC091: // DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384
                return TLSCiphersuite(0xC091, "", "DHE_PSK", "Camellia-256/GCM", 32, 4, "AEAD", 0, "SHA-384");
                
            case 0x008E: // DHE_PSK_WITH_RC4_128_SHA
                return TLSCiphersuite(0x008E, "", "DHE_PSK", "RC4", 16, 0, "SHA-1", 20);
                
            case 0x0016: // DHE_RSA_WITH_3DES_EDE_CBC_SHA
                return TLSCiphersuite(0x0016, "RSA", "DH", "3DES", 24, 8, "SHA-1", 20);
                
            case 0x0033: // DHE_RSA_WITH_AES_128_CBC_SHA
                return TLSCiphersuite(0x0033, "RSA", "DH", "AES-128", 16, 16, "SHA-1", 20);
                
            case 0x0067: // DHE_RSA_WITH_AES_128_CBC_SHA256
                return TLSCiphersuite(0x0067, "RSA", "DH", "AES-128", 16, 16, "SHA-256", 32);
                
            case 0xC09E: // DHE_RSA_WITH_AES_128_CCM
                return TLSCiphersuite(0xC09E, "RSA", "DH", "AES-128/CCM", 16, 4, "AEAD", 0, "SHA-256");
                
            case 0xC0A2: // DHE_RSA_WITH_AES_128_CCM_8
                return TLSCiphersuite(0xC0A2, "RSA", "DH", "AES-128/CCM-8", 16, 4, "AEAD", 0, "SHA-256");
                
            case 0x009E: // DHE_RSA_WITH_AES_128_GCM_SHA256
                return TLSCiphersuite(0x009E, "RSA", "DH", "AES-128/GCM", 16, 4, "AEAD", 0, "SHA-256");
                
            case 0x0039: // DHE_RSA_WITH_AES_256_CBC_SHA
                return TLSCiphersuite(0x0039, "RSA", "DH", "AES-256", 32, 16, "SHA-1", 20);
                
            case 0x006B: // DHE_RSA_WITH_AES_256_CBC_SHA256
                return TLSCiphersuite(0x006B, "RSA", "DH", "AES-256", 32, 16, "SHA-256", 32);
                
            case 0xC09F: // DHE_RSA_WITH_AES_256_CCM
                return TLSCiphersuite(0xC09F, "RSA", "DH", "AES-256/CCM", 32, 4, "AEAD", 0, "SHA-256");
                
            case 0xC0A3: // DHE_RSA_WITH_AES_256_CCM_8
                return TLSCiphersuite(0xC0A3, "RSA", "DH", "AES-256/CCM-8", 32, 4, "AEAD", 0, "SHA-256");
                
            case 0x009F: // DHE_RSA_WITH_AES_256_GCM_SHA384
                return TLSCiphersuite(0x009F, "RSA", "DH", "AES-256/GCM", 32, 4, "AEAD", 0, "SHA-384");
                
            case 0x0045: // DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
                return TLSCiphersuite(0x0045, "RSA", "DH", "Camellia-128", 16, 16, "SHA-1", 20);
                
            case 0x00BE: // DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
                return TLSCiphersuite(0x00BE, "RSA", "DH", "Camellia-128", 16, 16, "SHA-256", 32);
                
            case 0xC07C: // DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256
                return TLSCiphersuite(0xC07C, "RSA", "DH", "Camellia-128/GCM", 16, 4, "AEAD", 0, "SHA-256");
                
            case 0x0088: // DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
                return TLSCiphersuite(0x0088, "RSA", "DH", "Camellia-256", 32, 16, "SHA-1", 20);
                
            case 0x00C4: // DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256
                return TLSCiphersuite(0x00C4, "RSA", "DH", "Camellia-256", 32, 16, "SHA-256", 32);
                
            case 0xC07D: // DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384
                return TLSCiphersuite(0xC07D, "RSA", "DH", "Camellia-256/GCM", 32, 4, "AEAD", 0, "SHA-384");
                
            case 0x009A: // DHE_RSA_WITH_SEED_CBC_SHA
                return TLSCiphersuite(0x009A, "RSA", "DH", "SEED", 16, 16, "SHA-1", 20);
                
            case 0x001B: // DH_anon_WITH_3DES_EDE_CBC_SHA
                return TLSCiphersuite(0x001B, "", "DH", "3DES", 24, 8, "SHA-1", 20);
                
            case 0x0034: // DH_anon_WITH_AES_128_CBC_SHA
                return TLSCiphersuite(0x0034, "", "DH", "AES-128", 16, 16, "SHA-1", 20);
                
            case 0x006C: // DH_anon_WITH_AES_128_CBC_SHA256
                return TLSCiphersuite(0x006C, "", "DH", "AES-128", 16, 16, "SHA-256", 32);
                
            case 0x00A6: // DH_anon_WITH_AES_128_GCM_SHA256
                return TLSCiphersuite(0x00A6, "", "DH", "AES-128/GCM", 16, 4, "AEAD", 0, "SHA-256");
                
            case 0x003A: // DH_anon_WITH_AES_256_CBC_SHA
                return TLSCiphersuite(0x003A, "", "DH", "AES-256", 32, 16, "SHA-1", 20);
                
            case 0x006D: // DH_anon_WITH_AES_256_CBC_SHA256
                return TLSCiphersuite(0x006D, "", "DH", "AES-256", 32, 16, "SHA-256", 32);
                
            case 0x00A7: // DH_anon_WITH_AES_256_GCM_SHA384
                return TLSCiphersuite(0x00A7, "", "DH", "AES-256/GCM", 32, 4, "AEAD", 0, "SHA-384");
                
            case 0x0046: // DH_anon_WITH_CAMELLIA_128_CBC_SHA
                return TLSCiphersuite(0x0046, "", "DH", "Camellia-128", 16, 16, "SHA-1", 20);
                
            case 0x00BF: // DH_anon_WITH_CAMELLIA_128_CBC_SHA256
                return TLSCiphersuite(0x00BF, "", "DH", "Camellia-128", 16, 16, "SHA-256", 32);
                
            case 0xC084: // DH_anon_WITH_CAMELLIA_128_GCM_SHA256
                return TLSCiphersuite(0xC084, "", "DH", "Camellia-128/GCM", 16, 4, "AEAD", 0, "SHA-256");
                
            case 0x0089: // DH_anon_WITH_CAMELLIA_256_CBC_SHA
                return TLSCiphersuite(0x0089, "", "DH", "Camellia-256", 32, 16, "SHA-1", 20);
                
            case 0x00C5: // DH_anon_WITH_CAMELLIA_256_CBC_SHA256
                return TLSCiphersuite(0x00C5, "", "DH", "Camellia-256", 32, 16, "SHA-256", 32);
                
            case 0xC085: // DH_anon_WITH_CAMELLIA_256_GCM_SHA384
                return TLSCiphersuite(0xC085, "", "DH", "Camellia-256/GCM", 32, 4, "AEAD", 0, "SHA-384");
                
            case 0x0018: // DH_anon_WITH_RC4_128_MD5
                return TLSCiphersuite(0x0018, "", "DH", "RC4", 16, 0, "MD5", 16);
                
            case 0x009B: // DH_anon_WITH_SEED_CBC_SHA
                return TLSCiphersuite(0x009B, "", "DH", "SEED", 16, 16, "SHA-1", 20);
                
            case 0xC008: // ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
                return TLSCiphersuite(0xC008, "ECDSA", "ECDH", "3DES", 24, 8, "SHA-1", 20);
                
            case 0xC009: // ECDHE_ECDSA_WITH_AES_128_CBC_SHA
                return TLSCiphersuite(0xC009, "ECDSA", "ECDH", "AES-128", 16, 16, "SHA-1", 20);
                
            case 0xC023: // ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
                return TLSCiphersuite(0xC023, "ECDSA", "ECDH", "AES-128", 16, 16, "SHA-256", 32);
                
            case 0xC0AC: // ECDHE_ECDSA_WITH_AES_128_CCM
                return TLSCiphersuite(0xC0AC, "ECDSA", "ECDH", "AES-128/CCM", 16, 4, "AEAD", 0, "SHA-256");
                
            case 0xC0AE: // ECDHE_ECDSA_WITH_AES_128_CCM_8
                return TLSCiphersuite(0xC0AE, "ECDSA", "ECDH", "AES-128/CCM-8", 16, 4, "AEAD", 0, "SHA-256");
                
            case 0xC02B: // ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                return TLSCiphersuite(0xC02B, "ECDSA", "ECDH", "AES-128/GCM", 16, 4, "AEAD", 0, "SHA-256");
                
            case 0xC00A: // ECDHE_ECDSA_WITH_AES_256_CBC_SHA
                return TLSCiphersuite(0xC00A, "ECDSA", "ECDH", "AES-256", 32, 16, "SHA-1", 20);
                
            case 0xC024: // ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
                return TLSCiphersuite(0xC024, "ECDSA", "ECDH", "AES-256", 32, 16, "SHA-384", 48);
                
            case 0xC0AD: // ECDHE_ECDSA_WITH_AES_256_CCM
                return TLSCiphersuite(0xC0AD, "ECDSA", "ECDH", "AES-256/CCM", 32, 4, "AEAD", 0, "SHA-256");
                
            case 0xC0AF: // ECDHE_ECDSA_WITH_AES_256_CCM_8
                return TLSCiphersuite(0xC0AF, "ECDSA", "ECDH", "AES-256/CCM-8", 32, 4, "AEAD", 0, "SHA-256");
                
            case 0xC02C: // ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                return TLSCiphersuite(0xC02C, "ECDSA", "ECDH", "AES-256/GCM", 32, 4, "AEAD", 0, "SHA-384");
                
            case 0xC072: // ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
                return TLSCiphersuite(0xC072, "ECDSA", "ECDH", "Camellia-128", 16, 16, "SHA-256", 32);
                
            case 0xC086: // ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256
                return TLSCiphersuite(0xC086, "ECDSA", "ECDH", "Camellia-128/GCM", 16, 4, "AEAD", 0, "SHA-256");
                
            case 0xC073: // ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
                return TLSCiphersuite(0xC073, "ECDSA", "ECDH", "Camellia-256", 32, 16, "SHA-384", 48);
                
            case 0xC087: // ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384
                return TLSCiphersuite(0xC087, "ECDSA", "ECDH", "Camellia-256/GCM", 32, 4, "AEAD", 0, "SHA-384");
                
            case 0xC007: // ECDHE_ECDSA_WITH_RC4_128_SHA
                return TLSCiphersuite(0xC007, "ECDSA", "ECDH", "RC4", 16, 0, "SHA-1", 20);
                
            case 0xC034: // ECDHE_PSK_WITH_3DES_EDE_CBC_SHA
                return TLSCiphersuite(0xC034, "", "ECDHE_PSK", "3DES", 24, 8, "SHA-1", 20);
                
            case 0xC035: // ECDHE_PSK_WITH_AES_128_CBC_SHA
                return TLSCiphersuite(0xC035, "", "ECDHE_PSK", "AES-128", 16, 16, "SHA-1", 20);
                
            case 0xC037: // ECDHE_PSK_WITH_AES_128_CBC_SHA256
                return TLSCiphersuite(0xC037, "", "ECDHE_PSK", "AES-128", 16, 16, "SHA-256", 32);
                
            case 0xC036: // ECDHE_PSK_WITH_AES_256_CBC_SHA
                return TLSCiphersuite(0xC036, "", "ECDHE_PSK", "AES-256", 32, 16, "SHA-1", 20);
                
            case 0xC038: // ECDHE_PSK_WITH_AES_256_CBC_SHA384
                return TLSCiphersuite(0xC038, "", "ECDHE_PSK", "AES-256", 32, 16, "SHA-384", 48);
                
            case 0xC09A: // ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
                return TLSCiphersuite(0xC09A, "", "ECDHE_PSK", "Camellia-128", 16, 16, "SHA-256", 32);
                
            case 0xC09B: // ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
                return TLSCiphersuite(0xC09B, "", "ECDHE_PSK", "Camellia-256", 32, 16, "SHA-384", 48);
                
            case 0xC033: // ECDHE_PSK_WITH_RC4_128_SHA
                return TLSCiphersuite(0xC033, "", "ECDHE_PSK", "RC4", 16, 0, "SHA-1", 20);
                
            case 0xC012: // ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
                return TLSCiphersuite(0xC012, "RSA", "ECDH", "3DES", 24, 8, "SHA-1", 20);
                
            case 0xC013: // ECDHE_RSA_WITH_AES_128_CBC_SHA
                return TLSCiphersuite(0xC013, "RSA", "ECDH", "AES-128", 16, 16, "SHA-1", 20);
                
            case 0xC027: // ECDHE_RSA_WITH_AES_128_CBC_SHA256
                return TLSCiphersuite(0xC027, "RSA", "ECDH", "AES-128", 16, 16, "SHA-256", 32);
                
            case 0xC02F: // ECDHE_RSA_WITH_AES_128_GCM_SHA256
                return TLSCiphersuite(0xC02F, "RSA", "ECDH", "AES-128/GCM", 16, 4, "AEAD", 0, "SHA-256");
                
            case 0xC014: // ECDHE_RSA_WITH_AES_256_CBC_SHA
                return TLSCiphersuite(0xC014, "RSA", "ECDH", "AES-256", 32, 16, "SHA-1", 20);
                
            case 0xC028: // ECDHE_RSA_WITH_AES_256_CBC_SHA384
                return TLSCiphersuite(0xC028, "RSA", "ECDH", "AES-256", 32, 16, "SHA-384", 48);
                
            case 0xC030: // ECDHE_RSA_WITH_AES_256_GCM_SHA384
                return TLSCiphersuite(0xC030, "RSA", "ECDH", "AES-256/GCM", 32, 4, "AEAD", 0, "SHA-384");
                
            case 0xC076: // ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
                return TLSCiphersuite(0xC076, "RSA", "ECDH", "Camellia-128", 16, 16, "SHA-256", 32);
                
            case 0xC08A: // ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256
                return TLSCiphersuite(0xC08A, "RSA", "ECDH", "Camellia-128/GCM", 16, 4, "AEAD", 0, "SHA-256");
                
            case 0xC077: // ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384
                return TLSCiphersuite(0xC077, "RSA", "ECDH", "Camellia-256", 32, 16, "SHA-384", 48);
                
            case 0xC08B: // ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384
                return TLSCiphersuite(0xC08B, "RSA", "ECDH", "Camellia-256/GCM", 32, 4, "AEAD", 0, "SHA-384");
                
            case 0xC011: // ECDHE_RSA_WITH_RC4_128_SHA
                return TLSCiphersuite(0xC011, "RSA", "ECDH", "RC4", 16, 0, "SHA-1", 20);
                
            case 0xC017: // ECDH_anon_WITH_3DES_EDE_CBC_SHA
                return TLSCiphersuite(0xC017, "", "ECDH", "3DES", 24, 8, "SHA-1", 20);
                
            case 0xC018: // ECDH_anon_WITH_AES_128_CBC_SHA
                return TLSCiphersuite(0xC018, "", "ECDH", "AES-128", 16, 16, "SHA-1", 20);
                
            case 0xC019: // ECDH_anon_WITH_AES_256_CBC_SHA
                return TLSCiphersuite(0xC019, "", "ECDH", "AES-256", 32, 16, "SHA-1", 20);
                
            case 0xC016: // ECDH_anon_WITH_RC4_128_SHA
                return TLSCiphersuite(0xC016, "", "ECDH", "RC4", 16, 0, "SHA-1", 20);
                
            case 0xC0AA: // PSK_DHE_WITH_AES_128_CCM_8
                return TLSCiphersuite(0xC0AA, "", "DHE_PSK", "AES-128/CCM-8", 16, 4, "AEAD", 0, "SHA-256");
                
            case 0xC0AB: // PSK_DHE_WITH_AES_256_CCM_8
                return TLSCiphersuite(0xC0AB, "", "DHE_PSK", "AES-256/CCM-8", 32, 4, "AEAD", 0, "SHA-256");
                
            case 0x008B: // PSK_WITH_3DES_EDE_CBC_SHA
                return TLSCiphersuite(0x008B, "", "PSK", "3DES", 24, 8, "SHA-1", 20);
                
            case 0x008C: // PSK_WITH_AES_128_CBC_SHA
                return TLSCiphersuite(0x008C, "", "PSK", "AES-128", 16, 16, "SHA-1", 20);
                
            case 0x00AE: // PSK_WITH_AES_128_CBC_SHA256
                return TLSCiphersuite(0x00AE, "", "PSK", "AES-128", 16, 16, "SHA-256", 32);
                
            case 0xC0A4: // PSK_WITH_AES_128_CCM
                return TLSCiphersuite(0xC0A4, "", "PSK", "AES-128/CCM", 16, 4, "AEAD", 0, "SHA-256");
                
            case 0xC0A8: // PSK_WITH_AES_128_CCM_8
                return TLSCiphersuite(0xC0A8, "", "PSK", "AES-128/CCM-8", 16, 4, "AEAD", 0, "SHA-256");
                
            case 0x00A8: // PSK_WITH_AES_128_GCM_SHA256
                return TLSCiphersuite(0x00A8, "", "PSK", "AES-128/GCM", 16, 4, "AEAD", 0, "SHA-256");
                
            case 0x008D: // PSK_WITH_AES_256_CBC_SHA
                return TLSCiphersuite(0x008D, "", "PSK", "AES-256", 32, 16, "SHA-1", 20);
                
            case 0x00AF: // PSK_WITH_AES_256_CBC_SHA384
                return TLSCiphersuite(0x00AF, "", "PSK", "AES-256", 32, 16, "SHA-384", 48);
                
            case 0xC0A5: // PSK_WITH_AES_256_CCM
                return TLSCiphersuite(0xC0A5, "", "PSK", "AES-256/CCM", 32, 4, "AEAD", 0, "SHA-256");
                
            case 0xC0A9: // PSK_WITH_AES_256_CCM_8
                return TLSCiphersuite(0xC0A9, "", "PSK", "AES-256/CCM-8", 32, 4, "AEAD", 0, "SHA-256");
                
            case 0x00A9: // PSK_WITH_AES_256_GCM_SHA384
                return TLSCiphersuite(0x00A9, "", "PSK", "AES-256/GCM", 32, 4, "AEAD", 0, "SHA-384");
                
            case 0xC094: // PSK_WITH_CAMELLIA_128_CBC_SHA256
                return TLSCiphersuite(0xC094, "", "PSK", "Camellia-128", 16, 16, "SHA-256", 32);
                
            case 0xC08E: // PSK_WITH_CAMELLIA_128_GCM_SHA256
                return TLSCiphersuite(0xC08E, "", "PSK", "Camellia-128/GCM", 16, 4, "AEAD", 0, "SHA-256");
                
            case 0xC095: // PSK_WITH_CAMELLIA_256_CBC_SHA384
                return TLSCiphersuite(0xC095, "", "PSK", "Camellia-256", 32, 16, "SHA-384", 48);
                
            case 0xC08F: // PSK_WITH_CAMELLIA_256_GCM_SHA384
                return TLSCiphersuite(0xC08F, "", "PSK", "Camellia-256/GCM", 32, 4, "AEAD", 0, "SHA-384");
                
            case 0x008A: // PSK_WITH_RC4_128_SHA
                return TLSCiphersuite(0x008A, "", "PSK", "RC4", 16, 0, "SHA-1", 20);
                
            case 0x000A: // RSA_WITH_3DES_EDE_CBC_SHA
                return TLSCiphersuite(0x000A, "RSA", "RSA", "3DES", 24, 8, "SHA-1", 20);
                
            case 0x002F: // RSA_WITH_AES_128_CBC_SHA
                return TLSCiphersuite(0x002F, "RSA", "RSA", "AES-128", 16, 16, "SHA-1", 20);
                
            case 0x003C: // RSA_WITH_AES_128_CBC_SHA256
                return TLSCiphersuite(0x003C, "RSA", "RSA", "AES-128", 16, 16, "SHA-256", 32);
                
            case 0xC09C: // RSA_WITH_AES_128_CCM
                return TLSCiphersuite(0xC09C, "RSA", "RSA", "AES-128/CCM", 16, 4, "AEAD", 0, "SHA-256");
                
            case 0xC0A0: // RSA_WITH_AES_128_CCM_8
                return TLSCiphersuite(0xC0A0, "RSA", "RSA", "AES-128/CCM-8", 16, 4, "AEAD", 0, "SHA-256");
                
            case 0x009C: // RSA_WITH_AES_128_GCM_SHA256
                return TLSCiphersuite(0x009C, "RSA", "RSA", "AES-128/GCM", 16, 4, "AEAD", 0, "SHA-256");
                
            case 0x0035: // RSA_WITH_AES_256_CBC_SHA
                return TLSCiphersuite(0x0035, "RSA", "RSA", "AES-256", 32, 16, "SHA-1", 20);
                
            case 0x003D: // RSA_WITH_AES_256_CBC_SHA256
                return TLSCiphersuite(0x003D, "RSA", "RSA", "AES-256", 32, 16, "SHA-256", 32);
                
            case 0xC09D: // RSA_WITH_AES_256_CCM
                return TLSCiphersuite(0xC09D, "RSA", "RSA", "AES-256/CCM", 32, 4, "AEAD", 0, "SHA-256");
                
            case 0xC0A1: // RSA_WITH_AES_256_CCM_8
                return TLSCiphersuite(0xC0A1, "RSA", "RSA", "AES-256/CCM-8", 32, 4, "AEAD", 0, "SHA-256");
                
            case 0x009D: // RSA_WITH_AES_256_GCM_SHA384
                return TLSCiphersuite(0x009D, "RSA", "RSA", "AES-256/GCM", 32, 4, "AEAD", 0, "SHA-384");
                
            case 0x0041: // RSA_WITH_CAMELLIA_128_CBC_SHA
                return TLSCiphersuite(0x0041, "RSA", "RSA", "Camellia-128", 16, 16, "SHA-1", 20);
                
            case 0x00BA: // RSA_WITH_CAMELLIA_128_CBC_SHA256
                return TLSCiphersuite(0x00BA, "RSA", "RSA", "Camellia-128", 16, 16, "SHA-256", 32);
                
            case 0xC07A: // RSA_WITH_CAMELLIA_128_GCM_SHA256
                return TLSCiphersuite(0xC07A, "RSA", "RSA", "Camellia-128/GCM", 16, 4, "AEAD", 0, "SHA-256");
                
            case 0x0084: // RSA_WITH_CAMELLIA_256_CBC_SHA
                return TLSCiphersuite(0x0084, "RSA", "RSA", "Camellia-256", 32, 16, "SHA-1", 20);
                
            case 0x00C0: // RSA_WITH_CAMELLIA_256_CBC_SHA256
                return TLSCiphersuite(0x00C0, "RSA", "RSA", "Camellia-256", 32, 16, "SHA-256", 32);
                
            case 0xC07B: // RSA_WITH_CAMELLIA_256_GCM_SHA384
                return TLSCiphersuite(0xC07B, "RSA", "RSA", "Camellia-256/GCM", 32, 4, "AEAD", 0, "SHA-384");
                
            case 0x0004: // RSA_WITH_RC4_128_MD5
                return TLSCiphersuite(0x0004, "RSA", "RSA", "RC4", 16, 0, "MD5", 16);
                
            case 0x0005: // RSA_WITH_RC4_128_SHA
                return TLSCiphersuite(0x0005, "RSA", "RSA", "RC4", 16, 0, "SHA-1", 20);
                
            case 0x0096: // RSA_WITH_SEED_CBC_SHA
                return TLSCiphersuite(0x0096, "RSA", "RSA", "SEED", 16, 16, "SHA-1", 20);
                
            case 0xC01C: // SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA
                return TLSCiphersuite(0xC01C, "DSA", "SRP_SHA", "3DES", 24, 8, "SHA-1", 20);
                
            case 0xC01F: // SRP_SHA_DSS_WITH_AES_128_CBC_SHA
                return TLSCiphersuite(0xC01F, "DSA", "SRP_SHA", "AES-128", 16, 16, "SHA-1", 20);
                
            case 0xC022: // SRP_SHA_DSS_WITH_AES_256_CBC_SHA
                return TLSCiphersuite(0xC022, "DSA", "SRP_SHA", "AES-256", 32, 16, "SHA-1", 20);
                
            case 0xC01B: // SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA
                return TLSCiphersuite(0xC01B, "RSA", "SRP_SHA", "3DES", 24, 8, "SHA-1", 20);
                
            case 0xC01E: // SRP_SHA_RSA_WITH_AES_128_CBC_SHA
                return TLSCiphersuite(0xC01E, "RSA", "SRP_SHA", "AES-128", 16, 16, "SHA-1", 20);
                
            case 0xC021: // SRP_SHA_RSA_WITH_AES_256_CBC_SHA
                return TLSCiphersuite(0xC021, "RSA", "SRP_SHA", "AES-256", 32, 16, "SHA-1", 20);
                
            case 0xC01A: // SRP_SHA_WITH_3DES_EDE_CBC_SHA
                return TLSCiphersuite(0xC01A, "", "SRP_SHA", "3DES", 24, 8, "SHA-1", 20);
                
            case 0xC01D: // SRP_SHA_WITH_AES_128_CBC_SHA
                return TLSCiphersuite(0xC01D, "", "SRP_SHA", "AES-128", 16, 16, "SHA-1", 20);
                
            case 0xC020: // SRP_SHA_WITH_AES_256_CBC_SHA
                return TLSCiphersuite(0xC020, "", "SRP_SHA", "AES-256", 32, 16, "SHA-1", 20);
            default:
                return TLSCiphersuite.init; // some unknown ciphersuite
        }
    }

    /**
    * Lookup a ciphersuite by name
    * Params:
    *  name = the name (eg TLS_RSA_WITH_RC4_128_SHA)
    * Returns: ciphersuite object
    */
    static TLSCiphersuite byName(in string name)
    {
        foreach (const ref TLSCiphersuite suite; allKnownCiphersuites()[])
        {
            if (suite.toString() == name)
                return suite;
        }
        
        return TLSCiphersuite.init; // some unknown ciphersuite
    }

    /**
    * Generate a static list of all known ciphersuites and return it.
    *
    * Returns: list of all known ciphersuites
    */
    static Vector!TLSCiphersuite allKnownCiphersuites()
    {
        static Vector!TLSCiphersuite all_ciphersuites;
        static bool initialized;
        if (!initialized) {
            initialized = true;
            all_ciphersuites = gatherKnownCiphersuites();
        }
        return all_ciphersuites.dup();
    }

    /**
    * Formats the ciphersuite back to an RFC-style ciphersuite string
    * Returns: RFC ciphersuite string identifier
    */
    string toString() const
    {
        if (m_cipher_keylen == 0)
            throw new Exception("toString - no value set");
        Appender!string output;
        
        output ~= "TLS_";
        
        if (kexAlgo() != "RSA")
        {
            if (kexAlgo() == "DH")
                output ~= "DHE";
            else if (kexAlgo() == "ECDH")
                output ~= "ECDHE";
            else
                output ~= kexAlgo();
            
            output ~= '_';
        }
        
        if (sigAlgo() == "DSA")
            output ~= "DSS_";
        else if (sigAlgo() != "")
            output ~= sigAlgo() ~ '_';
        
        output ~= "WITH_";
        
        if (cipherAlgo() == "RC4")
        {
            output ~= "RC4_128_";
        }
        else
        {
            if (cipherAlgo() == "3DES")
                output ~= "3DES_EDE";
            else if (cipherAlgo().find("Camellia") == -1)
                output ~= "CAMELLIA_" ~ to!string(8*cipherKeylen());
            else
                output ~= replaceChars(cipherAlgo(), ['-', '/'], '_');
            
            if (cipherAlgo().find("/") != -1)
                output ~= "_"; // some explicit mode already included
            else
                output ~= "_CBC_";
        }
        
        if (macAlgo() == "SHA-1")
            output ~= "SHA";
        else if (macAlgo() == "AEAD")
            output ~= eraseChars(prfAlgo(), ['-']);
        else
            output ~= eraseChars(macAlgo(), ['-']);
        
        return output.data;
    }

    /**
    * Returns: ciphersuite number
    */
    ushort ciphersuiteCode() const { return m_ciphersuite_code; }

    /**
    * Returns: true if this is a PSK ciphersuite
    */
    bool pskCiphersuite() const
    {
        return (kexAlgo() == "PSK" ||
                kexAlgo() == "DHE_PSK" ||
                kexAlgo() == "ECDHE_PSK");
    }

    /**
    * Returns: true if this is an ECC ciphersuite
    */
    bool eccCiphersuite() const
    {
        return (sigAlgo() == "ECDSA" || kexAlgo() == "ECDH" || kexAlgo() == "ECDHE_PSK");
    }

    /**
    * Returns: key exchange algorithm used by this ciphersuite
    */
    string kexAlgo() const { return m_kex_algo; }

    /**
    * Returns: signature algorithm used by this ciphersuite
    */
    string sigAlgo() const { return m_sig_algo; }

    /**
    * Returns: symmetric cipher algorithm used by this ciphersuite
    */
    string cipherAlgo() const { return m_cipher_algo; }

    /**
    * Returns: message authentication algorithm used by this ciphersuite
    */
    string macAlgo() const { return m_mac_algo; }

    string prfAlgo() const
    {
        return (m_prf_algo != "") ? m_prf_algo : m_mac_algo;
    }

    /**
    * Returns: cipher key length used by this ciphersuite
    */
    size_t cipherKeylen() const { return m_cipher_keylen; }

    size_t cipherIvlen() const { return m_cipher_ivlen; }

    size_t macKeylen() const { return m_mac_keylen; }

    /**
    * Returns: true if this is a valid/known ciphersuite
    */    
    bool valid() const
    {
        if (!m_cipher_keylen) // uninitialized object
            return false;
        
        AlgorithmFactory af = globalState().algorithmFactory();
        
        if (!af.prototypeHashFunction(prfAlgo()))
            return false;
        
        if (macAlgo() == "AEAD")
        {
            auto cipher_and_mode = splitter(cipherAlgo(), '/');
            assert(cipher_and_mode.length == 2, "Expected format for AEAD algo");
            if (!af.prototypeBlockCipher(cipher_and_mode[0]))
                return false;
            
            const auto mode = cipher_and_mode[1];
            
            static if (!BOTAN_HAS_AEAD_CCM) {
                if (mode == "CCM" || mode == "CCM-8")
                    return false;
            }
            
            static if (!BOTAN_HAS_AEAD_GCM) {
                if (mode == "GCM")
                    return false;
            }
            
            static if (!BOTAN_HAS_AEAD_OCB) {
                if (mode == "OCB")
                    return false;
            }
        }
        else
        {
            if (!af.prototypeBlockCipher(cipherAlgo()) &&
                !af.prototypeStreamCipher(cipherAlgo()))
                return false;
            
            if (!af.prototypeHashFunction(macAlgo()))
                return false;
        }
        
        if (kexAlgo() == "SRP_SHA")
        {
            static if (!BOTAN_HAS_SRP6) {
                return false;
            }
        }
        else if (kexAlgo() == "ECDH" || kexAlgo() == "ECDHE_PSK")
        {
            static if (!BOTAN_HAS_ECDH) {
                return false;
            }
        }
        else if (kexAlgo() == "DH" || kexAlgo() == "DHE_PSK")
        {
            static if (!BOTAN_HAS_DIFFIE_HELLMAN) {
                return false;
            }
        }
        
        if (sigAlgo() == "DSA")
        {
            static if (!BOTAN_HAS_DSA) {
                return false;
            }
        }
        else if (sigAlgo() == "ECDSA")
        {
            static if (!BOTAN_HAS_ECDSA) {
                return false;
            }
        }
        else if (sigAlgo() == "RSA")
        {
            static if (!BOTAN_HAS_RSA) {
                return false;
            }
        }
        
        return true;
    }
private:
    this(ushort ciphersuite_code,
         string sig_algo,
         string kex_algo,
         string cipher_algo,
         size_t cipher_keylen,
         size_t cipher_ivlen,
         string mac_algo,
         size_t mac_keylen,
         string prf_algo = "")
    {
        m_ciphersuite_code = ciphersuite_code;
        m_sig_algo = sig_algo;
        m_kex_algo = kex_algo;
        m_cipher_algo = cipher_algo;
        m_mac_algo = mac_algo;
        m_prf_algo = prf_algo;
        m_cipher_keylen = cipher_keylen;
        m_cipher_ivlen = cipher_ivlen;
        m_mac_keylen = mac_keylen;
    }

    /*
    * This way all work happens at the constuctor call, and we can
    * rely on that happening only once in D
    */
    static Vector!TLSCiphersuite gatherKnownCiphersuites()
    {
        Vector!TLSCiphersuite ciphersuites;
        
        for (size_t i = 0; i <= 0xFFFF; ++i)
        {
            TLSCiphersuite suite = byId(cast(ushort)i);
            
            if (suite.valid())
                ciphersuites.pushBack(suite);
        }
        
        return ciphersuites;
    }

    ushort m_ciphersuite_code;

    string m_sig_algo;
    string m_kex_algo;
    string m_cipher_algo;
    string m_mac_algo;
    string m_prf_algo;

    size_t m_cipher_keylen;
    size_t m_cipher_ivlen;
    size_t m_mac_keylen;
}

ptrdiff_t find(string str, string str2) {
    import std.algorithm : countUntil;
    return str.countUntil(str2);
}