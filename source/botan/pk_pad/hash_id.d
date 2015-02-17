/**
* Hash Function Identification
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pk_pad.hash_id;

import memutils.vector;
import botan.utils.exceptn;
import botan.utils.types;

/**
* Return the PKCS #1 hash identifier
* @see RFC 3447 section 9.2
* Params:
*  hash_name = the name of the hash function
* Returns: ubyte sequence identifying the hash
* Throws: $D(InvalidArgument) if the hash has no known PKCS #1 hash id
*/
Vector!ubyte pkcsHashId(in string name)
{
    // Special case for SSL/TLS RSA signatures
    if (name == "Parallel(MD5,SHA-160)")
        return Vector!ubyte();
    
    if (name == "MD2")
        return Vector!ubyte(MD2_PKCS_ID[0 .. (MD2_PKCS_ID).length]);
    
    if (name == "MD5")
        return Vector!ubyte(MD5_PKCS_ID);
    
    if (name == "RIPEMD-128")
        return Vector!ubyte(RIPEMD_128_PKCS_ID);
    
    if (name == "RIPEMD-160")
        return Vector!ubyte(RIPEMD_160_PKCS_ID);
    
    if (name == "SHA-160")
        return Vector!ubyte(SHA_160_PKCS_ID);
    
    if (name == "SHA-224")
        return Vector!ubyte(SHA_224_PKCS_ID);
    
    if (name == "SHA-256")
        return Vector!ubyte(SHA_256_PKCS_ID);
    
    if (name == "SHA-384")
        return Vector!ubyte(SHA_384_PKCS_ID);
    
    if (name == "SHA-512")
        return Vector!ubyte(SHA_512_PKCS_ID);
    
    if (name == "Tiger(24,3)")
        return Vector!ubyte(TIGER_PKCS_ID);
    
    throw new InvalidArgument("No PKCS #1 identifier for " ~ name);
}

/**
* Return the IEEE 1363 hash identifier
* Params:
*  hash_name = the name of the hash function
* Returns: ubyte code identifying the hash, or 0 if not known
*/

ubyte ieee1363HashId(in string name)
{
    if (name == "SHA-160")     return 0x33;
    
    if (name == "SHA-224")     return 0x38;
    if (name == "SHA-256")     return 0x34;
    if (name == "SHA-384")     return 0x36;
    if (name == "SHA-512")     return 0x35;
    
    if (name == "RIPEMD-160") return 0x31;
    if (name == "RIPEMD-128") return 0x32;
    
    if (name == "Whirlpool")  return 0x37;
    
    return 0;
}


private:

__gshared immutable ubyte[] MD2_PKCS_ID = [
    0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86,
    0xF7, 0x0D, 0x02, 0x02, 0x05, 0x00, 0x04, 0x10 ];

__gshared immutable ubyte[] MD5_PKCS_ID = [
    0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86,
    0xF7, 0x0D, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10 ];

__gshared immutable ubyte[] RIPEMD_128_PKCS_ID = [
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x24, 0x03, 0x02,
    0x02, 0x05, 0x00, 0x04, 0x14 ];

__gshared immutable ubyte[] RIPEMD_160_PKCS_ID = [
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x24, 0x03, 0x02,
    0x01, 0x05, 0x00, 0x04, 0x14 ];

__gshared immutable ubyte[] SHA_160_PKCS_ID = [
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02,
    0x1A, 0x05, 0x00, 0x04, 0x14 ];

__gshared immutable ubyte[] SHA_224_PKCS_ID = [
    0x30, 0x2D, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1C ];

__gshared immutable ubyte[] SHA_256_PKCS_ID = [
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 ];

__gshared immutable ubyte[] SHA_384_PKCS_ID = [
    0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30 ];

__gshared immutable ubyte[] SHA_512_PKCS_ID = [
    0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 ];

__gshared immutable ubyte[] TIGER_PKCS_ID = [
    0x30, 0x29, 0x30, 0x0D, 0x06, 0x09, 0x2B, 0x06, 0x01, 0x04,
    0x01, 0xDA, 0x47, 0x0C, 0x02, 0x05, 0x00, 0x04, 0x18 ];