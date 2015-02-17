/**
* MGF1
* 
* Copyright:
* (C) 1999-2007,2014 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pk_pad.mgf1;

import botan.kdf.kdf;
import botan.hash.hash;
import botan.utils.exceptn;
import botan.utils.xor_buf;
import botan.utils.types;
import std.algorithm;

/**
* MGF1 from PKCS #1 v2.0
*/
void mgf1Mask(HashFunction hash,
              const(ubyte)* input, size_t in_len,
              ubyte* output, size_t out_len)
{
    uint counter = 0;
    
    while (out_len)
    {
        hash.update(input, in_len);
        hash.updateBigEndian(counter);
        SecureVector!ubyte buffer = hash.finished();
        
        size_t xored = std.algorithm.min(buffer.length, out_len);
        xorBuf(output, buffer.ptr, xored);
        output += xored;
        out_len -= xored;
        
        ++counter;
    }
}