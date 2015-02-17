/**
* Adler32
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.checksum.adler32;

import botan.constants;
static if (BOTAN_HAS_ADLER32):

import botan.utils.loadstor;
import botan.hash.hash;
/**
* The Adler32 checksum, used in zlib
*/
final class Adler32 : HashFunction
{
public:
    override @property string name() const { return "Adler32"; }
    override @property size_t outputLength() const { return 4; }
    override @property size_t hashBlockSize() const { return 0; }
    override HashFunction clone() const { return new Adler32; }

    override void clear() { m_S1 = 1; m_S2 = 0; }

    this() { clear(); }
    ~this() { clear(); }
protected:
    /*
    * Update an Adler32 Checksum
    */
    override void addData(const(ubyte)* input, size_t length)
    {
        __gshared immutable size_t PROCESS_AMOUNT = 5552;
        
        while (length >= PROCESS_AMOUNT)
        {
            adler32Update(input, PROCESS_AMOUNT, m_S1, m_S2);
            input += PROCESS_AMOUNT;
            length -= PROCESS_AMOUNT;
        }
        
        adler32Update(input, length, m_S1, m_S2);
    }

    /*
    * Finalize an Adler32 Checksum
    */
    override void finalResult(ubyte* output)
    {
        storeBigEndian(output, m_S2, m_S1);
        clear();
    }

    ushort m_S1, m_S2;
}

package:

void adler32Update(const(ubyte)* input, size_t length, ref ushort S1, ref ushort S2)
{
    uint S1x = S1;
    uint S2x = S2;
    
    while (length >= 16)
    {
        S1x += input[ 0]; S2x += S1x;
        S1x += input[ 1]; S2x += S1x;
        S1x += input[ 2]; S2x += S1x;
        S1x += input[ 3]; S2x += S1x;
        S1x += input[ 4]; S2x += S1x;
        S1x += input[ 5]; S2x += S1x;
        S1x += input[ 6]; S2x += S1x;
        S1x += input[ 7]; S2x += S1x;
        S1x += input[ 8]; S2x += S1x;
        S1x += input[ 9]; S2x += S1x;
        S1x += input[10]; S2x += S1x;
        S1x += input[11]; S2x += S1x;
        S1x += input[12]; S2x += S1x;
        S1x += input[13]; S2x += S1x;
        S1x += input[14]; S2x += S1x;
        S1x += input[15]; S2x += S1x;
        input += 16;
        length -= 16;
    }
    
    foreach (size_t j; 0 .. length)
    {
        S1x += input[j];
        S2x += S1x;
    }
    
    S1 = S1x % 65521;
    S2 = S2x % 65521;
}
    
