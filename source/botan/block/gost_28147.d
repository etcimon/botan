/**
* GOST 28147-89
* 
* Copyright:
* (C) 1999-2009 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.block.gost_28147;

import botan.constants;
static if (BOTAN_HAS_GOST_28147_89):

import botan.block.block_cipher;
import botan.utils.loadstor;
import botan.utils.rotate;
import botan.utils.exceptn;
import botan.utils.get_byte;
import botan.utils.mem_ops;

/**
* The GOST 28147-89 block cipher uses a set of 4 bit Sboxes, however
* the standard does not actually define these Sboxes; they are
* considered a local configuration issue. Several different sets are
* used.
*/
final class GOST_28147_89_Params
{
public:
    /**
    * Params:
    *  row = the row
    *  col = the column
    * Returns: sbox entry at this row/column
    */
    ubyte sboxEntry(size_t row, size_t col) const
    {
        ubyte x = m_sboxes[4 * col + (row / 2)];
        
        return (row % 2 == 0) ? (x >> 4) : (x & 0x0F);
    }

    /**
    * Returns: name of this parameter set
    */
    string paramName() const { return m_name; }

    /**
    * Default GOST parameters are the ones given in GOST R 34.11 for
    * testing purposes; these sboxes are also used by Crypto++, and,
    * at least according to Wikipedia, the Central Bank of Russian
    * Federation
    * 
    * Params:
    *  name = of the parameter set
    */
    this(in string name = "R3411_94_TestParam") 
    {
        m_name = name;
        // Encoded in the packed fromat from RFC 4357
        
        // GostR3411_94_TestParamSet (OID 1.2.643.2.2.31.0)
        __gshared immutable ubyte[64] GOST_R_3411_TEST_PARAMS = [
            0x4E, 0x57, 0x64, 0xD1, 0xAB, 0x8D, 0xCB, 0xBF, 0x94, 0x1A, 0x7A,
            0x4D, 0x2C, 0xD1, 0x10, 0x10, 0xD6, 0xA0, 0x57, 0x35, 0x8D, 0x38,
            0xF2, 0xF7, 0x0F, 0x49, 0xD1, 0x5A, 0xEA, 0x2F, 0x8D, 0x94, 0x62,
            0xEE, 0x43, 0x09, 0xB3, 0xF4, 0xA6, 0xA2, 0x18, 0xC6, 0x98, 0xE3,
            0xC1, 0x7C, 0xE5, 0x7E, 0x70, 0x6B, 0x09, 0x66, 0xF7, 0x02, 0x3C,
            0x8B, 0x55, 0x95, 0xBF, 0x28, 0x39, 0xB3, 0x2E, 0xCC ];
        
        // GostR3411-94-CryptoProParamSet (OID 1.2.643.2.2.31.1)
        __gshared immutable ubyte[64] GOST_R_3411_CRYPTOPRO_PARAMS = [
            0xA5, 0x74, 0x77, 0xD1, 0x4F, 0xFA, 0x66, 0xE3, 0x54, 0xC7, 0x42,
            0x4A, 0x60, 0xEC, 0xB4, 0x19, 0x82, 0x90, 0x9D, 0x75, 0x1D, 0x4F,
            0xC9, 0x0B, 0x3B, 0x12, 0x2F, 0x54, 0x79, 0x08, 0xA0, 0xAF, 0xD1,
            0x3E, 0x1A, 0x38, 0xC7, 0xB1, 0x81, 0xC6, 0xE6, 0x56, 0x05, 0x87,
            0x03, 0x25, 0xEB, 0xFE, 0x9C, 0x6D, 0xF8, 0x6D, 0x2E, 0xAB, 0xDE,
            0x20, 0xBA, 0x89, 0x3C, 0x92, 0xF8, 0xD3, 0x53, 0xBC ];
        
        if (m_name == "R3411_94_TestParam")
            m_sboxes = GOST_R_3411_TEST_PARAMS;
        else if (m_name == "R3411_CryptoPro")
            m_sboxes = GOST_R_3411_CRYPTOPRO_PARAMS;
        else
            throw new InvalidArgument("GOST_28147_89_Params: Unknown " ~ m_name);
    }
private:
    const ubyte[64] m_sboxes;
    string m_name;
}

/**
* GOST 28147-89
*/
final class GOST_28147_89 : BlockCipherFixedParams!(8, 32), BlockCipher, SymmetricAlgorithm
{
public:

    /*
    * GOST Encryption
    */
    override void encryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        foreach (size_t i; 0 .. blocks)
        {
            uint N1 = loadLittleEndian!uint(input, 0);
            uint N2 = loadLittleEndian!uint(input, 1);
            
            foreach (size_t j; 0 .. 3)
            {
                mixin(GOST_2ROUND!(N1, N2, 0, 1)());
                mixin(GOST_2ROUND!(N1, N2, 2, 3)());
                mixin(GOST_2ROUND!(N1, N2, 4, 5)());
                mixin(GOST_2ROUND!(N1, N2, 6, 7)());
            }
            
            mixin(GOST_2ROUND!(N1, N2, 7, 6)());
            mixin(GOST_2ROUND!(N1, N2, 5, 4)());
            mixin(GOST_2ROUND!(N1, N2, 3, 2)());
            mixin(GOST_2ROUND!(N1, N2, 1, 0)());
            
            storeLittleEndian(output, N2, N1);
            
            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }

    /*
    * GOST Decryption
    */
    override void decryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        foreach (size_t i; 0 .. blocks)
        {
            uint N1 = loadLittleEndian!uint(input, 0);
            uint N2 = loadLittleEndian!uint(input, 1);
            
            mixin(GOST_2ROUND!(N1, N2, 0, 1)());
            mixin(GOST_2ROUND!(N1, N2, 2, 3)());
            mixin(GOST_2ROUND!(N1, N2, 4, 5)());
            mixin(GOST_2ROUND!(N1, N2, 6, 7)());
            
            foreach (size_t j; 0 .. 3)
            {
                mixin(GOST_2ROUND!(N1, N2, 7, 6)());
                mixin(GOST_2ROUND!(N1, N2, 5, 4)());
                mixin(GOST_2ROUND!(N1, N2, 3, 2)());
                mixin(GOST_2ROUND!(N1, N2, 1, 0)());
            }
            
            storeLittleEndian(output, N2, N1);
            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }

    override void clear()
    {
        zap(m_EK);
    }

    @property string name() const
    {
        /*
        'Guess' the right name for the sbox on the basis of the values.
        This would need to be updated if support for other sbox parameters
        is added. Preferably, we would just store the string value in the
        constructor, but can't break binary compat.
        */
        string sbox_name = "";
        if (m_SBOX[0] == 0x00072000)
            sbox_name = "R3411_94_TestParam";
        else if (m_SBOX[0] == 0x0002D000)
            sbox_name = "R3411_CryptoPro";
        else
            throw new InternalError("GOST-28147 unrecognized sbox value");
        
        return "GOST-28147-89(" ~ sbox_name ~ ")";
    }

    override @property size_t parallelism() const { return 1; }
    override BlockCipher clone() const { return new GOST_28147_89(m_SBOX); }
    override size_t blockSize() const { return super.blockSize(); }
    override KeyLengthSpecification keySpec() const { return super.keySpec(); }

    this(in string params) {
        this(scoped!GOST_28147_89_Params(params).Scoped_payload);
    }

    /**
    * Params:
    *  params = the sbox parameters to use
    */
    this(in GOST_28147_89_Params param)
    {
        m_SBOX = Vector!uint(1024);
        // Convert the parallel 4x4 sboxes into larger word-based sboxes
        foreach (size_t i; 0 .. 4)
        {
            foreach (size_t j; 0 .. 256)
            {
                const uint T = (param.sboxEntry(2*i  , j % 16)) |
                               (param.sboxEntry(2*i+1, j / 16) << 4);
                m_SBOX[256*i+j] = rotateLeft(T, (11+8*i) % 32);
            }
        }
    }
protected:
    this(const ref Vector!uint other_SBOX) {
        m_SBOX = other_SBOX.dup; 
        m_EK = 8;
    }

    /*
    * GOST Key Schedule
    */
    override void keySchedule(const(ubyte)* key, size_t)
    {
        m_EK.resize(8);
        foreach (size_t i; 0 .. 8)
            m_EK[i] = loadLittleEndian!uint(key, i);
    }

    /*
    * The sbox is not secret, this is just a larger expansion of it
    * which we generate at runtime for faster execution
    */
    Vector!uint m_SBOX;

    SecureVector!uint m_EK;
}

protected:

/*
* Two rounds of GOST
*/
string GOST_2ROUND(alias N1, alias N2, ubyte R1, ubyte R2)()
{
    const N1_ = __traits(identifier, N1);
    const N2_ = __traits(identifier, N2);
    return `{
            uint T0 = ` ~ N1_ ~ ` + m_EK[` ~ R1.stringof ~ `];
            N2 ^= m_SBOX[get_byte(3, T0)] |
                m_SBOX[get_byte(2, T0)+256] | 
                m_SBOX[get_byte(1, T0)+512] | 
                m_SBOX[get_byte(0, T0)+768];

            uint T1 = ` ~ N2_ ~ ` + m_EK[` ~ R2.stringof ~ `];
            N1 ^= m_SBOX[get_byte(3, T1)] |
                m_SBOX[get_byte(2, T1)+256] |
                m_SBOX[get_byte(1, T1)+512] |
                m_SBOX[get_byte(0, T1)+768];
        }`;
}
