/**
* Threefish
* 
* Copyright:
* (C) 2013,2014 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.block.threefish;

import botan.constants;
static if (BOTAN_HAS_THREEFISH_512):

import botan.utils.rotate;
import botan.utils.loadstor;
import botan.block.block_cipher;
import botan.utils.types;
import botan.utils.mem_ops;

/**
* Threefish-512
*/
class Threefish512 : BlockCipherFixedParams!(64, 64), BlockCipher, SymmetricAlgorithm
{
public:
    override void encryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        assert(m_K.length == 9, "Key was set");
        assert(m_T.length == 3, "Tweak was set");
        
        foreach (size_t i; 0 .. blocks)
        {
            ulong X0 = loadLittleEndian!ulong(input, 0);
            ulong X1 = loadLittleEndian!ulong(input, 1);
            ulong X2 = loadLittleEndian!ulong(input, 2);
            ulong X3 = loadLittleEndian!ulong(input, 3);
            ulong X4 = loadLittleEndian!ulong(input, 4);
            ulong X5 = loadLittleEndian!ulong(input, 5);
            ulong X6 = loadLittleEndian!ulong(input, 6);
            ulong X7 = loadLittleEndian!ulong(input, 7);
            
            mixin(THREEFISH_ENC_INJECT_KEY!(0)());

            mixin(THREEFISH_ENC_8_ROUNDS!(1,2)());
            mixin(THREEFISH_ENC_8_ROUNDS!(3,4)());
            mixin(THREEFISH_ENC_8_ROUNDS!(5,6)());
            mixin(THREEFISH_ENC_8_ROUNDS!(7,8)());
            mixin(THREEFISH_ENC_8_ROUNDS!(9,10)());
            mixin(THREEFISH_ENC_8_ROUNDS!(11,12)());
            mixin(THREEFISH_ENC_8_ROUNDS!(13,14)());
            mixin(THREEFISH_ENC_8_ROUNDS!(15,16)());
            mixin(THREEFISH_ENC_8_ROUNDS!(17,18)());
            
            storeLittleEndian(output, X0, X1, X2, X3, X4, X5, X6, X7);
            
            input += 64;
            output += 64;
        }
    }

    override void decryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        assert(m_K.length == 9, "Key was set");
        assert(m_T.length == 3, "Tweak was set");
        
        foreach (size_t i; 0 .. blocks)
        {
            ulong X0 = loadLittleEndian!ulong(input, 0);
            ulong X1 = loadLittleEndian!ulong(input, 1);
            ulong X2 = loadLittleEndian!ulong(input, 2);
            ulong X3 = loadLittleEndian!ulong(input, 3);
            ulong X4 = loadLittleEndian!ulong(input, 4);
            ulong X5 = loadLittleEndian!ulong(input, 5);
            ulong X6 = loadLittleEndian!ulong(input, 6);
            ulong X7 = loadLittleEndian!ulong(input, 7);
            
            mixin(THREEFISH_DEC_INJECT_KEY!(18)());

            mixin(THREEFISH_DEC_8_ROUNDS!(17,16)());
            mixin(THREEFISH_DEC_8_ROUNDS!(15,14)());
            mixin(THREEFISH_DEC_8_ROUNDS!(13,12)());
            mixin(THREEFISH_DEC_8_ROUNDS!(11,10)());
            mixin(THREEFISH_DEC_8_ROUNDS!(9,8)());
            mixin(THREEFISH_DEC_8_ROUNDS!(7,6)());
            mixin(THREEFISH_DEC_8_ROUNDS!(5,4)());
            mixin(THREEFISH_DEC_8_ROUNDS!(3,2)());
            mixin(THREEFISH_DEC_8_ROUNDS!(1,0)());
            
            storeLittleEndian(output, X0, X1, X2, X3, X4, X5, X6, X7);
            
            input += 64;
            output += 64;
        }
    }

    final void setTweak(const(ubyte)* tweak, size_t len)
    {
        if (len != 16)
            throw new Exception("Unsupported twofish tweak length");
        m_T[0] = loadLittleEndian!ulong(tweak, 0);
        m_T[1] = loadLittleEndian!ulong(tweak, 1);
        m_T[2] = m_T[0] ^ m_T[1];
    }

    override void clear()
    {
        if (m_T.length == 0) m_T = SecureVector!ulong(3);
        else zeroise(m_T);
        if (m_K.length == 0) m_K = SecureVector!ulong(9);
        else zeroise(m_K);
    }

    final override @property string name() const { return "Threefish-512"; }
    override @property size_t parallelism() const { return 1; }
    override BlockCipher clone() const { return new Threefish512; }
    override size_t blockSize() const { return super.blockSize(); }
    override KeyLengthSpecification keySpec() const { return super.keySpec(); }

    this() {
        m_T = SecureVector!ulong(3);
    }

protected:
    final ref const(SecureVector!ulong) getT() const { return m_T; }
    final ref const(SecureVector!ulong) getK() const { return m_K; }
    override void keySchedule(const(ubyte)* key, size_t)
    {
        // todo: define key schedule for smaller keys
        m_K.resize(9);
        
        foreach (size_t i; 0 .. 8)
            m_K[i] = loadLittleEndian!ulong(key, i);
        
        m_K[8] = m_K[0] ^ m_K[1] ^ m_K[2] ^ m_K[3] ^
                 m_K[4] ^ m_K[5] ^ m_K[6] ^ m_K[7] ^ 0x1BD11BDAA9FC1A22;
    }
public:
    final void skeinFeedfwd(const ref SecureVector!ulong M, const ref SecureVector!ulong T)
    {
        assert(m_K.length == 9, "Key was set");
        assert(M.length == 8, "Single block");
        
        m_T[0] = T[0];
        m_T[1] = T[1];
        m_T[2] = T[0] ^ T[1];
        
        ulong X0 = M[0];
        ulong X1 = M[1];
        ulong X2 = M[2];
        ulong X3 = M[3];
        ulong X4 = M[4];
        ulong X5 = M[5];
        ulong X6 = M[6];
        ulong X7 = M[7];
        
        mixin(THREEFISH_ENC_INJECT_KEY!(0)());

        mixin(THREEFISH_ENC_8_ROUNDS!(1,2)());
        mixin(THREEFISH_ENC_8_ROUNDS!(3,4)());
        mixin(THREEFISH_ENC_8_ROUNDS!(5,6)());
        mixin(THREEFISH_ENC_8_ROUNDS!(7,8)());
        mixin(THREEFISH_ENC_8_ROUNDS!(9,10)());
        mixin(THREEFISH_ENC_8_ROUNDS!(11,12)());
        mixin(THREEFISH_ENC_8_ROUNDS!(13,14)());
        mixin(THREEFISH_ENC_8_ROUNDS!(15,16)());
        mixin(THREEFISH_ENC_8_ROUNDS!(17,18)());
        
        m_K[0] = M[0] ^ X0;
        m_K[1] = M[1] ^ X1;
        m_K[2] = M[2] ^ X2;
        m_K[3] = M[3] ^ X3;
        m_K[4] = M[4] ^ X4;
        m_K[5] = M[5] ^ X5;
        m_K[6] = M[6] ^ X6;
        m_K[7] = M[7] ^ X7;
        
        m_K[8] = m_K[0] ^ m_K[1] ^ m_K[2] ^ m_K[3] ^
                 m_K[4] ^ m_K[5] ^ m_K[6] ^ m_K[7] ^ 0x1BD11BDAA9FC1A22;
    }

    // Private data
    SecureVector!ulong m_T;
    SecureVector!ulong m_K;
}

package:


string THREEFISH_ENC_ROUND(alias _X0, alias _X1, alias _X2, alias _X3, 
                           alias _X4, alias _X5, alias _X6, alias _X7, 
                           ubyte _ROT1, ubyte _ROT2, ubyte _ROT3, ubyte _ROT4)()
{
    const X0 = __traits(identifier, _X0);
    const X1 = __traits(identifier, _X1);
    const X2 = __traits(identifier, _X2);
    const X3 = __traits(identifier, _X3);
    const X4 = __traits(identifier, _X4);
    const X5 = __traits(identifier, _X5);
    const X6 = __traits(identifier, _X6);
    const X7 = __traits(identifier, _X7);
    const ROT1 = _ROT1.stringof;
    const ROT2 = _ROT2.stringof;
    const ROT3 = _ROT3.stringof;
    const ROT4 = _ROT4.stringof;

    return  X0 ~ ` += ` ~ X4 ~ `;
        ` ~ X1 ~ ` += ` ~ X5 ~ `;
        ` ~ X2 ~ ` += ` ~ X6 ~ `;
        ` ~ X3 ~ ` += ` ~ X7 ~ `;
        ` ~ X4 ~ ` = rotateLeft(` ~ X4 ~ `, ` ~ ROT1 ~ `);
        ` ~ X5 ~ ` = rotateLeft(` ~ X5 ~ `, ` ~ ROT2 ~ `);
        ` ~ X6 ~ ` = rotateLeft(` ~ X6 ~ `, ` ~ ROT3 ~ `);
        ` ~ X7 ~ ` = rotateLeft(` ~ X7 ~ `, ` ~ ROT4 ~ `);
        ` ~ X4 ~ ` ^= ` ~ X0 ~ `;
        ` ~ X5 ~ ` ^= ` ~ X1 ~ `;
        ` ~ X6 ~ ` ^= ` ~ X2 ~ `;
        ` ~ X7 ~ ` ^= ` ~ X3 ~ `;`;
}

string THREEFISH_ENC_INJECT_KEY(ushort r)() 
{
    
    return `X0 += m_K[(` ~ r.stringof ~ `  ) % 9];
            X1 += m_K[(` ~ (r + 1).stringof ~ `) % 9];
            X2 += m_K[(` ~ (r + 2).stringof ~ `) % 9];
            X3 += m_K[(` ~ (r + 3).stringof ~ `) % 9];
            X4 += m_K[(` ~ (r + 4).stringof ~ `) % 9];
            X5 += m_K[(` ~ (r + 5).stringof ~ `) % 9] + m_T[(` ~ r.stringof ~ `  ) % 3];
            X6 += m_K[(` ~ (r + 6).stringof ~ `) % 9] + m_T[(` ~ (r + 1).stringof ~ `) % 3];
            X7 += m_K[(` ~ (r + 7).stringof ~ `) % 9] + (` ~ r.stringof ~ `);`;
}

string THREEFISH_ENC_8_ROUNDS(ushort R1, ushort R2)()
{
    return `mixin(THREEFISH_ENC_ROUND!(X0,X2,X4,X6, X1,X3,X5,X7, 46,36,19,37)());
            mixin(THREEFISH_ENC_ROUND!(X2,X4,X6,X0, X1,X7,X5,X3, 33,27,14,42)());
            mixin(THREEFISH_ENC_ROUND!(X4,X6,X0,X2, X1,X3,X5,X7, 17,49,36,39)());
            mixin(THREEFISH_ENC_ROUND!(X6,X0,X2,X4, X1,X7,X5,X3, 44, 9,54,56)());
            mixin(THREEFISH_ENC_INJECT_KEY!(` ~ R1.stringof ~ `)());

            mixin(THREEFISH_ENC_ROUND!(X0,X2,X4,X6, X1,X3,X5,X7, 39,30,34,24)());
            mixin(THREEFISH_ENC_ROUND!(X2,X4,X6,X0, X1,X7,X5,X3, 13,50,10,17)());
            mixin(THREEFISH_ENC_ROUND!(X4,X6,X0,X2, X1,X3,X5,X7, 25,29,39,43)());
            mixin(THREEFISH_ENC_ROUND!(X6,X0,X2,X4, X1,X7,X5,X3,  8,35,56,22)());
            mixin(THREEFISH_ENC_INJECT_KEY!(` ~ R2.stringof ~ `)());`;
}

string THREEFISH_DEC_ROUND(alias _X0, alias _X1, alias _X2, alias _X3, 
                           alias _X4, alias _X5, alias _X6, alias _X7, 
                           ubyte _ROT1, ubyte _ROT2, ubyte _ROT3, ubyte _ROT4)()
{
    const X0 = __traits(identifier, _X0);
    const X1 = __traits(identifier, _X1);
    const X2 = __traits(identifier, _X2);
    const X3 = __traits(identifier, _X3);
    const X4 = __traits(identifier, _X4);
    const X5 = __traits(identifier, _X5);
    const X6 = __traits(identifier, _X6);
    const X7 = __traits(identifier, _X7);
    const ROT1 = _ROT1.stringof;
    const ROT2 = _ROT2.stringof;
    const ROT3 = _ROT3.stringof;
    const ROT4 = _ROT4.stringof;
    return X4 ~ `  ^= ` ~ X0 ~ `;
        ` ~ X5 ~ ` ^= ` ~ X1 ~ `;
        ` ~ X6 ~ ` ^= ` ~ X2 ~ `;
        ` ~ X7 ~ ` ^= ` ~ X3 ~ `;
        ` ~ X4 ~ ` = rotateRight(` ~ X4 ~ `, ` ~ ROT1 ~ `);
        ` ~ X5 ~ ` = rotateRight(` ~ X5 ~ `, ` ~ ROT2 ~ `);
        ` ~ X6 ~ ` = rotateRight(` ~ X6 ~ `, ` ~ ROT3 ~ `);
        ` ~ X7 ~ ` = rotateRight(` ~ X7 ~ `, ` ~ ROT4 ~ `);
        ` ~ X0 ~ ` -= ` ~ X4 ~ `;
        ` ~ X1 ~ ` -= ` ~ X5 ~ `;
        ` ~ X2 ~ ` -= ` ~ X6 ~ `;
        ` ~ X3 ~ ` -= ` ~ X7 ~ `;`;
}
    
string THREEFISH_DEC_INJECT_KEY(ushort r)() 
{
    return `X0 -= m_K[(` ~ r.stringof ~ `  ) % 9];
            X1 -= m_K[(` ~ (r+1).stringof ~ `) % 9];
            X2 -= m_K[(` ~ (r+2).stringof ~ `) % 9];
            X3 -= m_K[(` ~ (r+3).stringof ~ `) % 9];
            X4 -= m_K[(` ~ (r+4).stringof ~ `) % 9];
            X5 -= m_K[(` ~ (r+5).stringof ~ `) % 9] + m_T[(` ~ r.stringof ~ `  ) % 3];
            X6 -= m_K[(` ~ (r+6).stringof ~ `) % 9] + m_T[(` ~ (r+1).stringof ~ `) % 3];
            X7 -= m_K[(` ~ (r+7).stringof ~ `) % 9] + (` ~ r.stringof ~ `);`;
}

string THREEFISH_DEC_8_ROUNDS(ushort R1, ushort R2)()
{
    return `mixin(THREEFISH_DEC_ROUND!(X6,X0,X2,X4, X1,X7,X5,X3,  8,35,56,22)());
            mixin(THREEFISH_DEC_ROUND!(X4,X6,X0,X2, X1,X3,X5,X7, 25,29,39,43)());
            mixin(THREEFISH_DEC_ROUND!(X2,X4,X6,X0, X1,X7,X5,X3, 13,50,10,17)());
            mixin(THREEFISH_DEC_ROUND!(X0,X2,X4,X6, X1,X3,X5,X7, 39,30,34,24)());
            mixin(THREEFISH_DEC_INJECT_KEY!(` ~ R1.stringof ~ `)());
            
            mixin(THREEFISH_DEC_ROUND!(X6,X0,X2,X4, X1,X7,X5,X3, 44, 9,54,56)());
            mixin(THREEFISH_DEC_ROUND!(X4,X6,X0,X2, X1,X3,X5,X7, 17,49,36,39)());
            mixin(THREEFISH_DEC_ROUND!(X2,X4,X6,X0, X1,X7,X5,X3, 33,27,14,42)());
            mixin(THREEFISH_DEC_ROUND!(X0,X2,X4,X6, X1,X3,X5,X7, 46,36,19,37)());
            mixin(THREEFISH_DEC_INJECT_KEY!(` ~ R2.stringof ~ `)());`;
}

