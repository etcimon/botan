/**
* Lightweight wrappers around AltiVec for 32-bit operations
* 
* Copyright:
* (C) 2009 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.simd.simd_altivec;

import botan.constants;
static if (BOTAN_HAS_SIMD_ALTIVEC):

import botan.utils.loadstor;
import botan.utils.cpuid;
import botan.utils.simd.altivec;

struct SIMDAltivec
{
public:
    static bool enabled() { return CPUID.hasAltivec(); }

    this(in uint[4] B)
    {
        m_reg = [B[0], B[1], B[2], B[3]];
    }

    this(uint B0, uint B1, uint B2, uint B3)
    {
        m_reg = [B0, B1, B2, B3];
    }

    this(uint B)
    {
        m_reg = [B, B, B, B];
    }

    static SIMDAltivec loadLittleEndian(in void* input)
    {
        const uint* in_32 = cast(const uint*)(input);

        vector_uint R0 = vec_ld(0, in_32);
        vector_uint R1 = vec_ld(12, in_32);

        vector_byte perm = vec_lvsl(0, in_32);

        perm = vec_xor(perm, vec_splat_u8(3));

        R0 = vec_perm(R0, R1, perm);

        return SIMDAltivec(R0);
    }

    static SIMDAltivec loadBigEndian(in void* input)
    {
        const uint* in_32 = cast(const uint*)(input);

        vector_uint R0 = vec_ld(0, in_32);
        vector_uint R1 = vec_ld(12, in_32);

        vector_byte perm = vec_lvsl(0, in_32);

        R0 = vec_perm(R0, R1, perm);

        return SIMDAltivec(R0);
    }

    void storeLittleEndian(ubyte* output)
    {
        vector_byte perm = vec_lvsl(0, null);

        perm = vec_xor(perm, vec_splat_u8(3));

        union {
            vector_uint V;
            uint[4] R;
        } vec;

        vec.V = vec_perm(m_reg, m_reg, perm);

        .storeBigEndian(output, vec.R[0], vec.R[1], vec.R[2], vec.R[3]);
    }

    void storeBigEndian(ubyte* output)
    {
        union {
            vector_uint V;
            uint[4] R;
        } vec;

        vec.V = m_reg;

        .storeBigEndian(output, vec.R[0], vec.R[1], vec.R[2], vec.R[3]);
    }

    void rotateLeft(int rot)()
    {
        vector_uint rot_vec = vector_uint([rot, rot, rot, rot]);

        m_reg = vec_rl(m_reg, rot_vec);
    }

    void rotateRight(int rot)()
    {
        this.rotateLeft!(32 - rot)();
    }

    void opOpAssign(string op)(in SIMDAltivec other)
        if (op == "+")
    {
        m_reg = vec_add(m_reg, other.m_reg);
    }

    SIMDAltivec opBinary(string op)(in SIMDAltivec other)
        if (op == "+")
    {
        return SIMDAltivec(vec_add(m_reg, other.m_reg));
    }

    void opOpAssign(string op)(in SIMDAltivec other)
        if (op == "-")
    {
        m_reg = vec_sub(m_reg, other.m_reg);
    }

    SIMDAltivec opBinary(string op)(in SIMDAltivec other)
        if (op == "-")
    {
        return SIMDAltivec(vec_sub(m_reg, other.m_reg));
    }

    void opOpAssign(string op)(in SIMDAltivec other)
        if (op == "^")
    {
        m_reg = vec_xor(m_reg, other.m_reg);
    }

    SIMDAltivec opBinary(string op)(in SIMDAltivec other)
        if (op == "^")
    {
        return SIMDAltivec(vec_xor(m_reg, other.m_reg));
    }

    void opOpAssign(string op)(in SIMDAltivec other)
        if (op == "|")
    {
        m_reg = vec_or(m_reg, other.m_reg);
    }

    SIMDAltivec opBinary(string op)(in SIMDAltivec other)
        if (op == "&")
    {
        return SIMDAltivec(vec_and(m_reg, other.m_reg));
    }

    void opOpAssign(string op)(in SIMDAltivec other)
        if (op == "&")
    {
        m_reg = vec_and(m_reg, other.m_reg);
    }

    SIMDAltivec lshift(int shift_)()
    {
        uint shift = cast(uint) shift_;
        vector_uint shift_vec = vector_uint([shift, shift, shift, shift]);

        return SIMDAltivec(vec_sl(m_reg, shift_vec));
    }

    SIMDAltivec rshift(int shift_)()
    {
        uint shift = cast(uint) shift_;
        vector_uint shift_vec = vector_uint([shift, shift, shift, shift]);

        return SIMDAltivec(vec_sr(m_reg, shift_vec));
    }

    SIMDAltivec opUnary(string op)()
        if (op == "~")
    {
        return SIMDAltivec(vec_nor(m_reg, m_reg));
    }

    SIMDAltivec andc(in SIMDAltivec other)
    {
        // AltiVec does arg1 & ~arg2 rather than SSE's ~arg1 & arg2
        return SIMDAltivec(vec_andc(other.m_reg, m_reg));
    }

    SIMDAltivec bswap()
    {
        vector_byte perm = vec_lvsl(0, null);

        perm = vec_xor(perm, vec_splat_u8(3));

        return SIMDAltivec(vec_perm(m_reg, m_reg, perm));
    }

    static void transpose(ref SIMDAltivec B0, ref SIMDAltivec B1,
                          ref SIMDAltivec B2, ref SIMDAltivec B3)
    {
        vector_uint T0 = vec_mergeh(B0.m_reg, B2.m_reg);
        vector_uint T1 = vec_mergel(B0.m_reg, B2.m_reg);
        vector_uint T2 = vec_mergeh(B1.m_reg, B3.m_reg);
        vector_uint T3 = vec_mergel(B1.m_reg, B3.m_reg);

        B0.m_reg = vec_mergeh(T0, T2);
        B1.m_reg = vec_mergel(T0, T2);
        B2.m_reg = vec_mergeh(T1, T3);
        B3.m_reg = vec_mergel(T1, T3);
    }

private:
    this(vector_uint input) { m_reg = input; }

    vector_uint m_reg;
}
