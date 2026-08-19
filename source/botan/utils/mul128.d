/**
* 64x64.128 bit multiply operation
* 
* Copyright:
* (C) 2013 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.utils.mul128;
import botan.constants;
import botan.utils.types;

// LDC also defines D_InlineAsm_X86_64, but the DMD Intel path takes
// addresses of the result slots. Prefer GCC-style mulq so LLVM keeps
// the product in RDX:RAX.
version (LDC)
{
    version (X86_64)
        enum BotanLdcX64Asm = true;
    else
        enum BotanLdcX64Asm = false;
}
else
    enum BotanLdcX64Asm = false;

/**
* Perform a 64x64.128 bit multiplication
*/
void mul64x64_128(ulong a, ulong b, ref ulong[2] res) pure
{
    static if (BotanLdcX64Asm) {
        ulong lo, hi;
        asm pure nothrow @nogc {
            "movq %2, %%rax\n\tmulq %3"
            : "=&a"(lo), "=&d"(hi)
            : "r"(a), "r"(b)
            : "cc";
        }
        res[0] = lo;
        res[1] = hi;
    }
    else version (D_InlineAsm_X86_64) {
        ulong* lo = res.ptr;
        ulong* hi = &res[1];
        asm pure nothrow @nogc {
            mov RAX, a;
            mul b;
            mov RBX, lo;
            mov RCX, hi;
            mov [RBX], RAX;
            mov [RCX], RDX;
        }
    }
    else {
        /*
        * Do a 64x64->128 multiply using four 32x32->64 multiplies plus
        * some adds and shifts. Last resort for CPUs like UltraSPARC (with
        * 64-bit registers/ALU, but no 64x64->128 multiply) or 32-bit CPUs.
       */
        const size_t HWORD_BITS = 32;
        const uint HWORD_MASK = 0xFFFFFFFF;
        
        const uint a_hi = (a >> HWORD_BITS);
        const uint a_lo = (a  & HWORD_MASK);
        const uint b_hi = (b >> HWORD_BITS);
        const uint b_lo = (b  & HWORD_MASK);
        
        ulong x0 = cast(ulong)(a_hi) * b_hi;
        ulong x1 = cast(ulong)(a_lo) * b_hi;
        ulong x2 = cast(ulong)(a_hi) * b_lo;
        ulong x3 = cast(ulong)(a_lo) * b_lo;
        
        // this cannot overflow as (2^32-1)^2 + 2^32-1 < 2^64-1
        x2 += x3 >> HWORD_BITS;
        
        // this one can overflow
        x2 += x1;
        
        // propagate the carry if any
        x0 += cast(ulong)(cast(bool)(x2 < x1)) << HWORD_BITS;
        
        res[1] = x0 + (x2 >> HWORD_BITS);
        res[0]  = ((x2 & HWORD_MASK) << HWORD_BITS) + (x3 & HWORD_MASK);
    }
}