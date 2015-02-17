/**
* SHA-160 in x86-32 asm
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.hash.sha1_x86_32;

import botan.constants;
static if (BOTAN_HAS_SHA1 && BOTAN_HAS_SHA1_X86_32):

import botan.hash.sha160;
import botan.utils.asm_x86_32.asm_x86_32;
import botan.hash.hash;

/**
* SHA-160 in x86 assembly
*/
class SHA160_X86_32 : SHA160
{
public:
    override HashFunction clone() const { return new SHA160_X86_32; }

    // Note 81 instead of normal 80: x86-32 asm needs an extra temp
    this() 
    {
        super(81);
    }

protected:
    /*
    * SHA-160 Compression Function
    */
    override void compressN(const(ubyte)* input, size_t blocks)
    {
        foreach (size_t i; 0 .. blocks)
        {
            botan_sha160_x86_32_compress(m_digest.ptr, input, m_W.ptr);
            input += hashBlockSize;
        }
    }

}

private:
extern(C)
void botan_sha160_x86_32_compress(uint* arg1, const(ubyte)* arg2, uint* arg3) pure
{
    enum PUSHED = 4;
    enum ASM =
          START_ASM ~ 
          "naked;" ~
          SPILL_REGS() ~ 
          ASSIGN(EDI, ARG(PUSHED, 2)) ~
          ASSIGN(EBP, ARG(PUSHED, 3)) ~
          
          ZEROIZE(ESI) ~
          
          START_LOOP("LOAD_INPUT") ~
          ADD_IMM(ESI, 4) ~
          
          ASSIGN(EAX, ARRAY4(EDI, 0)) ~
          ASSIGN(EBX, ARRAY4(EDI, 1)) ~
          ASSIGN(ECX, ARRAY4(EDI, 2)) ~
          ASSIGN(EDX, ARRAY4(EDI, 3)) ~
          
          ADD_IMM(EDI, 16) ~
          
          BSWAP(EAX) ~
          BSWAP(EBX) ~
          BSWAP(ECX) ~
          BSWAP(EDX) ~
          
          ASSIGN(ARRAY4_INDIRECT(EBP,ESI,-4), EAX) ~
          ASSIGN(ARRAY4_INDIRECT(EBP,ESI,-3), EBX) ~
          ASSIGN(ARRAY4_INDIRECT(EBP,ESI,-2), ECX) ~
          ASSIGN(ARRAY4_INDIRECT(EBP,ESI,-1), EDX) ~
          LOOP_UNTIL_EQ(ESI, 16, "LOAD_INPUT") ~
          
          ADD2_IMM(EDI, EBP, 64) ~
          
          START_LOOP("L_SHA_EXPANSION") ~
          ADD_IMM(ESI, 4) ~
          
          ZEROIZE(EAX) ~
          ASSIGN(EBX, ARRAY4(EDI, -1)) ~
          ASSIGN(ECX, ARRAY4(EDI, -2)) ~
          ASSIGN(EDX, ARRAY4(EDI, -3)) ~
          
          XOR(EAX, ARRAY4(EDI, -5)) ~
          XOR(EBX, ARRAY4(EDI, -6)) ~
          XOR(ECX, ARRAY4(EDI, -7)) ~
          XOR(EDX, ARRAY4(EDI, -8)) ~
          
          XOR(EAX, ARRAY4(EDI, -11)) ~
          XOR(EBX, ARRAY4(EDI, -12)) ~
          XOR(ECX, ARRAY4(EDI, -13)) ~
          XOR(EDX, ARRAY4(EDI, -14)) ~
          
          XOR(EAX, ARRAY4(EDI, -13)) ~
          XOR(EBX, ARRAY4(EDI, -14)) ~
          XOR(ECX, ARRAY4(EDI, -15)) ~
          XOR(EDX, ARRAY4(EDI, -16)) ~
          
          ROTL_IMM(EDX, 1) ~
          ROTL_IMM(ECX, 1) ~
          ROTL_IMM(EBX, 1) ~
          XOR(EAX, EDX) ~
          ROTL_IMM(EAX, 1) ~
          
          ASSIGN(ARRAY4(EDI, 0), EDX) ~
          ASSIGN(ARRAY4(EDI, 1), ECX) ~
          ASSIGN(ARRAY4(EDI, 2), EBX) ~
          ASSIGN(ARRAY4(EDI, 3), EAX) ~
          
          ADD_IMM(EDI, 16) ~
          LOOP_UNTIL_EQ(ESI, 80, "L_SHA_EXPANSION") ~
          
          ASSIGN(EAX, ARG(PUSHED, 1)) ~
          ASSIGN(EDI, ARRAY4(EAX, 0)) ~
          ASSIGN(EBX, ARRAY4(EAX, 1)) ~
          ASSIGN(ECX, ARRAY4(EAX, 2)) ~
          ASSIGN(EDX, ARRAY4(EAX, 3)) ~
          ASSIGN(ESI, ARRAY4(EAX, 4)) ~
          
          ASSIGN(ARRAY4(EBP, 80), ESP) ~
          ASSIGN(ESP, EBP) ~
          
          /* First Round */
          F1(EAX, EBX, ECX, EDX, ESI, EDI, 0) ~
          F1(EDI, EAX, EBX, ECX, EDX, ESI, 1) ~
          F1(ESI, EDI, EAX, EBX, ECX, EDX, 2) ~
          F1(EDX, ESI, EDI, EAX, EBX, ECX, 3) ~
          F1(ECX, EDX, ESI, EDI, EAX, EBX, 4) ~
          F1(EBX, ECX, EDX, ESI, EDI, EAX, 5) ~
          F1(EAX, EBX, ECX, EDX, ESI, EDI, 6) ~
          F1(EDI, EAX, EBX, ECX, EDX, ESI, 7) ~
          F1(ESI, EDI, EAX, EBX, ECX, EDX, 8) ~
          F1(EDX, ESI, EDI, EAX, EBX, ECX, 9) ~
          F1(ECX, EDX, ESI, EDI, EAX, EBX, 10) ~
          F1(EBX, ECX, EDX, ESI, EDI, EAX, 11) ~
          F1(EAX, EBX, ECX, EDX, ESI, EDI, 12) ~
          F1(EDI, EAX, EBX, ECX, EDX, ESI, 13) ~
          F1(ESI, EDI, EAX, EBX, ECX, EDX, 14) ~
          F1(EDX, ESI, EDI, EAX, EBX, ECX, 15) ~
          F1(ECX, EDX, ESI, EDI, EAX, EBX, 16) ~
          F1(EBX, ECX, EDX, ESI, EDI, EAX, 17) ~
          F1(EAX, EBX, ECX, EDX, ESI, EDI, 18) ~
          F1(EDI, EAX, EBX, ECX, EDX, ESI, 19) ~
          
          /* Second Round */
          F2(ESI, EDI, EAX, EBX, ECX, EDX, 20) ~
          F2(EDX, ESI, EDI, EAX, EBX, ECX, 21) ~
          F2(ECX, EDX, ESI, EDI, EAX, EBX, 22) ~
          F2(EBX, ECX, EDX, ESI, EDI, EAX, 23) ~
          F2(EAX, EBX, ECX, EDX, ESI, EDI, 24) ~
          F2(EDI, EAX, EBX, ECX, EDX, ESI, 25) ~
          F2(ESI, EDI, EAX, EBX, ECX, EDX, 26) ~
          F2(EDX, ESI, EDI, EAX, EBX, ECX, 27) ~
          F2(ECX, EDX, ESI, EDI, EAX, EBX, 28) ~
          F2(EBX, ECX, EDX, ESI, EDI, EAX, 29) ~
          F2(EAX, EBX, ECX, EDX, ESI, EDI, 30) ~
          F2(EDI, EAX, EBX, ECX, EDX, ESI, 31) ~
          F2(ESI, EDI, EAX, EBX, ECX, EDX, 32) ~
          F2(EDX, ESI, EDI, EAX, EBX, ECX, 33) ~
          F2(ECX, EDX, ESI, EDI, EAX, EBX, 34) ~
          F2(EBX, ECX, EDX, ESI, EDI, EAX, 35) ~
          F2(EAX, EBX, ECX, EDX, ESI, EDI, 36) ~
          F2(EDI, EAX, EBX, ECX, EDX, ESI, 37) ~
          F2(ESI, EDI, EAX, EBX, ECX, EDX, 38) ~
          F2(EDX, ESI, EDI, EAX, EBX, ECX, 39) ~
          
          /* Third Round */
          F3(ECX, EDX, ESI, EDI, EAX, EBX, 40) ~
          F3(EBX, ECX, EDX, ESI, EDI, EAX, 41) ~
          F3(EAX, EBX, ECX, EDX, ESI, EDI, 42) ~
          F3(EDI, EAX, EBX, ECX, EDX, ESI, 43) ~
          F3(ESI, EDI, EAX, EBX, ECX, EDX, 44) ~
          F3(EDX, ESI, EDI, EAX, EBX, ECX, 45) ~
          F3(ECX, EDX, ESI, EDI, EAX, EBX, 46) ~
          F3(EBX, ECX, EDX, ESI, EDI, EAX, 47) ~
          F3(EAX, EBX, ECX, EDX, ESI, EDI, 48) ~
          F3(EDI, EAX, EBX, ECX, EDX, ESI, 49) ~
          F3(ESI, EDI, EAX, EBX, ECX, EDX, 50) ~
          F3(EDX, ESI, EDI, EAX, EBX, ECX, 51) ~
          F3(ECX, EDX, ESI, EDI, EAX, EBX, 52) ~
          F3(EBX, ECX, EDX, ESI, EDI, EAX, 53) ~
          F3(EAX, EBX, ECX, EDX, ESI, EDI, 54) ~
          F3(EDI, EAX, EBX, ECX, EDX, ESI, 55) ~
          F3(ESI, EDI, EAX, EBX, ECX, EDX, 56) ~
          F3(EDX, ESI, EDI, EAX, EBX, ECX, 57) ~
          F3(ECX, EDX, ESI, EDI, EAX, EBX, 58) ~
          F3(EBX, ECX, EDX, ESI, EDI, EAX, 59) ~
          
          /* Fourth Round */
          F4(EAX, EBX, ECX, EDX, ESI, EDI, 60) ~
          F4(EDI, EAX, EBX, ECX, EDX, ESI, 61) ~
          F4(ESI, EDI, EAX, EBX, ECX, EDX, 62) ~
          F4(EDX, ESI, EDI, EAX, EBX, ECX, 63) ~
          F4(ECX, EDX, ESI, EDI, EAX, EBX, 64) ~
          F4(EBX, ECX, EDX, ESI, EDI, EAX, 65) ~
          F4(EAX, EBX, ECX, EDX, ESI, EDI, 66) ~
          F4(EDI, EAX, EBX, ECX, EDX, ESI, 67) ~
          F4(ESI, EDI, EAX, EBX, ECX, EDX, 68) ~
          F4(EDX, ESI, EDI, EAX, EBX, ECX, 69) ~
          F4(ECX, EDX, ESI, EDI, EAX, EBX, 70) ~
          F4(EBX, ECX, EDX, ESI, EDI, EAX, 71) ~
          F4(EAX, EBX, ECX, EDX, ESI, EDI, 72) ~
          F4(EDI, EAX, EBX, ECX, EDX, ESI, 73) ~
          F4(ESI, EDI, EAX, EBX, ECX, EDX, 74) ~
          F4(EDX, ESI, EDI, EAX, EBX, ECX, 75) ~
          F4(ECX, EDX, ESI, EDI, EAX, EBX, 76) ~
          F4(EBX, ECX, EDX, ESI, EDI, EAX, 77) ~
          F4(EAX, EBX, ECX, EDX, ESI, EDI, 78) ~
          F4(EDI, EAX, EBX, ECX, EDX, ESI, 79) ~
          
          ASSIGN(ESP, ARRAY4(ESP, 80)) ~
          
          ASSIGN(EBP, ARG(PUSHED, 1)) ~
          ADD(ARRAY4(EBP, 0), EDX) ~
          ADD(ARRAY4(EBP, 1), EDI) ~
          ADD(ARRAY4(EBP, 2), EAX) ~
          ADD(ARRAY4(EBP, 3), EBX) ~
          ADD(ARRAY4(EBP, 4), ECX) ~

          RESTORE_REGS() ~
          "ret;"~
          END_ASM;
    mixin(ASM);
}

enum MAGIC1 = 0x5A827999;
enum MAGIC2 = 0x6ED9EBA1;
enum MAGIC3 = 0x8F1BBCDC;
enum MAGIC4 = 0xCA62C1D6;

enum MSG = ESP;
enum T2 = EBP;

string F1(string A, string B, string C, string D, string E, string F, ubyte N) 
{
    return  ASSIGN(T2, ARRAY4(MSG, N)) ~
            ASSIGN(A, F) ~
            ROTL_IMM(F, 5) ~
            ADD(F, E) ~
            ASSIGN(E, C)     ~
            XOR(E, D) ~
            ADD3_IMM(F, T2, MAGIC1)     ~
            AND(E, B) ~
            XOR(E, D) ~
            ROTR_IMM(B, 2) ~
            ADD(E, F);
}

string F2_4(string A, string B, string C, string D, string E, string F, ubyte N, int MAGIC)
{
    return  ASSIGN(T2, ARRAY4(MSG, N)) ~
            ASSIGN(A, F)     ~
            ROTL_IMM(F, 5) ~
            ADD(F, E) ~
            ASSIGN(E, B)     ~
            XOR(E, C) ~
            ADD3_IMM(F, T2, MAGIC)     ~
            XOR(E, D) ~
            ROTR_IMM(B, 2) ~
            ADD(E, F);
}

string F3(string A, string B, string C, string D, string E, string F, ubyte N)
{
    return  ASSIGN(T2, ARRAY4(MSG, N)) ~
            ASSIGN(A, F)     ~
            ROTL_IMM(F, 5) ~
            ADD(F, E) ~
            ASSIGN(E, B)     ~
            OR(E, C) ~
            AND(E, D) ~
            ADD3_IMM(F, T2, MAGIC3)     ~
            ASSIGN(T2, B) ~
            AND(T2, C)     ~
            OR(E, T2) ~
            ROTR_IMM(B, 2) ~
            ADD(E, F);
}

string F2(string A, string B, string C, string D, string E, string F, ubyte MSG2)
{
    return F2_4(A, B, C, D, E, F, MSG2, MAGIC2);
}

string F4(string A, string B, string C, string D, string E, string F, ubyte MSG2)
{
    return F2_4(A, B, C, D, E, F, MSG2, MAGIC4);
}