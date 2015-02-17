/**
* MD4 (x86-32)
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.hash.md4_x86_32;

import botan.constants;
static if (BOTAN_HAS_MD4_X86_32):

import botan.utils.asm_x86_32.asm_x86_32;
import botan.hash.md4;
import botan.hash.hash;

/**
* MD4 using x86 assembly
*/
class MD4_X86_32 : MD4
{
public:
    override HashFunction clone() const { return new MD4_X86_32; }

protected:
    /*
    * MD4 Compression Function
    */
    override void compressN(const(ubyte)* input, size_t blocks)
    {
        foreach (size_t i; 0 .. blocks)
        {
            botan_md4_x86_32_compress(m_digest.ptr, input, m_M.ptr);
            input += hashBlockSize;
        }
    }
}

private:
/**
* MD4 compression function in x86-32 asm
* Params:
*  digest = the current digest
*  input = the input block
*  M = the message buffer
*/
extern(C)
void botan_md4_x86_32_compress(uint* digest, const(ubyte)* input, uint* M)
{
    enum PUSHED = 4;
    enum ASM = START_ASM ~ 
            "naked;" ~
            SPILL_REGS() ~ 
            ASSIGN(EBP, ARG(PUSHED, 2)) ~/* input block */
            ASSIGN(EDI, ARG(PUSHED, 3)) ~ /* expanded words */

            ZEROIZE(ESI) ~

            START_LOOP("LOAD_INPUT") ~
            ADD_IMM(ESI, 4) ~

            ASSIGN(EAX, ARRAY4(EBP, 0)) ~
            ASSIGN(EBX, ARRAY4(EBP, 1)) ~
            ASSIGN(ECX, ARRAY4(EBP, 2)) ~
            ASSIGN(EDX, ARRAY4(EBP, 3)) ~

            ADD_IMM(EBP, 16) ~

            ASSIGN(ARRAY4_INDIRECT(EDI,ESI,-4), EAX) ~
            ASSIGN(ARRAY4_INDIRECT(EDI,ESI,-3), EBX) ~
            ASSIGN(ARRAY4_INDIRECT(EDI,ESI,-2), ECX) ~
            ASSIGN(ARRAY4_INDIRECT(EDI,ESI,-1), EDX) ~
            LOOP_UNTIL_EQ(ESI, 16, "LOAD_INPUT") ~

            ASSIGN(EBP, ARG(PUSHED, 1)) ~
            ASSIGN(EAX, ARRAY4(EBP, 0)) ~
            ASSIGN(EBX, ARRAY4(EBP, 1)) ~
            ASSIGN(ECX, ARRAY4(EBP, 2)) ~
            ASSIGN(EDX, ARRAY4(EBP, 3)) ~

            FF(EAX,EBX,ECX,EDX, 0, 3) ~
            FF(EDX,EAX,EBX,ECX, 1, 7) ~
            FF(ECX,EDX,EAX,EBX, 2,11) ~
            FF(EBX,ECX,EDX,EAX, 3,19) ~
            FF(EAX,EBX,ECX,EDX, 4, 3) ~
            FF(EDX,EAX,EBX,ECX, 5, 7) ~
            FF(ECX,EDX,EAX,EBX, 6,11) ~
            FF(EBX,ECX,EDX,EAX, 7,19) ~
            FF(EAX,EBX,ECX,EDX, 8, 3) ~
            FF(EDX,EAX,EBX,ECX, 9, 7) ~
            FF(ECX,EDX,EAX,EBX,10,11) ~
            FF(EBX,ECX,EDX,EAX,11,19) ~
            FF(EAX,EBX,ECX,EDX,12, 3) ~
            FF(EDX,EAX,EBX,ECX,13, 7) ~
            FF(ECX,EDX,EAX,EBX,14,11) ~
            FF(EBX,ECX,EDX,EAX,15,19) ~

            GG(EAX,EBX,ECX,EDX, 0, 3) ~
            GG(EDX,EAX,EBX,ECX, 4, 5) ~
            GG(ECX,EDX,EAX,EBX, 8, 9) ~
            GG(EBX,ECX,EDX,EAX,12,13) ~
            GG(EAX,EBX,ECX,EDX, 1, 3) ~
            GG(EDX,EAX,EBX,ECX, 5, 5) ~
            GG(ECX,EDX,EAX,EBX, 9, 9) ~
            GG(EBX,ECX,EDX,EAX,13,13) ~
            GG(EAX,EBX,ECX,EDX, 2, 3) ~
            GG(EDX,EAX,EBX,ECX, 6, 5) ~
            GG(ECX,EDX,EAX,EBX,10, 9) ~
            GG(EBX,ECX,EDX,EAX,14,13) ~
            GG(EAX,EBX,ECX,EDX, 3, 3) ~
            GG(EDX,EAX,EBX,ECX, 7, 5) ~
            GG(ECX,EDX,EAX,EBX,11, 9) ~
            GG(EBX,ECX,EDX,EAX,15,13) ~

            HH(EAX,EBX,ECX,EDX, 0, 3) ~
            HH(EDX,EAX,EBX,ECX, 8, 9) ~
            HH(ECX,EDX,EAX,EBX, 4,11) ~
            HH(EBX,ECX,EDX,EAX,12,15) ~
            HH(EAX,EBX,ECX,EDX, 2, 3) ~
            HH(EDX,EAX,EBX,ECX,10, 9) ~
            HH(ECX,EDX,EAX,EBX, 6,11) ~
            HH(EBX,ECX,EDX,EAX,14,15) ~
            HH(EAX,EBX,ECX,EDX, 1, 3) ~
            HH(EDX,EAX,EBX,ECX, 9, 9) ~
            HH(ECX,EDX,EAX,EBX, 5,11) ~
            HH(EBX,ECX,EDX,EAX,13,15) ~
            HH(EAX,EBX,ECX,EDX, 3, 3) ~
            HH(EDX,EAX,EBX,ECX,11, 9) ~
            HH(ECX,EDX,EAX,EBX, 7,11) ~
            HH(EBX,ECX,EDX,EAX,15,15) ~

            ASSIGN(EBP, ARG(PUSHED, 1)) ~
            ADD(ARRAY4(EBP, 0), EAX) ~
            ADD(ARRAY4(EBP, 1), EBX) ~
            ADD(ARRAY4(EBP, 2), ECX) ~
            ADD(ARRAY4(EBP, 3), EDX) ~
            RESTORE_REGS() ~
            "ret;" ~
            END_ASM;
    mixin(ASM);
}


enum MSG = EDI;
enum T1 = ESI;
enum T2 = EBP;
        
string FF(string A, string B, string C, string D, ubyte N, ubyte S) {
    return  ASSIGN(T1, ARRAY4(MSG, N))~
            ASSIGN(T2, C)~
            XOR(T2, D)    ~
            AND(T2, B)    ~
            XOR(T2, D)    ~
            ADD(A, T1)    ~
            ADD(A, T2)    ~
            ROTL_IMM(A, S);
}

string GG(string A, string B, string C, string D, ubyte N, ubyte S) {
    return  ASSIGN(T1, ARRAY4(MSG, N)) ~
            ASSIGN(T2, B) ~
            OR(T2, C)         ~
            AND(T2, D)     ~
            ADD3_IMM(A, T1, 0x5A827999) ~
            ASSIGN(T1, B) ~
            AND(T1, C)     ~
            OR(T2, T1)     ~
            ADD(A, T2)     ~
            ROTL_IMM(A, S);
}
string HH(string A, string B, string C, string D, ubyte N, ubyte S) {
    return  ASSIGN(T1, ARRAY4(MSG, N)) ~
            ASSIGN(T2, B) ~
            XOR(T2, C)     ~
            XOR(T2, D)     ~
            ADD3_IMM(A, T1, 0x6ED9EBA1) ~
            ADD(A, T2)     ~
            ROTL_IMM(A, S);
}