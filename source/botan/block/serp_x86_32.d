/**
* Serpent in x86-32 asm
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.block.serp_x86_32;

import botan.constants;
static if (BOTAN_HAS_SERPENT_X86_32):

import botan.block.serpent;
import botan.utils.loadstor;
import botan.utils.asm_x86_32.asm_x86_32;
import botan.block.block_cipher;
import botan.utils.mem_ops;

/**
* Serpent implementation in x86-32 assembly
*/
final class Serpent_X86_32 : Serpent
{
public:
    /*
    * Serpent Encryption
    */
    override void encryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        auto keys = this.getRoundKeys().ptr;
        
        foreach (size_t i; 0 .. blocks)
        {
            botan_serpent_x86_32_encrypt(input, output, keys);
            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }
    /*
    * Serpent Decryption
    */
    override void decryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        auto keys = this.getRoundKeys().ptr;
        
        foreach (size_t i; 0 .. blocks)
        {
            botan_serpent_x86_32_decrypt(input, output, keys);
            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }

    override @property size_t parallelism() const { return 1; }
    override BlockCipher clone() const { return new Serpent_X86_32; }
protected:
    /*
    * Serpent Key Schedule
    */
    override void keySchedule(const(ubyte)* key, size_t length)
    {
        SecureVector!uint W = SecureVector!uint(140);
        foreach (size_t i; 0 .. (length / 4))
            W[i] = loadLittleEndian!uint(key, i);
        W[length / 4] |= uint(1) << ((length%4)*8);
        
        botan_serpent_x86_32_key_schedule(W.ptr);
        this.setRoundKeys(*cast(uint[132]*) &W[8]);
    }

}

/**
* Entry point for Serpent encryption in x86 asm
* Params:
*  input = the input block
*  output = the output block
*  ks = the key schedule
*/
extern(C)
void botan_serpent_x86_32_encrypt(const(ubyte)* input, ubyte* output, in uint* ks ) pure
{

    enum PUSHED = 4;
    enum ASM = START_ASM ~
          "naked;\n" ~
          SPILL_REGS() ~
          ASSIGN(EBP, ARG(PUSHED, 1)) /* input block */ ~
          ASSIGN(EAX, ARRAY4(EBP, 0)) ~
          ASSIGN(EBX, ARRAY4(EBP, 1)) ~
          ASSIGN(ECX, ARRAY4(EBP, 2)) ~
          ASSIGN(EDX, ARRAY4(EBP, 3)) ~
          
          ASSIGN(EDI, ARG(PUSHED, 3))  ~ /* round keys */
          ZEROIZE(EBP) ~
          
          E_ROUND!SBOX_E1(EAX, EBX, ECX, EDX, EBP,  0 ) ~
          E_ROUND!SBOX_E2(EAX, EBX, ECX, EDX, EBP,  1 ) ~
          E_ROUND!SBOX_E3(EAX, EBX, ECX, EDX, EBP,  2 ) ~
          E_ROUND!SBOX_E4(EAX, EBX, ECX, EDX, EBP,  3 ) ~
          E_ROUND!SBOX_E5(EAX, EBX, ECX, EDX, EBP,  4 ) ~
          E_ROUND!SBOX_E6(EAX, EBX, ECX, EDX, EBP,  5 ) ~
          E_ROUND!SBOX_E7(EAX, EBX, ECX, EDX, EBP,  6 ) ~
          E_ROUND!SBOX_E8(EAX, EBX, ECX, EDX, EBP,  7 ) ~
          
          E_ROUND!SBOX_E1(EAX, EBX, ECX, EDX, EBP,  8 ) ~
          E_ROUND!SBOX_E2(EAX, EBX, ECX, EDX, EBP,  9 ) ~
          E_ROUND!SBOX_E3(EAX, EBX, ECX, EDX, EBP, 10 ) ~
          E_ROUND!SBOX_E4(EAX, EBX, ECX, EDX, EBP, 11 ) ~
          E_ROUND!SBOX_E5(EAX, EBX, ECX, EDX, EBP, 12 ) ~
          E_ROUND!SBOX_E6(EAX, EBX, ECX, EDX, EBP, 13 ) ~
          E_ROUND!SBOX_E7(EAX, EBX, ECX, EDX, EBP, 14 ) ~
          E_ROUND!SBOX_E8(EAX, EBX, ECX, EDX, EBP, 15 ) ~
          
          E_ROUND!SBOX_E1(EAX, EBX, ECX, EDX, EBP, 16 ) ~
          E_ROUND!SBOX_E2(EAX, EBX, ECX, EDX, EBP, 17 ) ~
          E_ROUND!SBOX_E3(EAX, EBX, ECX, EDX, EBP, 18 ) ~
          E_ROUND!SBOX_E4(EAX, EBX, ECX, EDX, EBP, 19 ) ~
          E_ROUND!SBOX_E5(EAX, EBX, ECX, EDX, EBP, 20 ) ~
          E_ROUND!SBOX_E6(EAX, EBX, ECX, EDX, EBP, 21 ) ~
          E_ROUND!SBOX_E7(EAX, EBX, ECX, EDX, EBP, 22 ) ~
          E_ROUND!SBOX_E8(EAX, EBX, ECX, EDX, EBP, 23 ) ~
          
          E_ROUND!SBOX_E1(EAX, EBX, ECX, EDX, EBP, 24 ) ~
          E_ROUND!SBOX_E2(EAX, EBX, ECX, EDX, EBP, 25 ) ~
          E_ROUND!SBOX_E3(EAX, EBX, ECX, EDX, EBP, 26 ) ~
          E_ROUND!SBOX_E4(EAX, EBX, ECX, EDX, EBP, 27 ) ~
          E_ROUND!SBOX_E5(EAX, EBX, ECX, EDX, EBP, 28 ) ~
          E_ROUND!SBOX_E6(EAX, EBX, ECX, EDX, EBP, 29 ) ~
          E_ROUND!SBOX_E7(EAX, EBX, ECX, EDX, EBP, 30 ) ~
          
          KEY_XOR(EAX, EBX, ECX, EDX, 31) ~
          SBOX_E8(EAX, EBX, ECX, EDX, EBP) ~
          KEY_XOR(EAX, EBX, ECX, EDX, 32) ~
          
          ASSIGN(EBP, ARG(PUSHED, 2)) /* output block */ ~
          ASSIGN(ARRAY4(EBP, 0), EAX) ~
          ASSIGN(ARRAY4(EBP, 1), EBX) ~
          ASSIGN(ARRAY4(EBP, 2), ECX) ~
          ASSIGN(ARRAY4(EBP, 3), EDX) ~
          RESTORE_REGS() ~
          "ret;\n" ~
          END_ASM;
    mixin(ASM);
}

/**
* Entry point for Serpent decryption in x86 asm
* Params:
*  input = the input block
*  output = the output block
*  ks = the key schedule
*/
extern(C)
void botan_serpent_x86_32_decrypt(const(ubyte)* input, ubyte* output, in uint* ks) pure
{

    enum PUSHED = 4;
    
    enum ASM = START_ASM ~
          "naked;" ~
          SPILL_REGS() ~ 
          ASSIGN(EBP, ARG(PUSHED, 1)) ~ /* input block */
          ASSIGN(EAX, ARRAY4(EBP, 0)) ~
          ASSIGN(EBX, ARRAY4(EBP, 1)) ~ 
          ASSIGN(ECX, ARRAY4(EBP, 2)) ~
          ASSIGN(EDX, ARRAY4(EBP, 3)) ~
          
          ASSIGN(EDI, ARG(PUSHED, 3)) ~ /* round keys */
          
          ZEROIZE(EBP) ~
          
          KEY_XOR(EAX, EBX, ECX, EDX, 32) ~
          SBOX_D8(EAX, EBX, ECX, EDX, EBP) ~
          KEY_XOR(EAX, EBX, ECX, EDX, 31) ~
          
          D_ROUND!SBOX_D7(EAX, EBX, ECX, EDX, EBP, 30) ~
          D_ROUND!SBOX_D6(EAX, EBX, ECX, EDX, EBP, 29) ~
          D_ROUND!SBOX_D5(EAX, EBX, ECX, EDX, EBP, 28) ~
          D_ROUND!SBOX_D4(EAX, EBX, ECX, EDX, EBP, 27) ~
          D_ROUND!SBOX_D3(EAX, EBX, ECX, EDX, EBP, 26) ~
          D_ROUND!SBOX_D2(EAX, EBX, ECX, EDX, EBP, 25) ~
          D_ROUND!SBOX_D1(EAX, EBX, ECX, EDX, EBP, 24) ~
          
          D_ROUND!SBOX_D8(EAX, EBX, ECX, EDX, EBP, 23) ~
          D_ROUND!SBOX_D7(EAX, EBX, ECX, EDX, EBP, 22) ~
          D_ROUND!SBOX_D6(EAX, EBX, ECX, EDX, EBP, 21) ~
          D_ROUND!SBOX_D5(EAX, EBX, ECX, EDX, EBP, 20) ~
          D_ROUND!SBOX_D4(EAX, EBX, ECX, EDX, EBP, 19) ~
          D_ROUND!SBOX_D3(EAX, EBX, ECX, EDX, EBP, 18) ~
          D_ROUND!SBOX_D2(EAX, EBX, ECX, EDX, EBP, 17) ~
          D_ROUND!SBOX_D1(EAX, EBX, ECX, EDX, EBP, 16) ~
          
          D_ROUND!SBOX_D8(EAX, EBX, ECX, EDX, EBP, 15) ~
          D_ROUND!SBOX_D7(EAX, EBX, ECX, EDX, EBP, 14) ~
          D_ROUND!SBOX_D6(EAX, EBX, ECX, EDX, EBP, 13) ~
          D_ROUND!SBOX_D5(EAX, EBX, ECX, EDX, EBP, 12) ~
          D_ROUND!SBOX_D4(EAX, EBX, ECX, EDX, EBP, 11) ~
          D_ROUND!SBOX_D3(EAX, EBX, ECX, EDX, EBP, 10) ~
          D_ROUND!SBOX_D2(EAX, EBX, ECX, EDX, EBP,  9) ~
          D_ROUND!SBOX_D1(EAX, EBX, ECX, EDX, EBP,  8) ~
          
          D_ROUND!SBOX_D8(EAX, EBX, ECX, EDX, EBP,  7) ~
          D_ROUND!SBOX_D7(EAX, EBX, ECX, EDX, EBP,  6) ~
          D_ROUND!SBOX_D6(EAX, EBX, ECX, EDX, EBP,  5) ~
          D_ROUND!SBOX_D5(EAX, EBX, ECX, EDX, EBP,  4) ~
          D_ROUND!SBOX_D4(EAX, EBX, ECX, EDX, EBP,  3) ~
          D_ROUND!SBOX_D3(EAX, EBX, ECX, EDX, EBP,  2) ~
          D_ROUND!SBOX_D2(EAX, EBX, ECX, EDX, EBP,  1) ~
          D_ROUND!SBOX_D1(EAX, EBX, ECX, EDX, EBP,  0) ~
          
          ASSIGN(EBP, ARG(PUSHED, 2)) ~ /* output block */
          ASSIGN(ARRAY4(EBP, 0), EAX) ~
          ASSIGN(ARRAY4(EBP, 1), EBX) ~
          ASSIGN(ARRAY4(EBP, 2), ECX) ~
          ASSIGN(ARRAY4(EBP, 3), EDX) ~
          RESTORE_REGS() ~ 
          "ret;\n" ~
          END_ASM;
    mixin(ASM);
}

/**
* Entry point for Serpent key schedule in x86 asm
* Params:
*  ks = holds the initial working key (padded), and is set to the
            final key schedule
*/
extern(C)
void botan_serpent_x86_32_key_schedule(uint* ks) pure
{
    string LOAD_AND_SBOX(alias SBOX)(ubyte MSG) {
        return  ASSIGN(EAX, ARRAY4(EDI, (4*MSG+ 8))) ~
                ASSIGN(EBX, ARRAY4(EDI, (4*MSG+ 9))) ~
                ASSIGN(ECX, ARRAY4(EDI, (4*MSG+10))) ~
                ASSIGN(EDX, ARRAY4(EDI, (4*MSG+11))) ~
                SBOX(EAX, EBX, ECX, EDX, EBP)        ~
                ASSIGN(ARRAY4(EDI, (4*MSG+ 8)), EAX) ~
                ASSIGN(ARRAY4(EDI, (4*MSG+ 9)), EBX) ~ 
                ASSIGN(ARRAY4(EDI, (4*MSG+10)), ECX) ~ 
                ASSIGN(ARRAY4(EDI, (4*MSG+11)), EDX);
    }
    enum PUSHED = 4;
    enum ASM =
          START_ASM ~
          "naked;\n" ~
          SPILL_REGS() ~
          ASSIGN(EDI, ARG(PUSHED, 1)) ~ /* round keys */
          ASSIGN(ESI, IMM(8)) ~
          ADD_IMM(EDI, 32) ~
          
          START_LOOP("L_SERP_EXPANSION") ~
          ASSIGN(EAX, ARRAY4(EDI, -1)) ~
          ASSIGN(EBX, ARRAY4(EDI, -3)) ~
          ASSIGN(ECX, ARRAY4(EDI, -5)) ~
          ASSIGN(EDX, ARRAY4(EDI, -8)) ~
          
          ASSIGN(EBP, ESI) ~
          SUB_IMM(EBP, 8) ~
          XOR(EBP, IMM(0x9E3779B9)) ~
          XOR(EAX, EBX) ~
          XOR(ECX, EDX) ~
          XOR(EAX, EBP) ~
          XOR(EAX, ECX) ~
          
          ROTL_IMM(EAX, 11) ~
          
          ASSIGN(ARRAY4(EDI, 0), EAX) ~
          
          ADD_IMM(ESI, 1) ~
          ADD_IMM(EDI, 4) ~
          LOOP_UNTIL_EQ(ESI, 140, "L_SERP_EXPANSION") ~
          
          ASSIGN(EDI, ARG(PUSHED, 1)) ~ /* round keys */
          
          LOAD_AND_SBOX!SBOX_E4( 0 ) ~
          LOAD_AND_SBOX!SBOX_E3( 1 ) ~
          LOAD_AND_SBOX!SBOX_E2( 2 ) ~
          LOAD_AND_SBOX!SBOX_E1( 3 ) ~
          
          LOAD_AND_SBOX!SBOX_E8( 4 ) ~
          LOAD_AND_SBOX!SBOX_E7( 5 ) ~
          LOAD_AND_SBOX!SBOX_E6( 6 ) ~
          LOAD_AND_SBOX!SBOX_E5( 7 ) ~
          LOAD_AND_SBOX!SBOX_E4( 8 ) ~
          LOAD_AND_SBOX!SBOX_E3( 9 ) ~
          LOAD_AND_SBOX!SBOX_E2(10 ) ~
          LOAD_AND_SBOX!SBOX_E1(11 ) ~
          
          LOAD_AND_SBOX!SBOX_E8(12 ) ~
          LOAD_AND_SBOX!SBOX_E7(13 ) ~
          LOAD_AND_SBOX!SBOX_E6(14 ) ~
          LOAD_AND_SBOX!SBOX_E5(15 ) ~
          LOAD_AND_SBOX!SBOX_E4(16 ) ~
          LOAD_AND_SBOX!SBOX_E3(17 ) ~
          LOAD_AND_SBOX!SBOX_E2(18 ) ~
          LOAD_AND_SBOX!SBOX_E1(19 ) ~
          
          LOAD_AND_SBOX!SBOX_E8(20 ) ~
          LOAD_AND_SBOX!SBOX_E7(21 ) ~
          LOAD_AND_SBOX!SBOX_E6(22 ) ~
          LOAD_AND_SBOX!SBOX_E5(23 ) ~
          LOAD_AND_SBOX!SBOX_E4(24 ) ~
          LOAD_AND_SBOX!SBOX_E3(25 ) ~
          LOAD_AND_SBOX!SBOX_E2(26 ) ~
          LOAD_AND_SBOX!SBOX_E1(27 ) ~
          
          LOAD_AND_SBOX!SBOX_E8(28 ) ~
          LOAD_AND_SBOX!SBOX_E7(29 ) ~
          LOAD_AND_SBOX!SBOX_E6(30 ) ~
          LOAD_AND_SBOX!SBOX_E5(31 ) ~
          LOAD_AND_SBOX!SBOX_E4(32 ) ~

          RESTORE_REGS() ~
          "ret;\n"~
          END_ASM;

    mixin(ASM);
}

string E_ROUND(alias SBOX)(string A, string B, string C, string D, string T, ubyte N) 
{
    return  KEY_XOR(A, B, C, D, N) ~
            SBOX(A, B, C, D, T)     ~
            TRANSFORM(A, B, C, D, T);
}

string D_ROUND(alias SBOX)(string A, string B, string C, string D, string T, ubyte N)
{
    return  I_TRANSFORM(A, B, C, D, T) ~
            SBOX(A, B, C, D, T) ~
            KEY_XOR(A, B, C, D, N);
}

string KEY_XOR(string A, string B, string C, string D, ubyte N) {
    return  XOR(A, ARRAY4(EDI, (4*N  )))  ~
            XOR(B, ARRAY4(EDI, (4*N+1)))  ~
            XOR(C, ARRAY4(EDI, (4*N+2)))  ~
            XOR(D, ARRAY4(EDI, (4*N+3)));
}

string TRANSFORM(string A, string B, string C, string D, string T) {
    return  ROTL_IMM(A, 13)  ~
            ROTL_IMM(C, 3)   ~
            SHL2_3(T, A) ~
            XOR(B, A)    ~
            XOR(D, C)    ~
            XOR(B, C)    ~
            XOR(D, T)    ~
            ROTL_IMM(B, 1)   ~
            ROTL_IMM(D, 7)   ~
            ASSIGN(T, B) ~
            SHL_IMM(T, 7)~
            XOR(A, B)    ~
            XOR(C, D)    ~
            XOR(A, D)    ~
            XOR(C, T)    ~
            ROTL_IMM(A, 5)   ~
            ROTL_IMM(C, 22);
}

string I_TRANSFORM(string A, string B, string C, string D, string T) {
    return  ROTR_IMM(C, 22)  ~
            ROTR_IMM(A, 5)   ~
            ASSIGN(T, B) ~
            SHL_IMM(T, 7)~
            XOR(A, B)    ~
            XOR(C, D)    ~
            XOR(A, D)    ~
            XOR(C, T)    ~
            ROTR_IMM(D, 7)   ~
            ROTR_IMM(B, 1)   ~
            SHL2_3(T, A) ~
            XOR(B, C)    ~
            XOR(D, C)    ~
            XOR(B, A)    ~
            XOR(D, T)    ~
            ROTR_IMM(C, 3)   ~
            ROTR_IMM(A, 13);
}
string SBOX_E1(string A, string B, string C, string D, string T)
{
    return  XOR(D, A)    ~
            ASSIGN(T, B) ~
            AND(B, D)    ~
            XOR(T, C)    ~
            XOR(B, A)    ~
            OR(A, D)     ~
            XOR(A, T)    ~
            XOR(T, D)    ~
            XOR(D, C)    ~
            OR(C, B)     ~
            XOR(C, T)    ~
            NOT(T)       ~
            OR(T, B)     ~
            XOR(B, D)    ~
            XOR(B, T)    ~
            OR(D, A)     ~
            XOR(B, D)    ~
            XOR(T, D)    ~
            ASSIGN(D, A) ~
            ASSIGN(A, B) ~
            ASSIGN(B, T);
}
string SBOX_E2(string A, string B, string C, string D, string T) 
{
    return  NOT(A)       ~
            NOT(C)       ~
            ASSIGN(T, A) ~
            AND(A, B)    ~
            XOR(C, A)    ~
            OR(A, D)     ~
            XOR(D, C)    ~
            XOR(B, A)    ~
            XOR(A, T)    ~
            OR(T, B)     ~
            XOR(B, D)    ~
            OR(C, A)     ~
            AND(C, T)    ~
            XOR(A, B)    ~
            AND(B, C)    ~
            XOR(B, A)    ~
            AND(A, C)    ~
            XOR(T, A)    ~
            ASSIGN(A, C) ~
            ASSIGN(C, D) ~
            ASSIGN(D, B) ~
            ASSIGN(B, T);
}

string SBOX_E3(string A, string B, string C, string D, string T) {
    return  ASSIGN(T, A) ~
            AND(A, C)    ~
            XOR(A, D)    ~
            XOR(C, B)    ~
            XOR(C, A)    ~
            OR(D, T)     ~
            XOR(D, B)    ~
            XOR(T, C)    ~
            ASSIGN(B, D) ~
            OR(D, T)     ~
            XOR(D, A)    ~
            AND(A, B)    ~
            XOR(T, A)    ~
            XOR(B, D)    ~
            XOR(B, T)    ~
            NOT(T)       ~
            ASSIGN(A, C) ~
            ASSIGN(C, B) ~
            ASSIGN(B, D) ~
            ASSIGN(D, T);

}

string SBOX_E4(string A, string B, string C, string D, string T) {
    return  ASSIGN(T, A) ~
            OR(A, D)     ~
            XOR(D, B)    ~
            AND(B, T)    ~
            XOR(T, C)    ~
            XOR(C, D)    ~
            AND(D, A)    ~
            OR(T, B)     ~
            XOR(D, T)    ~
            XOR(A, B)    ~
            AND(T, A)    ~
            XOR(B, D)    ~
            XOR(T, C)    ~
            OR(B, A)     ~
            XOR(B, C)    ~
            XOR(A, D)    ~
            ASSIGN(C, B) ~
            OR(B, D)     ~
            XOR(B, A)    ~
            ASSIGN(A, B) ~
            ASSIGN(B, C) ~
            ASSIGN(C, D) ~
            ASSIGN(D, T);
}

string SBOX_E5(string A, string B, string C, string D, string T) {
    return  XOR(B, D)    ~
            NOT(D)       ~
            XOR(C, D)    ~
            XOR(D, A)    ~
            ASSIGN(T, B) ~
            AND(B, D)    ~
            XOR(B, C)    ~
            XOR(T, D)    ~
            XOR(A, T)    ~
            AND(C, T)    ~
            XOR(C, A)    ~
            AND(A, B)    ~
            XOR(D, A)    ~
            OR(T, B)     ~
            XOR(T, A)    ~
            OR(A, D)     ~
            XOR(A, C)    ~
            AND(C, D)    ~
            NOT(A)       ~
            XOR(T, C)    ~
            ASSIGN(C, A) ~
            ASSIGN(A, B) ~
            ASSIGN(B, T);
}

string SBOX_E6(string A, string B, string C, string D, string T) {
    return  XOR(A, B)    ~
            XOR(B, D)    ~
            NOT(D)       ~
            ASSIGN(T, B) ~
            AND(B, A)    ~
            XOR(C, D)    ~
            XOR(B, C)    ~
            OR(C, T)     ~
            XOR(T, D)    ~
            AND(D, B)    ~
            XOR(D, A)    ~
            XOR(T, B)    ~
            XOR(T, C)    ~
            XOR(C, A)    ~
            AND(A, D)    ~
            NOT(C)       ~
            XOR(A, T)    ~
            OR(T, D)     ~
            XOR(T, C)    ~
            ASSIGN(C, A) ~
            ASSIGN(A, B) ~
            ASSIGN(B, D) ~
            ASSIGN(D, T);
}

string SBOX_E7(string A, string B, string C, string D, string T) {
    return  NOT(C)       ~
            ASSIGN(T, D) ~
            AND(D, A)    ~
            XOR(A, T)    ~
            XOR(D, C)    ~
            OR(C, T)     ~
            XOR(B, D)    ~
            XOR(C, A)    ~
            OR(A, B)     ~
            XOR(C, B)    ~
            XOR(T, A)    ~
            OR(A, D)     ~
            XOR(A, C)    ~
            XOR(T, D)    ~
            XOR(T, A)    ~
            NOT(D)       ~
            AND(C, T)    ~
            XOR(C, D)    ~
            ASSIGN(D, C) ~
            ASSIGN(C, T);
}
    
string SBOX_E8(string A, string B, string C, string D, string T) {
    return  ASSIGN(T, B) ~
            OR(B, C)     ~
            XOR(B, D)    ~
            XOR(T, C)    ~
            XOR(C, B)    ~
            OR(D, T)     ~
            AND(D, A)    ~
            XOR(T, C)    ~
            XOR(D, B)    ~
            OR(B, T)     ~
            XOR(B, A)    ~
            OR(A, T)     ~
            XOR(A, C)    ~
            XOR(B, T)    ~
            XOR(C, B)    ~
            AND(B, A)    ~
            XOR(B, T)    ~
            NOT(C)       ~
            OR(C, A)     ~
            XOR(T, C)    ~
            ASSIGN(C, B) ~
            ASSIGN(B, D) ~
            ASSIGN(D, A) ~
            ASSIGN(A, T);
}

string SBOX_D1(string A, string B, string C, string D, string T) {
    return    NOT(C)       ~
            ASSIGN(T, B) ~
            OR(B, A)     ~
            NOT(T)       ~
            XOR(B, C)    ~
            OR(C, T)     ~
            XOR(B, D)    ~
            XOR(A, T)    ~
            XOR(C, A)    ~
            AND(A, D)    ~
            XOR(T, A)    ~
            OR(A, B)     ~
            XOR(A, C)    ~
            XOR(D, T)    ~
            XOR(C, B)    ~
            XOR(D, A)    ~
            XOR(D, B)    ~
            AND(C, D)    ~
            XOR(T, C)    ~
            ASSIGN(C, B) ~
            ASSIGN(B, T);
}

string SBOX_D2(string A, string B, string C, string D, string T) {
    return  ASSIGN(T, B) ~
            XOR(B, D)    ~
            AND(D, B)    ~
            XOR(T, C)    ~
            XOR(D, A)    ~
            OR(A, B)     ~
            XOR(C, D)    ~
            XOR(A, T)    ~
            OR(A, C)     ~
            XOR(B, D)    ~
            XOR(A, B)    ~
            OR(B, D)     ~
            XOR(B, A)    ~
            NOT(T)       ~
            XOR(T, B)    ~
            OR(B, A)     ~
            XOR(B, A)    ~
            OR(B, T)     ~
            XOR(D, B)    ~
            ASSIGN(B, A) ~
            ASSIGN(A, T) ~
            ASSIGN(T, D) ~
            ASSIGN(D, C) ~
            ASSIGN(C, T);
}

string SBOX_D3(string A, string B, string C, string D, string T) {
    return  XOR(C, D)    ~
            XOR(D, A)    ~
            ASSIGN(T, D) ~
            AND(D, C)    ~
            XOR(D, B)    ~
            OR(B, C)     ~
            XOR(B, T)    ~
            AND(T, D)    ~
            XOR(C, D)    ~
            AND(T, A)    ~
            XOR(T, C)    ~
            AND(C, B)    ~
            OR(C, A)     ~
            NOT(D)       ~
            XOR(C, D)    ~
            XOR(A, D)    ~
            AND(A, B)    ~
            XOR(D, T)    ~
            XOR(D, A)    ~
            ASSIGN(A, B) ~
            ASSIGN(B, T);
}

string SBOX_D4(string A, string B, string C, string D, string T) {
    return  ASSIGN(T, C) ~
            XOR(C, B)    ~
            XOR(A, C)    ~
            AND(T, C)    ~
            XOR(T, A)    ~
            AND(A, B)    ~
            XOR(B, D)    ~
            OR(D, T)     ~
            XOR(C, D)    ~
            XOR(A, D)    ~
            XOR(B, T)    ~
            AND(D, C)    ~
            XOR(D, B)    ~
            XOR(B, A)    ~
            OR(B, C)     ~
            XOR(A, D)    ~
            XOR(B, T)    ~
            XOR(A, B)    ~
            ASSIGN(T, A) ~
            ASSIGN(A, C) ~
            ASSIGN(C, D) ~
            ASSIGN(D, T);

}

string SBOX_D5(string A, string B, string C, string D, string T) {
    return  ASSIGN(T, C) ~
            AND(C, D)    ~
            XOR(C, B)    ~
            OR(B, D)     ~
            AND(B, A)    ~
            XOR(T, C)    ~
            XOR(T, B)    ~
            AND(B, C)    ~
            NOT(A)       ~
            XOR(D, T)    ~
            XOR(B, D)    ~
            AND(D, A)    ~
            XOR(D, C)    ~
            XOR(A, B)    ~
            AND(C, A)    ~
            XOR(D, A)    ~
            XOR(C, T)    ~
            OR(C, D)     ~
            XOR(D, A)    ~
            XOR(C, B)    ~
            ASSIGN(B, D) ~
            ASSIGN(D, T);
    }

string SBOX_D6(string A, string B, string C, string D, string T) {
    return  NOT(B)       ~
            ASSIGN(T, D) ~
            XOR(C, B)    ~
            OR(D, A)     ~
            XOR(D, C)    ~
            OR(C, B)     ~
            AND(C, A)    ~
            XOR(T, D)    ~
            XOR(C, T)    ~
            OR(T, A)     ~
            XOR(T, B)    ~
            AND(B, C)    ~
            XOR(B, D)    ~
            XOR(T, C)    ~
            AND(D, T)    ~
            XOR(T, B)    ~
            XOR(D, T)    ~
            NOT(T)       ~
            XOR(D, A)    ~
            ASSIGN(A, B) ~
            ASSIGN(B, T) ~
            ASSIGN(T, D) ~
            ASSIGN(D, C) ~
            ASSIGN(C, T);
    }

string SBOX_D7(string A, string B, string C, string D, string T) {
    return  XOR(A, C)    ~
            ASSIGN(T, C) ~
            AND(C, A)    ~
            XOR(T, D)    ~
            NOT(C)       ~
            XOR(D, B)    ~
            XOR(C, D)    ~
            OR(T, A)     ~
            XOR(A, C)    ~
            XOR(D, T)    ~
            XOR(T, B)    ~
            AND(B, D)    ~
            XOR(B, A)    ~
            XOR(A, D)    ~
            OR(A, C)     ~
            XOR(D, B)    ~
            XOR(T, A)    ~
            ASSIGN(A, B) ~
            ASSIGN(B, C) ~
            ASSIGN(C, T);
}

string SBOX_D8(string A, string B, string C, string D, string T) {
    return  ASSIGN(T, C) ~
            XOR(C, A)    ~
            AND(A, D)    ~
            OR(T, D)     ~
            NOT(C)       ~
            XOR(D, B)    ~
            OR(B, A)     ~
            XOR(A, C)    ~
            AND(C, T)    ~
            AND(D, T)    ~
            XOR(B, C)    ~
            XOR(C, A)    ~
            OR(A, C)     ~
            XOR(T, B)    ~
            XOR(A, D)    ~
            XOR(D, T)    ~
            OR(T, A)     ~
            XOR(D, C)    ~
            XOR(T, C)    ~
            ASSIGN(C, B) ~
            ASSIGN(B, A) ~
            ASSIGN(A, D) ~
            ASSIGN(D, T);
}
