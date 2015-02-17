/**
* SHA-160 (x86-64)
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.hash.sha1_x86_64;

import botan.constants;
static if (BOTAN_HAS_SHA1 && BOTAN_HAS_SHA1_X86_64):

import botan.utils.asm_x86_64.asm_x86_64;
import botan.hash.sha160;
import botan.hash.hash;

/**
* SHA-160 in x86-64 assembly
*/
class SHA160_X86_64 : SHA160
{
public:
    override HashFunction clone() const { return new SHA160_X86_64; }

protected:
    /*
    * SHA-160 Compression Function
    */
    override void compressN(const(ubyte)* input, size_t blocks)
    {
        foreach (size_t i; 0 .. blocks)
        {
            botan_sha160_x86_64_compress(m_digest.ptr, input, m_W.ptr);
            input += hashBlockSize;
        }
    }
}

private:
pure:

enum DIGEST_ARR = "RDI";
enum INPUT = "RSI";
enum W = "RDX";
enum LOOP_CTR = "EAX";

enum A = "R8D";
enum B = "R9D";
enum C = "R10D";
enum D = "R11D";
enum E = "ECX";

/*
* Using negative values for SHA-1 constants > 2^31 to work around
* a bug in binutils not accepting large lea displacements.
*    -0x70E44324 == 0x8F1BBCDC
*    -0x359D3E2A == 0xCA62C1D6
*/
enum MAGIC1 = 0x5A827999;
enum MAGIC2 = 0x6ED9EBA1;
enum MAGIC3 = -0x70E44324;
enum MAGIC4 = -0x359D3E2A;

enum T = "ESI";
enum T2 = "EAX";

extern(C)
void botan_sha160_x86_64_compress(uint* arg1, const(ubyte)* arg2, uint* arg3)
{
    /* defined later
         enum A = "R8D";
        enum B = "R9D";
        enum C = "R10D";
        enum D = "R11D";
        enum E = "ECX";
    */
    enum ASM = 
            START_ASM ~
            ZEROIZE(LOOP_CTR) ~
            ALIGN ~ `;
LOOP_LOAD_INPUT:
            add EAX, 8;

            mov ` ~ R8 ~ `, ` ~ ARRAY8(INPUT, 0) ~ `;
            mov ` ~ R9 ~ `, ` ~ ARRAY8(INPUT, 1) ~ `;
            mov ` ~ R10 ~ `, ` ~ ARRAY8(INPUT, 2) ~ `;
            mov ` ~ R11 ~ `, ` ~ ARRAY8(INPUT, 3) ~ `;

            bswap ` ~ R8 ~ `;
            bswap ` ~ R9 ~ `;
            bswap ` ~ R10 ~ `;
            bswap ` ~ R11 ~ `;

            rol ` ~ R8 ~ `, 32;
            rol ` ~ R9 ~ `, 32;
            rol ` ~ R10 ~ `, 32;
            rol ` ~ R11 ~ `, 32;

            mov ` ~ ARRAY8(W, 0) ~ `, ` ~ R8 ~ `;
            mov ` ~ ARRAY8(W, 1) ~ `, ` ~ R9 ~ `;
            mov ` ~ ARRAY8(W, 2) ~ `, ` ~ R10 ~ `;
            mov ` ~ ARRAY8(W, 3) ~ `, ` ~ R11 ~ `;

            add ` ~ W ~ `, 32;
            add ` ~ INPUT ~ `, 32;

            cmp ` ~ LOOP_CTR ~ `, ` ~ IMM(16) ~ `;
            jne LOOP_LOAD_INPUT;` ~

            ALIGN ~ `;
            LOOP_EXPANSION:
            add ` ~ LOOP_CTR ~ `, 4;
            `  ~
                
            ZEROIZE(A) ~
            ASSIGN(B, ARRAY4(W, -1)) ~
            ASSIGN(C, ARRAY4(W, -2)) ~
            ASSIGN(D, ARRAY4(W, -3)) ~

            XOR(A, ARRAY4(W, -5)) ~
            XOR(B, ARRAY4(W, -6)) ~
            XOR(C, ARRAY4(W, -7)) ~
            XOR(D, ARRAY4(W, -8)) ~

            XOR(A, ARRAY4(W, -11)) ~
            XOR(B, ARRAY4(W, -12)) ~
            XOR(C, ARRAY4(W, -13)) ~
            XOR(D, ARRAY4(W, -14)) ~

            XOR(A, ARRAY4(W, -13)) ~
            XOR(B, ARRAY4(W, -14)) ~
            XOR(C, ARRAY4(W, -15)) ~
            XOR(D, ARRAY4(W, -16)) ~

            ROTL_IMM(D, 1) ~
            ROTL_IMM(C, 1) ~
            ROTL_IMM(B, 1) ~
            XOR(A, D) ~
            ROTL_IMM(A, 1) ~

            ASSIGN(ARRAY4(W, 0), D) ~
            ASSIGN(ARRAY4(W, 1), C) ~
            ASSIGN(ARRAY4(W, 2), B) ~
            ASSIGN(ARRAY4(W, 3), A) ~

            `add ` ~ W ~ `, 16;
            cmp ` ~ LOOP_CTR ~ `, ` ~ IMM(80) ~ `;
            jne LOOP_EXPANSION;

            sub ` ~ W ~ `, 320;` ~



            ASSIGN(T, ARRAY4(DIGEST_ARR, 0)) ~
            ASSIGN(B, ARRAY4(DIGEST_ARR, 1)) ~
            ASSIGN(C, ARRAY4(DIGEST_ARR, 2)) ~
            ASSIGN(D, ARRAY4(DIGEST_ARR, 3)) ~
            ASSIGN(E, ARRAY4(DIGEST_ARR, 4)) ~

            /* First Round */
            F1(A, B, C, D, E, T, 0) ~
            F1(T, A, B, C, D, E, 1) ~
            F1(E, T, A, B, C, D, 2) ~
            F1(D, E, T, A, B, C, 3) ~
            F1(C, D, E, T, A, B, 4) ~
            F1(B, C, D, E, T, A, 5) ~
            F1(A, B, C, D, E, T, 6) ~
            F1(T, A, B, C, D, E, 7) ~
            F1(E, T, A, B, C, D, 8) ~
            F1(D, E, T, A, B, C, 9) ~
            F1(C, D, E, T, A, B, 10) ~
            F1(B, C, D, E, T, A, 11) ~
            F1(A, B, C, D, E, T, 12) ~
            F1(T, A, B, C, D, E, 13) ~
            F1(E, T, A, B, C, D, 14) ~
            F1(D, E, T, A, B, C, 15) ~
            F1(C, D, E, T, A, B, 16) ~
            F1(B, C, D, E, T, A, 17) ~
            F1(A, B, C, D, E, T, 18) ~
            F1(T, A, B, C, D, E, 19) ~

            /* Second Round */
            F2(E, T, A, B, C, D, 20) ~
            F2(D, E, T, A, B, C, 21) ~
            F2(C, D, E, T, A, B, 22) ~
            F2(B, C, D, E, T, A, 23) ~
            F2(A, B, C, D, E, T, 24) ~
            F2(T, A, B, C, D, E, 25) ~
            F2(E, T, A, B, C, D, 26) ~
            F2(D, E, T, A, B, C, 27) ~
            F2(C, D, E, T, A, B, 28) ~
            F2(B, C, D, E, T, A, 29 ) ~
            F2(A, B, C, D, E, T, 30 ) ~
            F2(T, A, B, C, D, E, 31 ) ~
            F2(E, T, A, B, C, D, 32 ) ~
            F2(D, E, T, A, B, C, 33 ) ~
            F2(C, D, E, T, A, B, 34 ) ~
            F2(B, C, D, E, T, A, 35 ) ~
            F2(A, B, C, D, E, T, 36 ) ~
            F2(T, A, B, C, D, E, 37 ) ~
            F2(E, T, A, B, C, D, 38 ) ~
            F2(D, E, T, A, B, C, 39 ) ~

            /* Third Round */
            F3(C, D, E, T, A, B, 40 ) ~
            F3(B, C, D, E, T, A, 41 ) ~
            F3(A, B, C, D, E, T, 42 ) ~
            F3(T, A, B, C, D, E, 43 ) ~
            F3(E, T, A, B, C, D, 44 ) ~
            F3(D, E, T, A, B, C, 45 ) ~
            F3(C, D, E, T, A, B, 46 ) ~
            F3(B, C, D, E, T, A, 47 ) ~
            F3(A, B, C, D, E, T, 48 ) ~
            F3(T, A, B, C, D, E, 49 ) ~
            F3(E, T, A, B, C, D, 50 ) ~
            F3(D, E, T, A, B, C, 51 ) ~
            F3(C, D, E, T, A, B, 52 ) ~
            F3(B, C, D, E, T, A, 53 ) ~
            F3(A, B, C, D, E, T, 54 ) ~
            F3(T, A, B, C, D, E, 55 ) ~
            F3(E, T, A, B, C, D, 56 ) ~
            F3(D, E, T, A, B, C, 57 ) ~
            F3(C, D, E, T, A, B, 58 ) ~
            F3(B, C, D, E, T, A, 59 ) ~

            /* Fourth Round */
            F4(A, B, C, D, E, T, 60 ) ~
            F4(T, A, B, C, D, E, 61 ) ~
            F4(E, T, A, B, C, D, 62 ) ~
            F4(D, E, T, A, B, C, 63 ) ~
            F4(C, D, E, T, A, B, 64 ) ~
            F4(B, C, D, E, T, A, 65 ) ~
            F4(A, B, C, D, E, T, 66 ) ~
            F4(T, A, B, C, D, E, 67 ) ~
            F4(E, T, A, B, C, D, 68 ) ~
            F4(D, E, T, A, B, C, 69 ) ~
            F4(C, D, E, T, A, B, 70 ) ~
            F4(B, C, D, E, T, A, 71 ) ~
            F4(A, B, C, D, E, T, 72 ) ~
            F4(T, A, B, C, D, E, 73 ) ~
            F4(E, T, A, B, C, D, 74 ) ~
            F4(D, E, T, A, B, C, 75 ) ~
            F4(C, D, E, T, A, B, 76 ) ~
            F4(B, C, D, E, T, A, 77 ) ~
            F4(A, B, C, D, E, T, 78 ) ~
            F4(T, A, B, C, D, E, 79 ) ~

            ADD(ARRAY4(DIGEST_ARR, 0), D) ~
            ADD(ARRAY4(DIGEST_ARR, 1), T) ~
            ADD(ARRAY4(DIGEST_ARR, 2), A) ~
            ADD(ARRAY4(DIGEST_ARR, 3), B) ~
            ADD(ARRAY4(DIGEST_ARR, 4), C) ~
      END_ASM;


    mixin(ASM);


}


string F1(string A, string B, string C, string D, string E, string F, ubyte N)
{
    return ASSIGN(T2, ARRAY4(W, N))    ~
            ASSIGN(A, F) ~
            ROTL_IMM(F, 5) ~
            ADD(F, E) ~
            ASSIGN(E, C) ~
            XOR(E, D) ~
            ADD3_IMM(F, T2, MAGIC1) ~
            AND(E, B) ~
            XOR(E, D) ~
            ROTR_IMM(B, 2) ~
            ADD(E, F);
}

string F2_4(string A, string B, string C, string D, string E, string F, ubyte N, int MAGIC)
{
    return ASSIGN(T2, ARRAY4(W, N)) ~
            ASSIGN(A, F) ~
            ROTL_IMM(F, 5) ~
            ADD(F, E) ~
            ASSIGN(E, B) ~
            XOR(E, C) ~
            ADD3_IMM(F, T2, MAGIC) ~
            XOR(E, D) ~
            ROTR_IMM(B, 2) ~
            ADD(E, F);
}

string F3(string A, string B, string C, string D, string E, string F, ubyte N)
{
    return ASSIGN(T2, ARRAY4(W, N)) ~
            ASSIGN(A, F) ~
            ROTL_IMM(F, 5) ~
            ADD(F, E) ~
            ASSIGN(E, B) ~
            OR(E, C) ~
            AND(E, D) ~
            ADD3_IMM(F, T2, MAGIC3) ~
            ASSIGN(T2, B) ~
            AND(T2, C) ~
            OR(E, T2) ~
            ROTR_IMM(B, 2) ~
            ADD(E, F);
}

string F2(string A, string B, string C, string D, string E, string F, ubyte W2)
{
    return F2_4(A, B, C, D, E, F, W2, MAGIC2);
}

string F4(string A, string B, string C, string D, string E, string F, ubyte W2)
{
    return F2_4(A, B, C, D, E, F, W2, MAGIC4);
}