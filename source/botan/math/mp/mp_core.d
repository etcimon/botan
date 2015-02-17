/**
* MPI Algorithms
* 
* Copyright:
* (C) 1999-2010 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*      2006 Luca Piccarreta
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.math.mp.mp_core;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

public import botan.math.mp.mp_types;
import botan.utils.exceptn;
import botan.utils.mem_ops;
import botan.utils.mul128;

/*
* Montgomery Multiplication
*/
void bigint_monty_mul(word* z, size_t z_size,
    in word* x, size_t x_size, size_t x_sw,
    in word* y, size_t y_size, size_t y_sw,
    in word* p, size_t p_size, word p_dash,
    word* ws)
{
    bigint_mul( z, z_size, ws,
        x, x_size, x_sw,
        y, y_size, y_sw);

    bigint_monty_redc(z, p, p_size, p_dash, ws);
}


/*
* Montgomery Squaring
*/
void bigint_monty_sqr(word* z, size_t z_size,
    in word* x, size_t x_size, size_t x_sw,
    in word* p, size_t p_size, word p_dash,
    word* ws)
{
    bigint_sqr(z, z_size, ws, x, x_size, x_sw);
    bigint_monty_redc(z, p, p_size, p_dash, ws);
}

// todo: Bring back ASM for x86_32, x86_64, from Botan C++.
pure:
/*
* The size of the word type, in bits
*/
const size_t MP_WORD_BITS = BOTAN_MP_WORD_BITS;

/*
* High Level Multiplication/Squaring Interfaces
*/

/*
* Multiplication Algorithm Dispatcher
*/
void bigint_mul(word* z, size_t z_size, word* workspace,
                in word* x, size_t x_size, size_t x_sw,
                in word* y, size_t y_size, size_t y_sw)
{
    if (x_sw == 1)
    {
        bigint_linmul3(z, y, y_sw, x[0]);
    }
    else if (y_sw == 1)
    {
        bigint_linmul3(z, x, x_sw, y[0]);
    }
    else if (x_sw <= 4 && x_size >= 4 &&
             y_sw <= 4 && y_size >= 4 && z_size >= 8)
    {
        bigint_comba_mul4(*cast(word[8]*) z, *cast(word[4]*) x, *cast(word[4]*) y);
    }
    else if (x_sw <= 6 && x_size >= 6 &&
             y_sw <= 6 && y_size >= 6 && z_size >= 12)
    {
        bigint_comba_mul6(*cast(word[12]*) z, *cast(word[6]*) x, *cast(word[6]*) y);
    }
    else if (x_sw <= 8 && x_size >= 8 &&
             y_sw <= 8 && y_size >= 8 && z_size >= 16)
    {
        bigint_comba_mul8(*cast(word[16]*) z, *cast(word[8]*) x, *cast(word[8]*) y);
    }
    else if (x_sw <= 16 && x_size >= 16 &&
             y_sw <= 16 && y_size >= 16 && z_size >= 32)
    {
        bigint_comba_mul16(*cast(word[32]*) z, *cast(word[16]*) x, *cast(word[16]*) y);
    }
    else if (x_sw < KARATSUBA_MULTIPLY_THRESHOLD ||
             y_sw < KARATSUBA_MULTIPLY_THRESHOLD ||
             !workspace)
    {
        bigint_simple_mul(z, x, x_sw, y, y_sw);
    }
    else
    {
        const size_t N = karatsuba_size(z_size, x_size, x_sw, y_size, y_sw);
        
        if (N)
            karatsuba_mul(z, x, y, N, workspace);
        else
            bigint_simple_mul(z, x, x_sw, y, y_sw);
    }
}

/*
* Squaring Algorithm Dispatcher
*/
void bigint_sqr(word* z, size_t z_size, word* workspace,
                in word* x, size_t x_size, size_t x_sw)
{
    if (x_sw == 1)
    {
        bigint_linmul3(z, x, x_sw, x[0]);
    }
    else if (x_sw <= 4 && x_size >= 4 && z_size >= 8)
    {
        bigint_comba_sqr4(*cast(word[8]*) z, *cast(word[4]*) x);
    }
    else if (x_sw <= 6 && x_size >= 6 && z_size >= 12)
    {
        bigint_comba_sqr6(*cast(word[12]*) z, *cast(word[6]*) x);
    }
    else if (x_sw <= 8 && x_size >= 8 && z_size >= 16)
    {
        bigint_comba_sqr8(*cast(word[16]*) z, *cast(word[8]*) x);
    }
    else if (x_sw <= 16 && x_size >= 16 && z_size >= 32)
    {
        bigint_comba_sqr16(*cast(word[32]*) z, *cast(word[16]*) x);
    }
    else if (x_size < KARATSUBA_SQUARE_THRESHOLD || !workspace)
    {
        bigint_simple_sqr(z, x, x_sw);
    }
    else
    {
        const size_t N = karatsuba_size(z_size, x_size, x_sw);
        
        if (N)
            karatsuba_sqr(z, x, N, workspace);
        else
            bigint_simple_sqr(z, x, x_sw);
    }
}

/**
* Two operand addition
* Params:
*  x = the first operand (and output)
*  x_size = size of x
*  y = the second operand
*  y_size = size of y (must be >= x_size)
*/
void bigint_add2(word* x, size_t x_size, in word* y, size_t y_size)
{
    if (bigint_add2_nc(x, x_size, y, y_size))
        x[x_size] += 1;
}

/**
* Three operand addition
*/
void bigint_add3(word* z, in word* x, size_t x_size,
                 in word* y, size_t y_size)
{
    z[(x_size > y_size ? x_size : y_size)] += bigint_add3_nc(z, x, x_size, y, y_size);
}

/**
* Two operand addition with carry out
*/
word bigint_add2_nc(word* x, size_t x_size, in word* y, size_t y_size)
{
    word carry = 0;
    
    const size_t blocks = y_size - (y_size % 8);
    
    for (size_t i = 0; i != blocks; i += 8)
        carry = word8_add2((x + i)[0 .. 8], (y + i)[0 .. 8], carry);
    
    foreach (size_t i; blocks .. y_size)
        x[i] = word_add(x[i], y[i], &carry);
    
    foreach (size_t i; y_size .. x_size)
        x[i] = word_add(x[i], 0, &carry);
    
    return carry;
}

/**
* Three operand addition with carry out
*/
word bigint_add3_nc(word* z, in word* x, size_t x_size, in word* y, size_t y_size)
{
    if (x_size < y_size)
    { return bigint_add3_nc(z, y, y_size, x, x_size); }
    
    word carry = 0;
    
    const size_t blocks = y_size - (y_size % 8);
    
    for (size_t i = 0; i != blocks; i += 8)
        carry = word8_add3(*cast(word[8]*) (z + i), *cast(word[8]*) (x + i), *cast(word[8]*) (y + i), carry);
    
    foreach (size_t i; blocks .. y_size)
        z[i] = word_add(x[i], y[i], &carry);
    
    foreach (size_t i; y_size .. x_size)
        z[i] = word_add(x[i], 0, &carry);
    
    return carry;
}

/**
* Two operand subtraction
*/
word bigint_sub2(word* x, size_t x_size, in word* y, size_t y_size)
{
    word borrow = 0;
    
    const size_t blocks = y_size - (y_size % 8);
    
    for (size_t i = 0; i != blocks; i += 8)
        borrow = word8_sub2(*cast(word[8]*) (x + i), *cast(word[8]*) (y + i), borrow);
    
    foreach (size_t i; blocks .. y_size)
        x[i] = word_sub(x[i], y[i], &borrow);
    
    foreach (size_t i; y_size .. x_size)
        x[i] = word_sub(x[i], 0, &borrow);
    
    return borrow;
}

/**
* Two operand subtraction, x = y - x; assumes y >= x
*/
void bigint_sub2_rev(word* x,  in word* y, size_t y_size)
{
    word borrow = 0;
    
    const size_t blocks = y_size - (y_size % 8);
    
    for (size_t i = 0; i != blocks; i += 8)
        borrow = word8_sub2_rev(*cast(word[8]*) (x + i), *cast(word[8]*) (y + i), borrow);
    
    foreach (size_t i; blocks .. y_size)
        x[i] = word_sub(y[i], x[i], &borrow);
    
    if (borrow)
        throw new InternalError("bigint_sub2_rev: x >= y");
}

/**
* Three operand subtraction
*/
word bigint_sub3(word* z, in word* x, size_t x_size, in word* y, size_t y_size)
{
    word borrow = 0;

    const size_t blocks = y_size - (y_size % 8);
    
    for (size_t i = 0; i != blocks; i += 8)
        borrow = word8_sub3(*cast(word[8]*) (z + i), *cast(word[8]*) (x + i), *cast(word[8]*) (y + i), borrow);
    
    foreach (size_t i; blocks .. y_size)
        z[i] = word_sub(x[i], y[i], &borrow);
    
    foreach (size_t i; y_size .. x_size)
        z[i] = word_sub(x[i], 0, &borrow);
    
    return borrow;
}

/*
* Shift Operations
*/

/*
* Single Operand Left Shift
*/
void bigint_shl1(word* x, size_t x_size, size_t word_shift, size_t bit_shift)
{
    if (word_shift)
    {
        copyMem(x + word_shift, x, x_size);
        clearMem(x, word_shift);
    }
    
    if (bit_shift)
    {
        word carry = 0;
        foreach (size_t j; word_shift .. (x_size + word_shift + 1))
        {
            word temp = x[j];
            x[j] = (temp << bit_shift) | carry;
            carry = (temp >> (MP_WORD_BITS - bit_shift));
        }
    }
}

/*
* Single Operand Right Shift
*/
void bigint_shr1(word* x, size_t x_size, size_t word_shift, size_t bit_shift)
{
    if (x_size < word_shift)
    {
        clearMem(x, x_size);
        return;
    }
    
    if (word_shift)
    {
        copyMem(x, x + word_shift, x_size - word_shift);
        clearMem(x + x_size - word_shift, word_shift);
    }
    
    if (bit_shift)
    {
        word carry = 0;
        
        size_t top = x_size - word_shift;
        
        while (top >= 4)
        {
            word w = x[top-1];
            x[top-1] = (w >> bit_shift) | carry;
            carry = (w << (MP_WORD_BITS - bit_shift));
            
            w = x[top-2];
            x[top-2] = (w >> bit_shift) | carry;
            carry = (w << (MP_WORD_BITS - bit_shift));
            
            w = x[top-3];
            x[top-3] = (w >> bit_shift) | carry;
            carry = (w << (MP_WORD_BITS - bit_shift));
            
            w = x[top-4];
            x[top-4] = (w >> bit_shift) | carry;
            carry = (w << (MP_WORD_BITS - bit_shift));
            
            top -= 4;
        }
        
        while (top)
        {
            word w = x[top-1];
            x[top-1] = (w >> bit_shift) | carry;
            carry = (w << (MP_WORD_BITS - bit_shift));
            
            top--;
        }
    }
}

/*
* Two Operand Left Shift
*/
void bigint_shl2(word* y, in word* x, size_t x_size, size_t word_shift, size_t bit_shift)
{
    foreach (size_t j; 0 .. x_size)
        y[j + word_shift] = x[j];
    if (bit_shift)
    {
        word carry = 0;
        foreach (size_t j; word_shift .. (x_size + word_shift + 1))
        {
            word w = y[j];
            y[j] = (w << bit_shift) | carry;
            carry = (w >> (MP_WORD_BITS - bit_shift));
        }
    }
}

/*
* Two Operand Right Shift
*/
void bigint_shr2(word* y, in word* x, size_t x_size,
                 size_t word_shift, size_t bit_shift)
{
    if (x_size < word_shift) return;
    
    foreach (size_t j; 0 .. (x_size - word_shift))
        y[j] = x[j + word_shift];
    if (bit_shift)
    {
        word carry = 0;
        for (size_t j = x_size - word_shift; j > 0; --j)
        {
            word w = y[j-1];
            y[j-1] = (w >> bit_shift) | carry;
            carry = (w << (MP_WORD_BITS - bit_shift));
        }
    }
}

/*
* Simple O(N^2) Multiplication and Squaring
*/
void bigint_simple_mul(word* z, in word* x, size_t x_size, in word* y, size_t y_size)
{
    const size_t x_size_8 = x_size - (x_size % 8);
    
    clearMem(z, x_size + y_size);
    
    foreach (size_t i; 0 .. y_size)
    {
        const word y_i = y[i];
        
        word carry = 0;
        
        for (size_t j = 0; j != x_size_8; j += 8)
            carry = word8_madd3(*cast(word[8]*) (z + i + j), *cast(word[8]*) (x + j), y_i, carry);
        
        foreach (size_t j; x_size_8 .. x_size)
            z[i+j] = word_madd3(x[j], y_i, z[i+j], &carry);
        
        z[x_size+i] = carry;
    }
}

/*
* Simple O(N^2) Squaring
*
* This is exactly the same algorithm as bigint_simple_mul, however
* because C/C++ compilers suck at alias analysis it is good to have
* the version where the compiler knows that x == y
*
* There is an O(n^1.5) squaring algorithm specified in Handbook of
* Applied Cryptography, chapter 14
*
*/
void bigint_simple_sqr(word* z, in word* x, size_t x_size)
{
    const size_t x_size_8 = x_size - (x_size % 8);
    
    clearMem(z, 2*x_size);
    
    foreach (size_t i; 0 .. x_size)
    {
        const word x_i = x[i];
        word carry = 0;
        
        for (size_t j = 0; j != x_size_8; j += 8)
            carry = word8_madd3(*cast(word[8]*) (z + i + j), *cast(word[8]*) (x + j), x_i, carry);
        
        foreach (size_t j; x_size_8 .. x_size)
            z[i+j] = word_madd3(x[j], x_i, z[i+j], &carry);
        
        z[x_size+i] = carry;
    }
}


/*
* Linear Multiply
*/
/*
* Two Operand Linear Multiply
*/
void bigint_linmul2(word* x, size_t x_size, word y)
{
    const size_t blocks = x_size - (x_size % 8);
    
    word carry = 0;
    
    for (size_t i = 0; i != blocks; i += 8)
        carry = word8_linmul2(*cast(word[8]*) (x + i), y, carry);
    
    foreach (size_t i; blocks .. x_size)
        x[i] = word_madd2(x[i], y, &carry);
    
    x[x_size] = carry;
}

/*
* Three Operand Linear Multiply
*/
void bigint_linmul3(word* z, in word* x, size_t x_size, word y)
{
    const size_t blocks = x_size - (x_size % 8);
    
    word carry = 0;
    
    for (size_t i = 0; i != blocks; i += 8)
        carry = word8_linmul3(*cast(word[8]*) (z + i), *cast(word[8]*) (x + i), y, carry);
    
    foreach (size_t i; blocks .. x_size)
        z[i] = word_madd2(x[i], y, &carry);
    
    z[x_size] = carry;
}


/**
* Montgomery Reduction
* Params:
*  z = integer to reduce, of size exactly 2*(p_size+1).
              Output is in the first p_size+1 words, higher
              words are set to zero.
*  p = modulus
*  p_size = size of p
*  p_dash = Montgomery value
*  ws = workspace array of at least 2*(p_size+1) words
*/
void bigint_monty_redc(word* z, in word* p, size_t p_size, word p_dash, word* ws)
{
    const size_t z_size = 2*(p_size+1);
    
    const size_t blocks_of_8 = p_size - (p_size % 8);
    
    foreach (size_t i; 0 .. p_size)
    {
        word* z_i = z + i;
        
        const word y = z_i[0] * p_dash;
        
        /*
        bigint_linmul3(ws, p, p_size, y);
        bigint_add2(z_i, z_size - i, ws, p_size+1);
        */
        
        word carry = 0;
        
        for (size_t j = 0; j != blocks_of_8; j += 8)
            carry = word8_madd3(*cast(word[8]*) (z_i + j), *cast(word[8]*) (p + j), y, carry);
        
        foreach (size_t j; blocks_of_8 .. p_size)
            z_i[j] = word_madd3(p[j], y, z_i[j], &carry);
        
        word z_sum = z_i[p_size] + carry;
        carry = (z_sum < z_i[p_size]);
        z_i[p_size] = z_sum;
        
        for (size_t j = p_size + 1; carry && j != z_size - i; ++j)
        {
            ++z_i[j];
            carry = !z_i[j];
        }
    }
    
    word borrow = 0;
    foreach (size_t i; 0 .. p_size)
        ws[i] = word_sub(z[p_size + i], p[i], &borrow);
    
    ws[p_size] = word_sub(z[p_size+p_size], 0, &borrow);
    
    copyMem(ws + p_size + 1, z + p_size, p_size + 1);
    
    copyMem(z, ws + borrow*(p_size+1), p_size + 1);
    clearMem(z + p_size + 1, z_size - p_size - 1);
}


/**
* Compare x and y
*/
int bigint_cmp(in word* x, size_t x_size,
               in word* y, size_t y_size)
{
    if (x_size < y_size) { return (-bigint_cmp(y, y_size, x, x_size)); }
    
    while (x_size > y_size)
    {
        if (x[x_size-1])
            return 1;
        x_size--;
    }
    
    for (size_t i = x_size; i > 0; --i)
    {
        if (x[i-1] > y[i-1])
            return 1;
        if (x[i-1] < y[i-1])
            return -1;
    }
    
    return 0;
}

/**
* Compute ((n1<<bits) + n0) / d
*/
word bigint_divop(word n1, word n0, word d)
{
    word high = n1 % d, quotient = 0;
    
    foreach (size_t i; 0 .. MP_WORD_BITS)
    {
        word high_top_bit = (high & MP_WORD_TOP_BIT);
        
        high <<= 1;
        high |= (n0 >> (MP_WORD_BITS-1-i)) & 1;
        quotient <<= 1;
        
        if (high_top_bit || high >= d)
        {
            high -= d;
            quotient |= 1;
        }
    }
    
    return quotient;
}

/**
* Compute ((n1<<bits) + n0) % d
*/
word bigint_modop(word n1, word n0, word d)
{
    word z = bigint_divop(n1, n0, d);
    word dummy = 0;
    z = word_madd2(z, d, &dummy);
    return (n0-z);
}

/*
* Comba Multiplication / Squaring
*/
/*
* Comba 4x4 Squaring
*/
void bigint_comba_sqr4(ref word[8] z, in word[4] x)
{
    word w2 = 0, w1 = 0, w0 = 0;
    
    word3_muladd(&w2, &w1, &w0, x[ 0], x[ 0]);
    z[ 0] = w0; w0 = 0;
    
    word3_muladd_2(&w0, &w2, &w1, x[ 0], x[ 1]);
    z[ 1] = w1; w1 = 0;
    
    word3_muladd_2(&w1, &w0, &w2, x[ 0], x[ 2]);
    word3_muladd(&w1, &w0, &w2, x[ 1], x[ 1]);
    z[ 2] = w2; w2 = 0;
    
    word3_muladd_2(&w2, &w1, &w0, x[ 0], x[ 3]);
    word3_muladd_2(&w2, &w1, &w0, x[ 1], x[ 2]);
    z[ 3] = w0; w0 = 0;
    
    word3_muladd_2(&w0, &w2, &w1, x[ 1], x[ 3]);
    word3_muladd(&w0, &w2, &w1, x[ 2], x[ 2]);
    z[ 4] = w1; w1 = 0;
    
    word3_muladd_2(&w1, &w0, &w2, x[ 2], x[ 3]);
    z[ 5] = w2; w2 = 0;
    
    word3_muladd(&w2, &w1, &w0, x[ 3], x[ 3]);
    z[ 6] = w0;
    z[ 7] = w1;
}

/*
* Comba 4x4 Multiplication
*/
void bigint_comba_mul4(ref word[8] z, in word[4] x, in word[4] y)
{
    word w2 = 0, w1 = 0, w0 = 0;
    
    word3_muladd(&w2, &w1, &w0, x[ 0], y[ 0]);
    z[ 0] = w0; w0 = 0;
    
    word3_muladd(&w0, &w2, &w1, x[ 0], y[ 1]);
    word3_muladd(&w0, &w2, &w1, x[ 1], y[ 0]);
    z[ 1] = w1; w1 = 0;
    
    word3_muladd(&w1, &w0, &w2, x[ 0], y[ 2]);
    word3_muladd(&w1, &w0, &w2, x[ 1], y[ 1]);
    word3_muladd(&w1, &w0, &w2, x[ 2], y[ 0]);
    z[ 2] = w2; w2 = 0;
    
    word3_muladd(&w2, &w1, &w0, x[ 0], y[ 3]);
    word3_muladd(&w2, &w1, &w0, x[ 1], y[ 2]);
    word3_muladd(&w2, &w1, &w0, x[ 2], y[ 1]);
    word3_muladd(&w2, &w1, &w0, x[ 3], y[ 0]);
    z[ 3] = w0; w0 = 0;
    
    word3_muladd(&w0, &w2, &w1, x[ 1], y[ 3]);
    word3_muladd(&w0, &w2, &w1, x[ 2], y[ 2]);
    word3_muladd(&w0, &w2, &w1, x[ 3], y[ 1]);
    z[ 4] = w1; w1 = 0;
    
    word3_muladd(&w1, &w0, &w2, x[ 2], y[ 3]);
    word3_muladd(&w1, &w0, &w2, x[ 3], y[ 2]);
    z[ 5] = w2; w2 = 0;
    
    word3_muladd(&w2, &w1, &w0, x[ 3], y[ 3]);
    z[ 6] = w0;
    z[ 7] = w1;
}

/*
* Comba 6x6 Squaring
*/
void bigint_comba_sqr6(ref word[12] z, in word[6] x)
{
    word w2 = 0, w1 = 0, w0 = 0;
    
    word3_muladd(&w2, &w1, &w0, x[ 0], x[ 0]);
    z[ 0] = w0; w0 = 0;
    
    word3_muladd_2(&w0, &w2, &w1, x[ 0], x[ 1]);
    z[ 1] = w1; w1 = 0;
    
    word3_muladd_2(&w1, &w0, &w2, x[ 0], x[ 2]);
    word3_muladd(&w1, &w0, &w2, x[ 1], x[ 1]);
    z[ 2] = w2; w2 = 0;
    
    word3_muladd_2(&w2, &w1, &w0, x[ 0], x[ 3]);
    word3_muladd_2(&w2, &w1, &w0, x[ 1], x[ 2]);
    z[ 3] = w0; w0 = 0;
    
    word3_muladd_2(&w0, &w2, &w1, x[ 0], x[ 4]);
    word3_muladd_2(&w0, &w2, &w1, x[ 1], x[ 3]);
    word3_muladd(&w0, &w2, &w1, x[ 2], x[ 2]);
    z[ 4] = w1; w1 = 0;
    
    word3_muladd_2(&w1, &w0, &w2, x[ 0], x[ 5]);
    word3_muladd_2(&w1, &w0, &w2, x[ 1], x[ 4]);
    word3_muladd_2(&w1, &w0, &w2, x[ 2], x[ 3]);
    z[ 5] = w2; w2 = 0;
    
    word3_muladd_2(&w2, &w1, &w0, x[ 1], x[ 5]);
    word3_muladd_2(&w2, &w1, &w0, x[ 2], x[ 4]);
    word3_muladd(&w2, &w1, &w0, x[ 3], x[ 3]);
    z[ 6] = w0; w0 = 0;
    
    word3_muladd_2(&w0, &w2, &w1, x[ 2], x[ 5]);
    word3_muladd_2(&w0, &w2, &w1, x[ 3], x[ 4]);
    z[ 7] = w1; w1 = 0;
    
    word3_muladd_2(&w1, &w0, &w2, x[ 3], x[ 5]);
    word3_muladd(&w1, &w0, &w2, x[ 4], x[ 4]);
    z[ 8] = w2; w2 = 0;
    
    word3_muladd_2(&w2, &w1, &w0, x[ 4], x[ 5]);
    z[ 9] = w0; w0 = 0;
    
    word3_muladd(&w0, &w2, &w1, x[ 5], x[ 5]);
    z[10] = w1;
    z[11] = w2;
}

/*
* Comba 6x6 Multiplication
*/
void bigint_comba_mul6(ref word[12] z, in word[6] x, in word[6] y)
{
    word w2 = 0, w1 = 0, w0 = 0;
    
    word3_muladd(&w2, &w1, &w0, x[ 0], y[ 0]);
    z[ 0] = w0; w0 = 0;

    word3_muladd(&w0, &w2, &w1, x[ 0], y[ 1]);
    word3_muladd(&w0, &w2, &w1, x[ 1], y[ 0]);
    z[ 1] = w1; w1 = 0;
    
    word3_muladd(&w1, &w0, &w2, x[ 0], y[ 2]);
    word3_muladd(&w1, &w0, &w2, x[ 1], y[ 1]);
    word3_muladd(&w1, &w0, &w2, x[ 2], y[ 0]);
    z[ 2] = w2; w2 = 0;
    
    word3_muladd(&w2, &w1, &w0, x[ 0], y[ 3]);
    word3_muladd(&w2, &w1, &w0, x[ 1], y[ 2]);
    word3_muladd(&w2, &w1, &w0, x[ 2], y[ 1]);
    word3_muladd(&w2, &w1, &w0, x[ 3], y[ 0]);
    z[ 3] = w0; w0 = 0;
    
    word3_muladd(&w0, &w2, &w1, x[ 0], y[ 4]);
    word3_muladd(&w0, &w2, &w1, x[ 1], y[ 3]);
    word3_muladd(&w0, &w2, &w1, x[ 2], y[ 2]);
    word3_muladd(&w0, &w2, &w1, x[ 3], y[ 1]);
    word3_muladd(&w0, &w2, &w1, x[ 4], y[ 0]);
    z[ 4] = w1; w1 = 0;
    
    word3_muladd(&w1, &w0, &w2, x[ 0], y[ 5]);
    word3_muladd(&w1, &w0, &w2, x[ 1], y[ 4]);
    word3_muladd(&w1, &w0, &w2, x[ 2], y[ 3]);
    word3_muladd(&w1, &w0, &w2, x[ 3], y[ 2]);
    word3_muladd(&w1, &w0, &w2, x[ 4], y[ 1]);
    word3_muladd(&w1, &w0, &w2, x[ 5], y[ 0]);
    z[ 5] = w2; w2 = 0;
    
    word3_muladd(&w2, &w1, &w0, x[ 1], y[ 5]);
    word3_muladd(&w2, &w1, &w0, x[ 2], y[ 4]);
    word3_muladd(&w2, &w1, &w0, x[ 3], y[ 3]);
    word3_muladd(&w2, &w1, &w0, x[ 4], y[ 2]);
    word3_muladd(&w2, &w1, &w0, x[ 5], y[ 1]);
    z[ 6] = w0; w0 = 0;
    
    word3_muladd(&w0, &w2, &w1, x[ 2], y[ 5]);
    word3_muladd(&w0, &w2, &w1, x[ 3], y[ 4]);
    word3_muladd(&w0, &w2, &w1, x[ 4], y[ 3]);
    word3_muladd(&w0, &w2, &w1, x[ 5], y[ 2]);
    z[ 7] = w1; w1 = 0;
    
    word3_muladd(&w1, &w0, &w2, x[ 3], y[ 5]);
    word3_muladd(&w1, &w0, &w2, x[ 4], y[ 4]);
    word3_muladd(&w1, &w0, &w2, x[ 5], y[ 3]);
    z[ 8] = w2; w2 = 0;
    
    word3_muladd(&w2, &w1, &w0, x[ 4], y[ 5]);
    word3_muladd(&w2, &w1, &w0, x[ 5], y[ 4]);
    z[ 9] = w0; w0 = 0;
    
    word3_muladd(&w0, &w2, &w1, x[ 5], y[ 5]);
    z[10] = w1;
    z[11] = w2;
}

/*
* Comba 8x8 Squaring
*/
void bigint_comba_sqr8(ref word[16] z, in word[8] x)
{
    word w2 = 0, w1 = 0, w0 = 0;
    
    word3_muladd(&w2, &w1, &w0, x[ 0], x[ 0]);
    z[ 0] = w0; w0 = 0;
    
    word3_muladd_2(&w0, &w2, &w1, x[ 0], x[ 1]);
    z[ 1] = w1; w1 = 0;
    
    word3_muladd_2(&w1, &w0, &w2, x[ 0], x[ 2]);
    word3_muladd(&w1, &w0, &w2, x[ 1], x[ 1]);
    z[ 2] = w2; w2 = 0;
    
    word3_muladd_2(&w2, &w1, &w0, x[ 0], x[ 3]);
    word3_muladd_2(&w2, &w1, &w0, x[ 1], x[ 2]);
    z[ 3] = w0; w0 = 0;
    
    word3_muladd_2(&w0, &w2, &w1, x[ 0], x[ 4]);
    word3_muladd_2(&w0, &w2, &w1, x[ 1], x[ 3]);
    word3_muladd(&w0, &w2, &w1, x[ 2], x[ 2]);
    z[ 4] = w1; w1 = 0;
    
    word3_muladd_2(&w1, &w0, &w2, x[ 0], x[ 5]);
    word3_muladd_2(&w1, &w0, &w2, x[ 1], x[ 4]);
    word3_muladd_2(&w1, &w0, &w2, x[ 2], x[ 3]);
    z[ 5] = w2; w2 = 0;
    
    word3_muladd_2(&w2, &w1, &w0, x[ 0], x[ 6]);
    word3_muladd_2(&w2, &w1, &w0, x[ 1], x[ 5]);
    word3_muladd_2(&w2, &w1, &w0, x[ 2], x[ 4]);
    word3_muladd(&w2, &w1, &w0, x[ 3], x[ 3]);
    z[ 6] = w0; w0 = 0;
    
    word3_muladd_2(&w0, &w2, &w1, x[ 0], x[ 7]);
    word3_muladd_2(&w0, &w2, &w1, x[ 1], x[ 6]);
    word3_muladd_2(&w0, &w2, &w1, x[ 2], x[ 5]);
    word3_muladd_2(&w0, &w2, &w1, x[ 3], x[ 4]);
    z[ 7] = w1; w1 = 0;
    
    word3_muladd_2(&w1, &w0, &w2, x[ 1], x[ 7]);
    word3_muladd_2(&w1, &w0, &w2, x[ 2], x[ 6]);
    word3_muladd_2(&w1, &w0, &w2, x[ 3], x[ 5]);
    word3_muladd(&w1, &w0, &w2, x[ 4], x[ 4]);
    z[ 8] = w2; w2 = 0;
    
    word3_muladd_2(&w2, &w1, &w0, x[ 2], x[ 7]);
    word3_muladd_2(&w2, &w1, &w0, x[ 3], x[ 6]);
    word3_muladd_2(&w2, &w1, &w0, x[ 4], x[ 5]);
    z[ 9] = w0; w0 = 0;
    
    word3_muladd_2(&w0, &w2, &w1, x[ 3], x[ 7]);
    word3_muladd_2(&w0, &w2, &w1, x[ 4], x[ 6]);
    word3_muladd(&w0, &w2, &w1, x[ 5], x[ 5]);
    z[10] = w1; w1 = 0;
    
    word3_muladd_2(&w1, &w0, &w2, x[ 4], x[ 7]);
    word3_muladd_2(&w1, &w0, &w2, x[ 5], x[ 6]);
    z[11] = w2; w2 = 0;
    
    word3_muladd_2(&w2, &w1, &w0, x[ 5], x[ 7]);
    word3_muladd(&w2, &w1, &w0, x[ 6], x[ 6]);
    z[12] = w0; w0 = 0;
    
    word3_muladd_2(&w0, &w2, &w1, x[ 6], x[ 7]);
    z[13] = w1; w1 = 0;
    
    word3_muladd(&w1, &w0, &w2, x[ 7], x[ 7]);
    z[14] = w2;
    z[15] = w0;
}

/*
* Comba 8x8 Multiplication
*/
void bigint_comba_mul8(ref word[16] z, in word[8] x, in word[8] y)
{
    word w2 = 0, w1 = 0, w0 = 0;
    
    word3_muladd(&w2, &w1, &w0, x[ 0], y[ 0]);
    z[ 0] = w0; w0 = 0;
    
    word3_muladd(&w0, &w2, &w1, x[ 0], y[ 1]);
    word3_muladd(&w0, &w2, &w1, x[ 1], y[ 0]);
    z[ 1] = w1; w1 = 0;
    
    word3_muladd(&w1, &w0, &w2, x[ 0], y[ 2]);
    word3_muladd(&w1, &w0, &w2, x[ 1], y[ 1]);
    word3_muladd(&w1, &w0, &w2, x[ 2], y[ 0]);
    z[ 2] = w2; w2 = 0;
    
    word3_muladd(&w2, &w1, &w0, x[ 0], y[ 3]);
    word3_muladd(&w2, &w1, &w0, x[ 1], y[ 2]);
    word3_muladd(&w2, &w1, &w0, x[ 2], y[ 1]);
    word3_muladd(&w2, &w1, &w0, x[ 3], y[ 0]);
    z[ 3] = w0; w0 = 0;
    
    word3_muladd(&w0, &w2, &w1, x[ 0], y[ 4]);
    word3_muladd(&w0, &w2, &w1, x[ 1], y[ 3]);
    word3_muladd(&w0, &w2, &w1, x[ 2], y[ 2]);
    word3_muladd(&w0, &w2, &w1, x[ 3], y[ 1]);
    word3_muladd(&w0, &w2, &w1, x[ 4], y[ 0]);
    z[ 4] = w1; w1 = 0;
    
    word3_muladd(&w1, &w0, &w2, x[ 0], y[ 5]);
    word3_muladd(&w1, &w0, &w2, x[ 1], y[ 4]);
    word3_muladd(&w1, &w0, &w2, x[ 2], y[ 3]);
    word3_muladd(&w1, &w0, &w2, x[ 3], y[ 2]);
    word3_muladd(&w1, &w0, &w2, x[ 4], y[ 1]);
    word3_muladd(&w1, &w0, &w2, x[ 5], y[ 0]);
    z[ 5] = w2; w2 = 0;
    
    word3_muladd(&w2, &w1, &w0, x[ 0], y[ 6]);
    word3_muladd(&w2, &w1, &w0, x[ 1], y[ 5]);
    word3_muladd(&w2, &w1, &w0, x[ 2], y[ 4]);
    word3_muladd(&w2, &w1, &w0, x[ 3], y[ 3]);
    word3_muladd(&w2, &w1, &w0, x[ 4], y[ 2]);
    word3_muladd(&w2, &w1, &w0, x[ 5], y[ 1]);
    word3_muladd(&w2, &w1, &w0, x[ 6], y[ 0]);
    z[ 6] = w0; w0 = 0;
    
    word3_muladd(&w0, &w2, &w1, x[ 0], y[ 7]);
    word3_muladd(&w0, &w2, &w1, x[ 1], y[ 6]);
    word3_muladd(&w0, &w2, &w1, x[ 2], y[ 5]);
    word3_muladd(&w0, &w2, &w1, x[ 3], y[ 4]);
    word3_muladd(&w0, &w2, &w1, x[ 4], y[ 3]);
    word3_muladd(&w0, &w2, &w1, x[ 5], y[ 2]);
    word3_muladd(&w0, &w2, &w1, x[ 6], y[ 1]);
    word3_muladd(&w0, &w2, &w1, x[ 7], y[ 0]);
    z[ 7] = w1; w1 = 0;
    
    word3_muladd(&w1, &w0, &w2, x[ 1], y[ 7]);
    word3_muladd(&w1, &w0, &w2, x[ 2], y[ 6]);
    word3_muladd(&w1, &w0, &w2, x[ 3], y[ 5]);
    word3_muladd(&w1, &w0, &w2, x[ 4], y[ 4]);
    word3_muladd(&w1, &w0, &w2, x[ 5], y[ 3]);
    word3_muladd(&w1, &w0, &w2, x[ 6], y[ 2]);
    word3_muladd(&w1, &w0, &w2, x[ 7], y[ 1]);
    z[ 8] = w2; w2 = 0;
    
    word3_muladd(&w2, &w1, &w0, x[ 2], y[ 7]);
    word3_muladd(&w2, &w1, &w0, x[ 3], y[ 6]);
    word3_muladd(&w2, &w1, &w0, x[ 4], y[ 5]);
    word3_muladd(&w2, &w1, &w0, x[ 5], y[ 4]);
    word3_muladd(&w2, &w1, &w0, x[ 6], y[ 3]);
    word3_muladd(&w2, &w1, &w0, x[ 7], y[ 2]);
    z[ 9] = w0; w0 = 0;
    
    word3_muladd(&w0, &w2, &w1, x[ 3], y[ 7]);
    word3_muladd(&w0, &w2, &w1, x[ 4], y[ 6]);
    word3_muladd(&w0, &w2, &w1, x[ 5], y[ 5]);
    word3_muladd(&w0, &w2, &w1, x[ 6], y[ 4]);
    word3_muladd(&w0, &w2, &w1, x[ 7], y[ 3]);
    z[10] = w1; w1 = 0;
    
    word3_muladd(&w1, &w0, &w2, x[ 4], y[ 7]);
    word3_muladd(&w1, &w0, &w2, x[ 5], y[ 6]);
    word3_muladd(&w1, &w0, &w2, x[ 6], y[ 5]);
    word3_muladd(&w1, &w0, &w2, x[ 7], y[ 4]);
    z[11] = w2; w2 = 0;
    
    word3_muladd(&w2, &w1, &w0, x[ 5], y[ 7]);
    word3_muladd(&w2, &w1, &w0, x[ 6], y[ 6]);
    word3_muladd(&w2, &w1, &w0, x[ 7], y[ 5]);
    z[12] = w0; w0 = 0;
    
    word3_muladd(&w0, &w2, &w1, x[ 6], y[ 7]);
    word3_muladd(&w0, &w2, &w1, x[ 7], y[ 6]);
    z[13] = w1; w1 = 0;
    
    word3_muladd(&w1, &w0, &w2, x[ 7], y[ 7]);
    z[14] = w2;
    z[15] = w0;
}

/*
* Comba 16x16 Squaring
*/
void bigint_comba_sqr16(ref word[32] z, in word[16] x)
{
    word w2 = 0, w1 = 0, w0 = 0;
    
    word3_muladd(&w2, &w1, &w0, x[ 0], x[ 0]);
    z[ 0] = w0; w0 = 0;
    
    word3_muladd_2(&w0, &w2, &w1, x[ 0], x[ 1]);
    z[ 1] = w1; w1 = 0;
    
    word3_muladd_2(&w1, &w0, &w2, x[ 0], x[ 2]);
    word3_muladd(&w1, &w0, &w2, x[ 1], x[ 1]);
    z[ 2] = w2; w2 = 0;
    
    word3_muladd_2(&w2, &w1, &w0, x[ 0], x[ 3]);
    word3_muladd_2(&w2, &w1, &w0, x[ 1], x[ 2]);
    z[ 3] = w0; w0 = 0;
    
    word3_muladd_2(&w0, &w2, &w1, x[ 0], x[ 4]);
    word3_muladd_2(&w0, &w2, &w1, x[ 1], x[ 3]);
    word3_muladd(&w0, &w2, &w1, x[ 2], x[ 2]);
    z[ 4] = w1; w1 = 0;
    
    word3_muladd_2(&w1, &w0, &w2, x[ 0], x[ 5]);
    word3_muladd_2(&w1, &w0, &w2, x[ 1], x[ 4]);
    word3_muladd_2(&w1, &w0, &w2, x[ 2], x[ 3]);
    z[ 5] = w2; w2 = 0;
    
    word3_muladd_2(&w2, &w1, &w0, x[ 0], x[ 6]);
    word3_muladd_2(&w2, &w1, &w0, x[ 1], x[ 5]);
    word3_muladd_2(&w2, &w1, &w0, x[ 2], x[ 4]);
    word3_muladd(&w2, &w1, &w0, x[ 3], x[ 3]);
    z[ 6] = w0; w0 = 0;
    
    word3_muladd_2(&w0, &w2, &w1, x[ 0], x[ 7]);
    word3_muladd_2(&w0, &w2, &w1, x[ 1], x[ 6]);
    word3_muladd_2(&w0, &w2, &w1, x[ 2], x[ 5]);
    word3_muladd_2(&w0, &w2, &w1, x[ 3], x[ 4]);
    z[ 7] = w1; w1 = 0;
    
    word3_muladd_2(&w1, &w0, &w2, x[ 0], x[ 8]);
    word3_muladd_2(&w1, &w0, &w2, x[ 1], x[ 7]);
    word3_muladd_2(&w1, &w0, &w2, x[ 2], x[ 6]);
    word3_muladd_2(&w1, &w0, &w2, x[ 3], x[ 5]);
    word3_muladd(&w1, &w0, &w2, x[ 4], x[ 4]);
    z[ 8] = w2; w2 = 0;
    
    word3_muladd_2(&w2, &w1, &w0, x[ 0], x[ 9]);
    word3_muladd_2(&w2, &w1, &w0, x[ 1], x[ 8]);
    word3_muladd_2(&w2, &w1, &w0, x[ 2], x[ 7]);
    word3_muladd_2(&w2, &w1, &w0, x[ 3], x[ 6]);
    word3_muladd_2(&w2, &w1, &w0, x[ 4], x[ 5]);
    z[ 9] = w0; w0 = 0;
    
    word3_muladd_2(&w0, &w2, &w1, x[ 0], x[10]);
    word3_muladd_2(&w0, &w2, &w1, x[ 1], x[ 9]);
    word3_muladd_2(&w0, &w2, &w1, x[ 2], x[ 8]);
    word3_muladd_2(&w0, &w2, &w1, x[ 3], x[ 7]);
    word3_muladd_2(&w0, &w2, &w1, x[ 4], x[ 6]);
    word3_muladd(&w0, &w2, &w1, x[ 5], x[ 5]);
    z[10] = w1; w1 = 0;
    
    word3_muladd_2(&w1, &w0, &w2, x[ 0], x[11]);
    word3_muladd_2(&w1, &w0, &w2, x[ 1], x[10]);
    word3_muladd_2(&w1, &w0, &w2, x[ 2], x[ 9]);
    word3_muladd_2(&w1, &w0, &w2, x[ 3], x[ 8]);
    word3_muladd_2(&w1, &w0, &w2, x[ 4], x[ 7]);
    word3_muladd_2(&w1, &w0, &w2, x[ 5], x[ 6]);
    z[11] = w2; w2 = 0;
    
    word3_muladd_2(&w2, &w1, &w0, x[ 0], x[12]);
    word3_muladd_2(&w2, &w1, &w0, x[ 1], x[11]);
    word3_muladd_2(&w2, &w1, &w0, x[ 2], x[10]);
    word3_muladd_2(&w2, &w1, &w0, x[ 3], x[ 9]);
    word3_muladd_2(&w2, &w1, &w0, x[ 4], x[ 8]);
    word3_muladd_2(&w2, &w1, &w0, x[ 5], x[ 7]);
    word3_muladd(&w2, &w1, &w0, x[ 6], x[ 6]);
    z[12] = w0; w0 = 0;
    
    word3_muladd_2(&w0, &w2, &w1, x[ 0], x[13]);
    word3_muladd_2(&w0, &w2, &w1, x[ 1], x[12]);
    word3_muladd_2(&w0, &w2, &w1, x[ 2], x[11]);
    word3_muladd_2(&w0, &w2, &w1, x[ 3], x[10]);
    word3_muladd_2(&w0, &w2, &w1, x[ 4], x[ 9]);
    word3_muladd_2(&w0, &w2, &w1, x[ 5], x[ 8]);
    word3_muladd_2(&w0, &w2, &w1, x[ 6], x[ 7]);
    z[13] = w1; w1 = 0;
    
    word3_muladd_2(&w1, &w0, &w2, x[ 0], x[14]);
    word3_muladd_2(&w1, &w0, &w2, x[ 1], x[13]);
    word3_muladd_2(&w1, &w0, &w2, x[ 2], x[12]);
    word3_muladd_2(&w1, &w0, &w2, x[ 3], x[11]);
    word3_muladd_2(&w1, &w0, &w2, x[ 4], x[10]);
    word3_muladd_2(&w1, &w0, &w2, x[ 5], x[ 9]);
    word3_muladd_2(&w1, &w0, &w2, x[ 6], x[ 8]);
    word3_muladd(&w1, &w0, &w2, x[ 7], x[ 7]);
    z[14] = w2; w2 = 0;
    
    word3_muladd_2(&w2, &w1, &w0, x[ 0], x[15]);
    word3_muladd_2(&w2, &w1, &w0, x[ 1], x[14]);
    word3_muladd_2(&w2, &w1, &w0, x[ 2], x[13]);
    word3_muladd_2(&w2, &w1, &w0, x[ 3], x[12]);
    word3_muladd_2(&w2, &w1, &w0, x[ 4], x[11]);
    word3_muladd_2(&w2, &w1, &w0, x[ 5], x[10]);
    word3_muladd_2(&w2, &w1, &w0, x[ 6], x[ 9]);
    word3_muladd_2(&w2, &w1, &w0, x[ 7], x[ 8]);
    z[15] = w0; w0 = 0;
    
    word3_muladd_2(&w0, &w2, &w1, x[ 1], x[15]);
    word3_muladd_2(&w0, &w2, &w1, x[ 2], x[14]);
    word3_muladd_2(&w0, &w2, &w1, x[ 3], x[13]);
    word3_muladd_2(&w0, &w2, &w1, x[ 4], x[12]);
    word3_muladd_2(&w0, &w2, &w1, x[ 5], x[11]);
    word3_muladd_2(&w0, &w2, &w1, x[ 6], x[10]);
    word3_muladd_2(&w0, &w2, &w1, x[ 7], x[ 9]);
    word3_muladd(&w0, &w2, &w1, x[ 8], x[ 8]);
    z[16] = w1; w1 = 0;
    
    word3_muladd_2(&w1, &w0, &w2, x[ 2], x[15]);
    word3_muladd_2(&w1, &w0, &w2, x[ 3], x[14]);
    word3_muladd_2(&w1, &w0, &w2, x[ 4], x[13]);
    word3_muladd_2(&w1, &w0, &w2, x[ 5], x[12]);
    word3_muladd_2(&w1, &w0, &w2, x[ 6], x[11]);
    word3_muladd_2(&w1, &w0, &w2, x[ 7], x[10]);
    word3_muladd_2(&w1, &w0, &w2, x[ 8], x[ 9]);
    z[17] = w2; w2 = 0;
    
    word3_muladd_2(&w2, &w1, &w0, x[ 3], x[15]);
    word3_muladd_2(&w2, &w1, &w0, x[ 4], x[14]);
    word3_muladd_2(&w2, &w1, &w0, x[ 5], x[13]);
    word3_muladd_2(&w2, &w1, &w0, x[ 6], x[12]);
    word3_muladd_2(&w2, &w1, &w0, x[ 7], x[11]);
    word3_muladd_2(&w2, &w1, &w0, x[ 8], x[10]);
    word3_muladd(&w2, &w1, &w0, x[ 9], x[ 9]);
    z[18] = w0; w0 = 0;
    
    word3_muladd_2(&w0, &w2, &w1, x[ 4], x[15]);
    word3_muladd_2(&w0, &w2, &w1, x[ 5], x[14]);
    word3_muladd_2(&w0, &w2, &w1, x[ 6], x[13]);
    word3_muladd_2(&w0, &w2, &w1, x[ 7], x[12]);
    word3_muladd_2(&w0, &w2, &w1, x[ 8], x[11]);
    word3_muladd_2(&w0, &w2, &w1, x[ 9], x[10]);
    z[19] = w1; w1 = 0;
    
    word3_muladd_2(&w1, &w0, &w2, x[ 5], x[15]);
    word3_muladd_2(&w1, &w0, &w2, x[ 6], x[14]);
    word3_muladd_2(&w1, &w0, &w2, x[ 7], x[13]);
    word3_muladd_2(&w1, &w0, &w2, x[ 8], x[12]);
    word3_muladd_2(&w1, &w0, &w2, x[ 9], x[11]);
    word3_muladd(&w1, &w0, &w2, x[10], x[10]);
    z[20] = w2; w2 = 0;
    
    word3_muladd_2(&w2, &w1, &w0, x[ 6], x[15]);
    word3_muladd_2(&w2, &w1, &w0, x[ 7], x[14]);
    word3_muladd_2(&w2, &w1, &w0, x[ 8], x[13]);
    word3_muladd_2(&w2, &w1, &w0, x[ 9], x[12]);
    word3_muladd_2(&w2, &w1, &w0, x[10], x[11]);
    z[21] = w0; w0 = 0;
    
    word3_muladd_2(&w0, &w2, &w1, x[ 7], x[15]);
    word3_muladd_2(&w0, &w2, &w1, x[ 8], x[14]);
    word3_muladd_2(&w0, &w2, &w1, x[ 9], x[13]);
    word3_muladd_2(&w0, &w2, &w1, x[10], x[12]);
    word3_muladd(&w0, &w2, &w1, x[11], x[11]);
    z[22] = w1; w1 = 0;
    
    word3_muladd_2(&w1, &w0, &w2, x[ 8], x[15]);
    word3_muladd_2(&w1, &w0, &w2, x[ 9], x[14]);
    word3_muladd_2(&w1, &w0, &w2, x[10], x[13]);
    word3_muladd_2(&w1, &w0, &w2, x[11], x[12]);
    z[23] = w2; w2 = 0;
    
    word3_muladd_2(&w2, &w1, &w0, x[ 9], x[15]);
    word3_muladd_2(&w2, &w1, &w0, x[10], x[14]);
    word3_muladd_2(&w2, &w1, &w0, x[11], x[13]);
    word3_muladd(&w2, &w1, &w0, x[12], x[12]);
    z[24] = w0; w0 = 0;
    
    word3_muladd_2(&w0, &w2, &w1, x[10], x[15]);
    word3_muladd_2(&w0, &w2, &w1, x[11], x[14]);
    word3_muladd_2(&w0, &w2, &w1, x[12], x[13]);
    z[25] = w1; w1 = 0;
    
    word3_muladd_2(&w1, &w0, &w2, x[11], x[15]);
    word3_muladd_2(&w1, &w0, &w2, x[12], x[14]);
    word3_muladd(&w1, &w0, &w2, x[13], x[13]);
    z[26] = w2; w2 = 0;
    
    word3_muladd_2(&w2, &w1, &w0, x[12], x[15]);
    word3_muladd_2(&w2, &w1, &w0, x[13], x[14]);
    z[27] = w0; w0 = 0;
    
    word3_muladd_2(&w0, &w2, &w1, x[13], x[15]);
    word3_muladd(&w0, &w2, &w1, x[14], x[14]);
    z[28] = w1; w1 = 0;
    
    word3_muladd_2(&w1, &w0, &w2, x[14], x[15]);
    z[29] = w2; w2 = 0;
    
    word3_muladd(&w2, &w1, &w0, x[15], x[15]);
    z[30] = w0;
    z[31] = w1;
}

/*
* Comba 16x16 Multiplication
*/
void bigint_comba_mul16(ref word[32] z, in word[16] x, in word[16] y)
{
    word w2 = 0, w1 = 0, w0 = 0;
    
    word3_muladd(&w2, &w1, &w0, x[ 0], y[ 0]);
    z[ 0] = w0; w0 = 0;
    
    word3_muladd(&w0, &w2, &w1, x[ 0], y[ 1]);
    word3_muladd(&w0, &w2, &w1, x[ 1], y[ 0]);
    z[ 1] = w1; w1 = 0;
    
    word3_muladd(&w1, &w0, &w2, x[ 0], y[ 2]);
    word3_muladd(&w1, &w0, &w2, x[ 1], y[ 1]);
    word3_muladd(&w1, &w0, &w2, x[ 2], y[ 0]);
    z[ 2] = w2; w2 = 0;
    
    word3_muladd(&w2, &w1, &w0, x[ 0], y[ 3]);
    word3_muladd(&w2, &w1, &w0, x[ 1], y[ 2]);
    word3_muladd(&w2, &w1, &w0, x[ 2], y[ 1]);
    word3_muladd(&w2, &w1, &w0, x[ 3], y[ 0]);
    z[ 3] = w0; w0 = 0;
    
    word3_muladd(&w0, &w2, &w1, x[ 0], y[ 4]);
    word3_muladd(&w0, &w2, &w1, x[ 1], y[ 3]);
    word3_muladd(&w0, &w2, &w1, x[ 2], y[ 2]);
    word3_muladd(&w0, &w2, &w1, x[ 3], y[ 1]);
    word3_muladd(&w0, &w2, &w1, x[ 4], y[ 0]);
    z[ 4] = w1; w1 = 0;
    
    word3_muladd(&w1, &w0, &w2, x[ 0], y[ 5]);
    word3_muladd(&w1, &w0, &w2, x[ 1], y[ 4]);
    word3_muladd(&w1, &w0, &w2, x[ 2], y[ 3]);
    word3_muladd(&w1, &w0, &w2, x[ 3], y[ 2]);
    word3_muladd(&w1, &w0, &w2, x[ 4], y[ 1]);
    word3_muladd(&w1, &w0, &w2, x[ 5], y[ 0]);
    z[ 5] = w2; w2 = 0;
    
    word3_muladd(&w2, &w1, &w0, x[ 0], y[ 6]);
    word3_muladd(&w2, &w1, &w0, x[ 1], y[ 5]);
    word3_muladd(&w2, &w1, &w0, x[ 2], y[ 4]);
    word3_muladd(&w2, &w1, &w0, x[ 3], y[ 3]);
    word3_muladd(&w2, &w1, &w0, x[ 4], y[ 2]);
    word3_muladd(&w2, &w1, &w0, x[ 5], y[ 1]);
    word3_muladd(&w2, &w1, &w0, x[ 6], y[ 0]);
    z[ 6] = w0; w0 = 0;
    
    word3_muladd(&w0, &w2, &w1, x[ 0], y[ 7]);
    word3_muladd(&w0, &w2, &w1, x[ 1], y[ 6]);
    word3_muladd(&w0, &w2, &w1, x[ 2], y[ 5]);
    word3_muladd(&w0, &w2, &w1, x[ 3], y[ 4]);
    word3_muladd(&w0, &w2, &w1, x[ 4], y[ 3]);
    word3_muladd(&w0, &w2, &w1, x[ 5], y[ 2]);
    word3_muladd(&w0, &w2, &w1, x[ 6], y[ 1]);
    word3_muladd(&w0, &w2, &w1, x[ 7], y[ 0]);
    z[ 7] = w1; w1 = 0;
    
    word3_muladd(&w1, &w0, &w2, x[ 0], y[ 8]);
    word3_muladd(&w1, &w0, &w2, x[ 1], y[ 7]);
    word3_muladd(&w1, &w0, &w2, x[ 2], y[ 6]);
    word3_muladd(&w1, &w0, &w2, x[ 3], y[ 5]);
    word3_muladd(&w1, &w0, &w2, x[ 4], y[ 4]);
    word3_muladd(&w1, &w0, &w2, x[ 5], y[ 3]);
    word3_muladd(&w1, &w0, &w2, x[ 6], y[ 2]);
    word3_muladd(&w1, &w0, &w2, x[ 7], y[ 1]);
    word3_muladd(&w1, &w0, &w2, x[ 8], y[ 0]);
    z[ 8] = w2; w2 = 0;
    
    word3_muladd(&w2, &w1, &w0, x[ 0], y[ 9]);
    word3_muladd(&w2, &w1, &w0, x[ 1], y[ 8]);
    word3_muladd(&w2, &w1, &w0, x[ 2], y[ 7]);
    word3_muladd(&w2, &w1, &w0, x[ 3], y[ 6]);
    word3_muladd(&w2, &w1, &w0, x[ 4], y[ 5]);
    word3_muladd(&w2, &w1, &w0, x[ 5], y[ 4]);
    word3_muladd(&w2, &w1, &w0, x[ 6], y[ 3]);
    word3_muladd(&w2, &w1, &w0, x[ 7], y[ 2]);
    word3_muladd(&w2, &w1, &w0, x[ 8], y[ 1]);
    word3_muladd(&w2, &w1, &w0, x[ 9], y[ 0]);
    z[ 9] = w0; w0 = 0;
    
    word3_muladd(&w0, &w2, &w1, x[ 0], y[10]);
    word3_muladd(&w0, &w2, &w1, x[ 1], y[ 9]);
    word3_muladd(&w0, &w2, &w1, x[ 2], y[ 8]);
    word3_muladd(&w0, &w2, &w1, x[ 3], y[ 7]);
    word3_muladd(&w0, &w2, &w1, x[ 4], y[ 6]);
    word3_muladd(&w0, &w2, &w1, x[ 5], y[ 5]);
    word3_muladd(&w0, &w2, &w1, x[ 6], y[ 4]);
    word3_muladd(&w0, &w2, &w1, x[ 7], y[ 3]);
    word3_muladd(&w0, &w2, &w1, x[ 8], y[ 2]);
    word3_muladd(&w0, &w2, &w1, x[ 9], y[ 1]);
    word3_muladd(&w0, &w2, &w1, x[10], y[ 0]);
    z[10] = w1; w1 = 0;
    
    word3_muladd(&w1, &w0, &w2, x[ 0], y[11]);
    word3_muladd(&w1, &w0, &w2, x[ 1], y[10]);
    word3_muladd(&w1, &w0, &w2, x[ 2], y[ 9]);
    word3_muladd(&w1, &w0, &w2, x[ 3], y[ 8]);
    word3_muladd(&w1, &w0, &w2, x[ 4], y[ 7]);
    word3_muladd(&w1, &w0, &w2, x[ 5], y[ 6]);
    word3_muladd(&w1, &w0, &w2, x[ 6], y[ 5]);
    word3_muladd(&w1, &w0, &w2, x[ 7], y[ 4]);
    word3_muladd(&w1, &w0, &w2, x[ 8], y[ 3]);
    word3_muladd(&w1, &w0, &w2, x[ 9], y[ 2]);
    word3_muladd(&w1, &w0, &w2, x[10], y[ 1]);
    word3_muladd(&w1, &w0, &w2, x[11], y[ 0]);
    z[11] = w2; w2 = 0;
    
    word3_muladd(&w2, &w1, &w0, x[ 0], y[12]);
    word3_muladd(&w2, &w1, &w0, x[ 1], y[11]);
    word3_muladd(&w2, &w1, &w0, x[ 2], y[10]);
    word3_muladd(&w2, &w1, &w0, x[ 3], y[ 9]);
    word3_muladd(&w2, &w1, &w0, x[ 4], y[ 8]);
    word3_muladd(&w2, &w1, &w0, x[ 5], y[ 7]);
    word3_muladd(&w2, &w1, &w0, x[ 6], y[ 6]);
    word3_muladd(&w2, &w1, &w0, x[ 7], y[ 5]);
    word3_muladd(&w2, &w1, &w0, x[ 8], y[ 4]);
    word3_muladd(&w2, &w1, &w0, x[ 9], y[ 3]);
    word3_muladd(&w2, &w1, &w0, x[10], y[ 2]);
    word3_muladd(&w2, &w1, &w0, x[11], y[ 1]);
    word3_muladd(&w2, &w1, &w0, x[12], y[ 0]);
    z[12] = w0; w0 = 0;
    
    word3_muladd(&w0, &w2, &w1, x[ 0], y[13]);
    word3_muladd(&w0, &w2, &w1, x[ 1], y[12]);
    word3_muladd(&w0, &w2, &w1, x[ 2], y[11]);
    word3_muladd(&w0, &w2, &w1, x[ 3], y[10]);
    word3_muladd(&w0, &w2, &w1, x[ 4], y[ 9]);
    word3_muladd(&w0, &w2, &w1, x[ 5], y[ 8]);
    word3_muladd(&w0, &w2, &w1, x[ 6], y[ 7]);
    word3_muladd(&w0, &w2, &w1, x[ 7], y[ 6]);
    word3_muladd(&w0, &w2, &w1, x[ 8], y[ 5]);
    word3_muladd(&w0, &w2, &w1, x[ 9], y[ 4]);
    word3_muladd(&w0, &w2, &w1, x[10], y[ 3]);
    word3_muladd(&w0, &w2, &w1, x[11], y[ 2]);
    word3_muladd(&w0, &w2, &w1, x[12], y[ 1]);
    word3_muladd(&w0, &w2, &w1, x[13], y[ 0]);
    z[13] = w1; w1 = 0;
    
    word3_muladd(&w1, &w0, &w2, x[ 0], y[14]);
    word3_muladd(&w1, &w0, &w2, x[ 1], y[13]);
    word3_muladd(&w1, &w0, &w2, x[ 2], y[12]);
    word3_muladd(&w1, &w0, &w2, x[ 3], y[11]);
    word3_muladd(&w1, &w0, &w2, x[ 4], y[10]);
    word3_muladd(&w1, &w0, &w2, x[ 5], y[ 9]);
    word3_muladd(&w1, &w0, &w2, x[ 6], y[ 8]);
    word3_muladd(&w1, &w0, &w2, x[ 7], y[ 7]);
    word3_muladd(&w1, &w0, &w2, x[ 8], y[ 6]);
    word3_muladd(&w1, &w0, &w2, x[ 9], y[ 5]);
    word3_muladd(&w1, &w0, &w2, x[10], y[ 4]);
    word3_muladd(&w1, &w0, &w2, x[11], y[ 3]);
    word3_muladd(&w1, &w0, &w2, x[12], y[ 2]);
    word3_muladd(&w1, &w0, &w2, x[13], y[ 1]);
    word3_muladd(&w1, &w0, &w2, x[14], y[ 0]);
    z[14] = w2; w2 = 0;
    
    word3_muladd(&w2, &w1, &w0, x[ 0], y[15]);
    word3_muladd(&w2, &w1, &w0, x[ 1], y[14]);
    word3_muladd(&w2, &w1, &w0, x[ 2], y[13]);
    word3_muladd(&w2, &w1, &w0, x[ 3], y[12]);
    word3_muladd(&w2, &w1, &w0, x[ 4], y[11]);
    word3_muladd(&w2, &w1, &w0, x[ 5], y[10]);
    word3_muladd(&w2, &w1, &w0, x[ 6], y[ 9]);
    word3_muladd(&w2, &w1, &w0, x[ 7], y[ 8]);
    word3_muladd(&w2, &w1, &w0, x[ 8], y[ 7]);
    word3_muladd(&w2, &w1, &w0, x[ 9], y[ 6]);
    word3_muladd(&w2, &w1, &w0, x[10], y[ 5]);
    word3_muladd(&w2, &w1, &w0, x[11], y[ 4]);
    word3_muladd(&w2, &w1, &w0, x[12], y[ 3]);
    word3_muladd(&w2, &w1, &w0, x[13], y[ 2]);
    word3_muladd(&w2, &w1, &w0, x[14], y[ 1]);
    word3_muladd(&w2, &w1, &w0, x[15], y[ 0]);
    z[15] = w0; w0 = 0;
    
    word3_muladd(&w0, &w2, &w1, x[ 1], y[15]);
    word3_muladd(&w0, &w2, &w1, x[ 2], y[14]);
    word3_muladd(&w0, &w2, &w1, x[ 3], y[13]);
    word3_muladd(&w0, &w2, &w1, x[ 4], y[12]);
    word3_muladd(&w0, &w2, &w1, x[ 5], y[11]);
    word3_muladd(&w0, &w2, &w1, x[ 6], y[10]);
    word3_muladd(&w0, &w2, &w1, x[ 7], y[ 9]);
    word3_muladd(&w0, &w2, &w1, x[ 8], y[ 8]);
    word3_muladd(&w0, &w2, &w1, x[ 9], y[ 7]);
    word3_muladd(&w0, &w2, &w1, x[10], y[ 6]);
    word3_muladd(&w0, &w2, &w1, x[11], y[ 5]);
    word3_muladd(&w0, &w2, &w1, x[12], y[ 4]);
    word3_muladd(&w0, &w2, &w1, x[13], y[ 3]);
    word3_muladd(&w0, &w2, &w1, x[14], y[ 2]);
    word3_muladd(&w0, &w2, &w1, x[15], y[ 1]);
    z[16] = w1; w1 = 0;
    
    word3_muladd(&w1, &w0, &w2, x[ 2], y[15]);
    word3_muladd(&w1, &w0, &w2, x[ 3], y[14]);
    word3_muladd(&w1, &w0, &w2, x[ 4], y[13]);
    word3_muladd(&w1, &w0, &w2, x[ 5], y[12]);
    word3_muladd(&w1, &w0, &w2, x[ 6], y[11]);
    word3_muladd(&w1, &w0, &w2, x[ 7], y[10]);
    word3_muladd(&w1, &w0, &w2, x[ 8], y[ 9]);
    word3_muladd(&w1, &w0, &w2, x[ 9], y[ 8]);
    word3_muladd(&w1, &w0, &w2, x[10], y[ 7]);
    word3_muladd(&w1, &w0, &w2, x[11], y[ 6]);
    word3_muladd(&w1, &w0, &w2, x[12], y[ 5]);
    word3_muladd(&w1, &w0, &w2, x[13], y[ 4]);
    word3_muladd(&w1, &w0, &w2, x[14], y[ 3]);
    word3_muladd(&w1, &w0, &w2, x[15], y[ 2]);
    z[17] = w2; w2 = 0;
    
    word3_muladd(&w2, &w1, &w0, x[ 3], y[15]);
    word3_muladd(&w2, &w1, &w0, x[ 4], y[14]);
    word3_muladd(&w2, &w1, &w0, x[ 5], y[13]);
    word3_muladd(&w2, &w1, &w0, x[ 6], y[12]);
    word3_muladd(&w2, &w1, &w0, x[ 7], y[11]);
    word3_muladd(&w2, &w1, &w0, x[ 8], y[10]);
    word3_muladd(&w2, &w1, &w0, x[ 9], y[ 9]);
    word3_muladd(&w2, &w1, &w0, x[10], y[ 8]);
    word3_muladd(&w2, &w1, &w0, x[11], y[ 7]);
    word3_muladd(&w2, &w1, &w0, x[12], y[ 6]);
    word3_muladd(&w2, &w1, &w0, x[13], y[ 5]);
    word3_muladd(&w2, &w1, &w0, x[14], y[ 4]);
    word3_muladd(&w2, &w1, &w0, x[15], y[ 3]);
    z[18] = w0; w0 = 0;
    
    word3_muladd(&w0, &w2, &w1, x[ 4], y[15]);
    word3_muladd(&w0, &w2, &w1, x[ 5], y[14]);
    word3_muladd(&w0, &w2, &w1, x[ 6], y[13]);
    word3_muladd(&w0, &w2, &w1, x[ 7], y[12]);
    word3_muladd(&w0, &w2, &w1, x[ 8], y[11]);
    word3_muladd(&w0, &w2, &w1, x[ 9], y[10]);
    word3_muladd(&w0, &w2, &w1, x[10], y[ 9]);
    word3_muladd(&w0, &w2, &w1, x[11], y[ 8]);
    word3_muladd(&w0, &w2, &w1, x[12], y[ 7]);
    word3_muladd(&w0, &w2, &w1, x[13], y[ 6]);
    word3_muladd(&w0, &w2, &w1, x[14], y[ 5]);
    word3_muladd(&w0, &w2, &w1, x[15], y[ 4]);
    z[19] = w1; w1 = 0;
    
    word3_muladd(&w1, &w0, &w2, x[ 5], y[15]);
    word3_muladd(&w1, &w0, &w2, x[ 6], y[14]);
    word3_muladd(&w1, &w0, &w2, x[ 7], y[13]);
    word3_muladd(&w1, &w0, &w2, x[ 8], y[12]);
    word3_muladd(&w1, &w0, &w2, x[ 9], y[11]);
    word3_muladd(&w1, &w0, &w2, x[10], y[10]);
    word3_muladd(&w1, &w0, &w2, x[11], y[ 9]);
    word3_muladd(&w1, &w0, &w2, x[12], y[ 8]);
    word3_muladd(&w1, &w0, &w2, x[13], y[ 7]);
    word3_muladd(&w1, &w0, &w2, x[14], y[ 6]);
    word3_muladd(&w1, &w0, &w2, x[15], y[ 5]);
    z[20] = w2; w2 = 0;
    
    word3_muladd(&w2, &w1, &w0, x[ 6], y[15]);
    word3_muladd(&w2, &w1, &w0, x[ 7], y[14]);
    word3_muladd(&w2, &w1, &w0, x[ 8], y[13]);
    word3_muladd(&w2, &w1, &w0, x[ 9], y[12]);
    word3_muladd(&w2, &w1, &w0, x[10], y[11]);
    word3_muladd(&w2, &w1, &w0, x[11], y[10]);
    word3_muladd(&w2, &w1, &w0, x[12], y[ 9]);
    word3_muladd(&w2, &w1, &w0, x[13], y[ 8]);
    word3_muladd(&w2, &w1, &w0, x[14], y[ 7]);
    word3_muladd(&w2, &w1, &w0, x[15], y[ 6]);
    z[21] = w0; w0 = 0;
    
    word3_muladd(&w0, &w2, &w1, x[ 7], y[15]);
    word3_muladd(&w0, &w2, &w1, x[ 8], y[14]);
    word3_muladd(&w0, &w2, &w1, x[ 9], y[13]);
    word3_muladd(&w0, &w2, &w1, x[10], y[12]);
    word3_muladd(&w0, &w2, &w1, x[11], y[11]);
    word3_muladd(&w0, &w2, &w1, x[12], y[10]);
    word3_muladd(&w0, &w2, &w1, x[13], y[ 9]);
    word3_muladd(&w0, &w2, &w1, x[14], y[ 8]);
    word3_muladd(&w0, &w2, &w1, x[15], y[ 7]);
    z[22] = w1; w1 = 0;
    
    word3_muladd(&w1, &w0, &w2, x[ 8], y[15]);
    word3_muladd(&w1, &w0, &w2, x[ 9], y[14]);
    word3_muladd(&w1, &w0, &w2, x[10], y[13]);
    word3_muladd(&w1, &w0, &w2, x[11], y[12]);
    word3_muladd(&w1, &w0, &w2, x[12], y[11]);
    word3_muladd(&w1, &w0, &w2, x[13], y[10]);
    word3_muladd(&w1, &w0, &w2, x[14], y[ 9]);
    word3_muladd(&w1, &w0, &w2, x[15], y[ 8]);
    z[23] = w2; w2 = 0;
    
    word3_muladd(&w2, &w1, &w0, x[ 9], y[15]);
    word3_muladd(&w2, &w1, &w0, x[10], y[14]);
    word3_muladd(&w2, &w1, &w0, x[11], y[13]);
    word3_muladd(&w2, &w1, &w0, x[12], y[12]);
    word3_muladd(&w2, &w1, &w0, x[13], y[11]);
    word3_muladd(&w2, &w1, &w0, x[14], y[10]);
    word3_muladd(&w2, &w1, &w0, x[15], y[ 9]);
    z[24] = w0; w0 = 0;
    
    word3_muladd(&w0, &w2, &w1, x[10], y[15]);
    word3_muladd(&w0, &w2, &w1, x[11], y[14]);
    word3_muladd(&w0, &w2, &w1, x[12], y[13]);
    word3_muladd(&w0, &w2, &w1, x[13], y[12]);
    word3_muladd(&w0, &w2, &w1, x[14], y[11]);
    word3_muladd(&w0, &w2, &w1, x[15], y[10]);
    z[25] = w1; w1 = 0;
    
    word3_muladd(&w1, &w0, &w2, x[11], y[15]);
    word3_muladd(&w1, &w0, &w2, x[12], y[14]);
    word3_muladd(&w1, &w0, &w2, x[13], y[13]);
    word3_muladd(&w1, &w0, &w2, x[14], y[12]);
    word3_muladd(&w1, &w0, &w2, x[15], y[11]);
    z[26] = w2; w2 = 0;
    
    word3_muladd(&w2, &w1, &w0, x[12], y[15]);
    word3_muladd(&w2, &w1, &w0, x[13], y[14]);
    word3_muladd(&w2, &w1, &w0, x[14], y[13]);
    word3_muladd(&w2, &w1, &w0, x[15], y[12]);
    z[27] = w0; w0 = 0;
    
    word3_muladd(&w0, &w2, &w1, x[13], y[15]);
    word3_muladd(&w0, &w2, &w1, x[14], y[14]);
    word3_muladd(&w0, &w2, &w1, x[15], y[13]);
    z[28] = w1; w1 = 0;
    
    word3_muladd(&w1, &w0, &w2, x[14], y[15]);
    word3_muladd(&w1, &w0, &w2, x[15], y[14]);
    z[29] = w2; w2 = 0;
    
    word3_muladd(&w2, &w1, &w0, x[15], y[15]);
    z[30] = w0;
    z[31] = w1;
}

/*
* Word Multiply/Add
*/
word word_madd2(word a, word b, word* c)
{
    static if (BOTAN_HAS_MP_DWORD) {
        const dword s = cast(dword)(a) * b + *c;
        *c = cast(word)(s >> BOTAN_MP_WORD_BITS);
        return cast(word)(s);
    } else {
        version(D_InlineAsm_X86_64) {
            word* _a = &a;
            asm pure nothrow @nogc {

                mov RAX, a;
                mov RBX, b;
                mul RBX;
                mov RCX, c;
                mov RBX, [RCX];
                add RAX, RBX;
                adc RDX, 0;
                mov [RCX], RDX;
                mov RBX, _a;
                mov [RBX], RAX;
            }
            return a;
        }
        else {
            static assert(BOTAN_MP_WORD_BITS == 64, "Unexpected word size");
            
            word[2] res;
            
            mul64x64_128(a, b, res);
            
            res[0] += *c;
            res[1] += (res[0] < *c); // carry?
            
            *c = res[1];
            return res[0];
        }
    }
}

/*
* Word Multiply/Add
*/
word word_madd3(word a, word b, word c, word* d)
{
    static if (BOTAN_HAS_MP_DWORD) {
        const dword s = cast(dword)(a) * b + c + *d;
        *d = cast(word)(s >> BOTAN_MP_WORD_BITS);
        return cast(word)(s);
    } else {
        version(D_InlineAsm_X86_64) {
            word* _a = &a;
            asm pure nothrow @nogc {
                mov RAX, a;
                mov RBX, b;
                mul RBX;
                mov RBX, d;
                mov RCX, c;
                add RAX, RCX;
                adc RDX, 0;
                add RAX, [RBX];
                adc RDX, 0;
                mov [RBX], RDX;
                mov RBX, _a;
                mov [RBX], RAX;
            }
            return a;
        }
        else {
            static assert(BOTAN_MP_WORD_BITS == 64, "Unexpected word size");
            
            word[2] res;
            
            mul64x64_128(a, b, res);
            
            res[0] += c;
            res[1] += (res[0] < c); // carry?
            
            res[0] += *d;
            res[1] += (res[0] < *d); // carry?
            
            *d = res[1];
            return res[0];
        }
    }
}


/*
* Word Addition
*/
word word_add(word x, word y, word* carry)
{
    word z = x + y;
    word c1 = (z < x);
    z += *carry;
    *carry = c1 | (z < *carry);
    return z;
}

/*
* Eight Word Block Addition, Two Argument
*/
word word8_add2(ref word[8] x, in word[8] y, word carry)
{
    x[0] = word_add(x[0], y[0], &carry);
    x[1] = word_add(x[1], y[1], &carry);
    x[2] = word_add(x[2], y[2], &carry);
    x[3] = word_add(x[3], y[3], &carry);
    x[4] = word_add(x[4], y[4], &carry);
    x[5] = word_add(x[5], y[5], &carry);
    x[6] = word_add(x[6], y[6], &carry);
    x[7] = word_add(x[7], y[7], &carry);
    return carry;
}

/*
* Eight Word Block Addition, Three Argument
*/
word word8_add3(ref word[8] z, in word[8] x, in word[8] y, word carry)
{
    z[0] = word_add(x[0], y[0], &carry);
    z[1] = word_add(x[1], y[1], &carry);
    z[2] = word_add(x[2], y[2], &carry);
    z[3] = word_add(x[3], y[3], &carry);
    z[4] = word_add(x[4], y[4], &carry);
    z[5] = word_add(x[5], y[5], &carry);
    z[6] = word_add(x[6], y[6], &carry);
    z[7] = word_add(x[7], y[7], &carry);
    return carry;
}

/*
* Word Subtraction
*/
word word_sub(word x, word y, word* carry)
{
    word t0 = x - y;
    word c1 = (t0 > x);
    word z = t0 - *carry;
    *carry = c1 | (z > t0);
    return z;
}

/*
* Eight Word Block Subtraction, Two Argument
*/
word word8_sub2(ref word[8] x, in word[8] y, word carry)
{
    x[0] = word_sub(x[0], y[0], &carry);
    x[1] = word_sub(x[1], y[1], &carry);
    x[2] = word_sub(x[2], y[2], &carry);
    x[3] = word_sub(x[3], y[3], &carry);
    x[4] = word_sub(x[4], y[4], &carry);
    x[5] = word_sub(x[5], y[5], &carry);
    x[6] = word_sub(x[6], y[6], &carry);
    x[7] = word_sub(x[7], y[7], &carry);
    return carry;
}

/*
* Eight Word Block Subtraction, Two Argument
*/
word word8_sub2_rev(ref word[8] x, in word[8] y, word carry)
{
    x[0] = word_sub(y[0], x[0], &carry);
    x[1] = word_sub(y[1], x[1], &carry);
    x[2] = word_sub(y[2], x[2], &carry);
    x[3] = word_sub(y[3], x[3], &carry);
    x[4] = word_sub(y[4], x[4], &carry);
    x[5] = word_sub(y[5], x[5], &carry);
    x[6] = word_sub(y[6], x[6], &carry);
    x[7] = word_sub(y[7], x[7], &carry);
    return carry;
}

/*
* Eight Word Block Subtraction, Three Argument
*/
word word8_sub3(ref word[8] z, in word[8] x, in word[8] y, word carry)
{
    z[0] = word_sub(x[0], y[0], &carry);
    z[1] = word_sub(x[1], y[1], &carry);
    z[2] = word_sub(x[2], y[2], &carry);
    z[3] = word_sub(x[3], y[3], &carry);
    z[4] = word_sub(x[4], y[4], &carry);
    z[5] = word_sub(x[5], y[5], &carry);
    z[6] = word_sub(x[6], y[6], &carry);
    z[7] = word_sub(x[7], y[7], &carry);
    return carry;
}

/*
* Eight Word Block Linear Multiplication
*/
word word8_linmul2(ref word[8] x, word y, word carry)
{
    x[0] = word_madd2(x[0], y, &carry);
    x[1] = word_madd2(x[1], y, &carry);
    x[2] = word_madd2(x[2], y, &carry);
    x[3] = word_madd2(x[3], y, &carry);
    x[4] = word_madd2(x[4], y, &carry);
    x[5] = word_madd2(x[5], y, &carry);
    x[6] = word_madd2(x[6], y, &carry);
    x[7] = word_madd2(x[7], y, &carry);
    return carry;
}

/*
* Eight Word Block Linear Multiplication
*/
word word8_linmul3(ref word[8] z, in word[8] x, word y, word carry)
{
    z[0] = word_madd2(x[0], y, &carry);
    z[1] = word_madd2(x[1], y, &carry);
    z[2] = word_madd2(x[2], y, &carry);
    z[3] = word_madd2(x[3], y, &carry);
    z[4] = word_madd2(x[4], y, &carry);
    z[5] = word_madd2(x[5], y, &carry);
    z[6] = word_madd2(x[6], y, &carry);
    z[7] = word_madd2(x[7], y, &carry);
    return carry;
}

/*
* Eight Word Block Multiply/Add
*/
word word8_madd3(ref word[8] z, in word[8] x, word y, word carry)
{
    z[0] = word_madd3(x[0], y, z[0], &carry);
    z[1] = word_madd3(x[1], y, z[1], &carry);
    z[2] = word_madd3(x[2], y, z[2], &carry);
    z[3] = word_madd3(x[3], y, z[3], &carry);
    z[4] = word_madd3(x[4], y, z[4], &carry);
    z[5] = word_madd3(x[5], y, z[5], &carry);
    z[6] = word_madd3(x[6], y, z[6], &carry);
    z[7] = word_madd3(x[7], y, z[7], &carry);
    return carry;
}

/*
* Multiply-Add Accumulator
*/
void word3_muladd(word* w2, word* w1, word* w0, word a, word b)
{
    word carry = *w0;
    *w0 = word_madd2(a, b, &carry);
    *w1 += carry;
    *w2 += (*w1 < carry) ? 1 : 0;
}

/*
* Multiply-Add Accumulator
*/
void word3_muladd_2(word* w2, word* w1, word* w0, word a, word b)
{
    word carry = 0;
    a = word_madd2(a, b, &carry);
    b = carry;
    
    word top = (b >> (BOTAN_MP_WORD_BITS-1));
    b <<= 1;
    b |= (a >> (BOTAN_MP_WORD_BITS-1));
    a <<= 1;
    
    carry = 0;
    *w0 = word_add(*w0, a, &carry);
    *w1 = word_add(*w1, b, &carry);
    *w2 = word_add(*w2, top, &carry);
}

__gshared immutable size_t KARATSUBA_MULTIPLY_THRESHOLD = 32;
__gshared immutable size_t KARATSUBA_SQUARE_THRESHOLD = 32;

/*
* Karatsuba Multiplication Operation
*/
void karatsuba_mul(word* z, in word* x, in word* y, size_t N, word* workspace)
{
    if (N < KARATSUBA_MULTIPLY_THRESHOLD || N % 2)
    {
        if (N == 6)
            return bigint_comba_mul6(*cast(word[12]*) z, *cast(word[6]*) x, *cast(word[6]*) y);
        else if (N == 8)
            return bigint_comba_mul8(*cast(word[16]*) z, *cast(word[8]*) x, *cast(word[8]*) y);
        else if (N == 16)
            return bigint_comba_mul16(*cast(word[32]*) z, *cast(word[16]*) x, *cast(word[16]*) y);
        else
            return bigint_simple_mul(z, x, N, y, N);
    }
    
    const size_t N2 = N / 2;
    
    const word* x0 = x;
    const word* x1 = x + N2;
    const word* y0 = y;
    const word* y1 = y + N2;
    word* z0 = z;
    word* z1 = z + N;
    
    const int cmp0 = bigint_cmp(x0, N2, x1, N2);
    const int cmp1 = bigint_cmp(y1, N2, y0, N2);
    
    clearMem(workspace, 2*N);
    
    //if (cmp0 && cmp1)
    {
        if (cmp0 > 0)
            bigint_sub3(z0, x0, N2, x1, N2);
        else
            bigint_sub3(z0, x1, N2, x0, N2);
        
        if (cmp1 > 0)
            bigint_sub3(z1, y1, N2, y0, N2);
        else
            bigint_sub3(z1, y0, N2, y1, N2);
        
        karatsuba_mul(workspace, z0, z1, N2, workspace+N);
    }
    
    karatsuba_mul(z0, x0, y0, N2, workspace+N);
    karatsuba_mul(z1, x1, y1, N2, workspace+N);
    
    const word ws_carry = bigint_add3_nc(workspace + N, z0, N, z1, N);
    word z_carry = bigint_add2_nc(z + N2, N, workspace + N, N);
    
    z_carry += bigint_add2_nc(z + N + N2, N2, &ws_carry, 1);
    bigint_add2_nc(z + N + N2, N2, &z_carry, 1);
    
    if ((cmp0 == cmp1) || (cmp0 == 0) || (cmp1 == 0))
        bigint_add2(z + N2, 2*N-N2, workspace, N);
    else
        bigint_sub2(z + N2, 2*N-N2, workspace, N);
}

/*
* Karatsuba Squaring Operation
*/
void karatsuba_sqr(word* z, in word* x, size_t N, word* workspace)
{
    if (N < KARATSUBA_SQUARE_THRESHOLD || N % 2)
    {
        if (N == 6)
            return bigint_comba_sqr6(*cast(word[12]*) z, *cast(word[6]*) x);
        else if (N == 8)
            return bigint_comba_sqr8(*cast(word[16]*) z, *cast(word[8]*) x);
        else if (N == 16)
            return bigint_comba_sqr16(*cast(word[32]*) z, *cast(word[16]*) x);
        else
            return bigint_simple_sqr(z, x, N);
    }
    
    const size_t N2 = N / 2;
    
    const word* x0 = x;
    const word* x1 = x + N2;
    word* z0 = z;
    word* z1 = z + N;
    
    const int cmp = bigint_cmp(x0, N2, x1, N2);
    
    clearMem(workspace, 2*N);
    
    //if (cmp)
    {
        if (cmp > 0)
            bigint_sub3(z0, x0, N2, x1, N2);
        else
            bigint_sub3(z0, x1, N2, x0, N2);
        
        karatsuba_sqr(workspace, z0, N2, workspace+N);
    }
    
    karatsuba_sqr(z0, x0, N2, workspace+N);
    karatsuba_sqr(z1, x1, N2, workspace+N);
    
    const word ws_carry = bigint_add3_nc(workspace + N, z0, N, z1, N);
    word z_carry = bigint_add2_nc(z + N2, N, workspace + N, N);
    
    z_carry += bigint_add2_nc(z + N + N2, N2, &ws_carry, 1);
    bigint_add2_nc(z + N + N2, N2, &z_carry, 1);
    
    /*
    * This is only actually required if cmp is != 0, however
    * if cmp==0 then workspace[0:N] == 0 and avoiding the jump
    * hides a timing channel.
    */
    bigint_sub2(z + N2, 2*N-N2, workspace, N);
}

/*
* Pick a good size for the Karatsuba multiply
*/
size_t karatsuba_size(size_t z_size,
                      size_t x_size, size_t x_sw,
                      size_t y_size, size_t y_sw)
{
    if (x_sw > x_size || x_sw > y_size || y_sw > x_size || y_sw > y_size)
        return 0;
    
    if (((x_size == x_sw) && (x_size % 2)) ||
        ((y_size == y_sw) && (y_size % 2)))
        return 0;
    
    const size_t start = (x_sw > y_sw) ? x_sw : y_sw;
    const size_t end = (x_size < y_size) ? x_size : y_size;
    
    if (start == end)
    {
        if (start % 2)
            return 0;
        return start;
    }
    
    for (size_t j = start; j <= end; ++j)
    {
        if (j % 2)
            continue;
        
        if (2*j > z_size)
            return 0;
        
        if (x_sw <= j && j <= x_size && y_sw <= j && j <= y_size)
        {
            if (j % 4 == 2 &&
                (j+2) <= x_size && (j+2) <= y_size && 2*(j+2) <= z_size)
                return j+2;
            return j;
        }
    }
    
    return 0;
}

/*
* Pick a good size for the Karatsuba squaring
*/
size_t karatsuba_size(size_t z_size, size_t x_size, size_t x_sw)
{
    if (x_sw == x_size)
    {
        if (x_sw % 2)
            return 0;
        return x_sw;
    }
    
    for (size_t j = x_sw; j <= x_size; ++j)
    {
        if (j % 2)
            continue;
        
        if (2*j > z_size)
            return 0;
        
        if (j % 4 == 2 && (j+2) <= x_size && 2*(j+2) <= z_size)
            return j+2;
        return j;
    }
    
    return 0;
}