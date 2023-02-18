/**
* Division
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.math.bigint.divide;

import botan.constants;
import botan.math.bigint.bigint;
import botan.math.mp.mp_core;
import botan.constants;
import std.algorithm : max;
/**
* BigInt Division
* Params:
*  x = an integer
*  y_arg = a non-zero integer
*  q = will be set to x / y
*  r = will be set to x % y
*/
void divide(const(BigInt)* x, const(BigInt)* y_arg, BigInt* q, BigInt* r)
{
    /*
    * Solve x = q * y + r
    */
    if (y_arg.isZero())
        throw new BigInt.DivideByZero();
    
    BigInt y = y_arg.clone;
    const size_t y_words = y.sigWords();
    
    *r = x.clone;
    *q = 0;
    
    r.setSign(BigInt.Positive);
    y.setSign(BigInt.Positive);
    
    int compare = r.cmp(y);
    
    if (compare == 0)
    {
        *q = 1;
        *r = 0;
    }
    else if (compare > 0)
    {
        size_t shifts = 0;
        word y_top = y.wordAt(y.sigWords()-1);
        while (y_top < MP_WORD_TOP_BIT) { y_top <<= 1; ++shifts; }
        y <<= shifts;
        *r <<= shifts;
        
        const size_t n = r.sigWords() - 1, t = y_words - 1;
        
        if (n < t)
            throw new InternalError("BigInt division word sizes");
        
        q.growTo(n - t + 1);
        
        word* q_words = q.mutablePtr();
        
        if (n <= t)
        {
            while (*r > y) { *r -= y; ++(*q); }
            *r >>= shifts;
            signFixup(x, y_arg, q, r);
            return;
        }
        
        BigInt temp = y << (MP_WORD_BITS * (n-t));
        
        while (*r >= temp) { *r -= temp; q_words[n-t] += 1; }
        
        for (size_t j = n; j != t; --j)
        {
            const word x_j0  = r.wordAt(j);
            const word x_j1 = r.wordAt(j-1);
            const word y_t  = y.wordAt(t);
            if (y_t == 0)
                throw new InvalidArgument("Division by zero due to too large bn");
            
            if (x_j0 == y_t)
                q_words[j-t-1] = MP_WORD_MAX;
            else
                q_words[j-t-1] = bigint_divop(x_j0, x_j1, y_t);
            
            while (divisionCheck(q_words[j-t-1], y_t, y.wordAt(t-1), x_j0, x_j1, r.wordAt(j-2)))
            {
                q_words[j-t-1] -= 1;
            }
			auto y_1 = (y * q_words[j-t-1]);
			auto j_t_1 = (j-t-1);
            y_1 <<= (MP_WORD_BITS * j_t_1);
            *r -= y_1;
            
            if (r.isNegative())
            {
                y <<= (MP_WORD_BITS * (j-t-1));
                *r += y;
                q_words[j-t-1] -= 1;
            }
        }
        *r >>= shifts;
    }
    
    signFixup(x, y_arg, q, r);
}

private:
/*
* Handle signed operands, if necessary
*/
void signFixup(const(BigInt)* x, const(BigInt)* y, BigInt* q, BigInt* r)
{
    if (x.sign() == BigInt.Negative)
    {
        q.flipSign();
        if (r.isNonzero()) { --*q; *r = y.abs() - *r; }
    }
    if (y.sign() == BigInt.Negative)
        q.flipSign();
}

bool divisionCheck(word q, word y2, word y1, word x3, word x2, word x1)
{
    // Compute (y3,y2,y1) = (y2,y1) * q
    
    word y3 = 0;
    y1 = word_madd2(q, y1, &y3);
    y2 = word_madd2(q, y2, &y3);

    // Return (y3,y2,y1) >? (x3,x2,x1)
    
    if (y3 > x3) return true;
    if (y3 < x3) return false;
    
    if (y2 > x2) return true;
    if (y2 < x2) return false;
    
    if (y1 > x1) return true;
    if (y1 < x1) return false;
    
    return false;
}
