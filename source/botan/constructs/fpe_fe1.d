/**
* Format Preserving Encryption (FE1 scheme)
* 
* Copyright:
* (C) 2009 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.constructs.fpe_fe1;

import botan.constants;
static if (BOTAN_HAS_FPE_FE1):

import botan.math.bigint.bigint;
import botan.algo_base.symkey;
import botan.math.numbertheory.numthry;
import botan.mac.hmac;
import botan.hash.sha2_32;
import botan.mac.mac;
import botan.utils.exceptn;
import botan.utils.types;
import botan.utils.mem_ops;
import std.exception;
import std.algorithm : swap;

struct FPE {

    /**
    * Format Preserving Encryption using the scheme FE1 from the paper
    * "Format-Preserving Encryption" by Bellare, Rogaway, et al
    * (http://eprint.iacr.org/2009/251)
    *
    * Encrypt X from and onto the group Z_n using key and tweak
    * 
    * Params:
    *  n = the modulus
    *  X = the plaintext as a BigInt
    *  key = a random key
    *  tweak = will modify the ciphertext (think of as an IV)
    */
    static BigInt fe1Encrypt(const(BigInt)* n0, const(BigInt)* X0,
                             in SymmetricKey key,
                             const ref Vector!ubyte tweak)
    {
        Unique!FPEEncryptor F = new FPEEncryptor(key, n0, tweak);
        
        BigInt a, b;
        factor(n0.clone, &a, &b);
        
        const size_t r = rounds(&a, &b);
        
        BigInt X = X0.clone;
        
        foreach (size_t i; 0 .. r)
        {
            BigInt L = X / b;
            BigInt R = X % b;
            auto W_0 = F(i, &R);
            BigInt W = (L + W_0) % a;
            X = (a * R) + W;
        }
        
        return X;
    }


    /**
    * Decrypt X from and onto the group Z_n using key and tweak
    * Params:
    *  n = the modulus
    *  X = the ciphertext as a BigInt
    *  key = is the key used for encryption
    *  tweak = the same tweak used for encryption
    */
    static BigInt fe1Decrypt(const(BigInt)* n0, const(BigInt)* X0, in SymmetricKey key, const ref Vector!ubyte tweak)
    {
        auto F = scoped!FPEEncryptor(key, n0, tweak);
        
        BigInt a, b;
        factor(n0.clone, &a, &b);
        
        const size_t r = rounds(&a, &b);
        
        BigInt X = X0.clone;
        
        foreach (size_t i; 0 .. r)
        {
            BigInt W = X % a;
            BigInt R = X / a;
            auto L_0 = F(r-i-1, &R);
            BigInt L = (W - L_0) % a;
            X = (b * L) + R;
        }
        
        return X;
    }


}

private:

// Normally FPE is for SSNs, CC#s, etc, nothing too big
__gshared immutable size_t MAX_N_BYTES = 128/8;

/*
* Factor n into a and b which are as close together as possible.
* Assumes n is composed mostly of small factors which is the case for
* typical uses of FPE (typically, n is a power of 10)
*
* Want a >= b since the safe number of rounds is 2+log_a(b); if a >= b
* then this is always 3
*/
void factor(BigInt n, BigInt* a, BigInt* b)
{
    *a = 1;
    *b = 1;
    
    size_t n_low_zero = lowZeroBits(&n);
    
    *a <<= (n_low_zero / 2);
    *b <<= n_low_zero - (n_low_zero / 2);
    n >>= n_low_zero;
    
    foreach (size_t i; 0 .. PRIME_TABLE_SIZE)
    {
        while (n % PRIMES[i] == 0)
        {
            *a *= PRIMES[i];
            if (*a > b)
                swap(a, b);
            n /= PRIMES[i];
        }
    }
    
    if (*a > b)
        swap(a, b);
    *a *= n;
    if (*a < b)
        swap(a, b);
    
    if (*a <= 1 || *b <= 1)
        throw new Exception("Could not factor n for use in FPE");
}

/*
* According to a paper by Rogaway, Bellare, etc, the min safe number
* of rounds to use for FPE is 2+log_a(b). If a >= b then log_a(b) <= 1
* so 3 rounds is safe. The FPE factorization routine should always
* return a >= b, so just confirm that and return 3.
*/
size_t rounds(const(BigInt)* a, const(BigInt)* b)
{
    if (a < b)
        throw new LogicError("FPE rounds: a < b");
    return 3;
}

/*
* A simple round function based on HMAC(SHA-256)
*/
final class FPEEncryptor
{
public:
    this()(in SymmetricKey key, const(BigInt)* n, const ref Vector!ubyte tweak)
    {

        m_mac = new HMAC(new SHA256);
        m_mac.setKey(key);
        
        Vector!ubyte n_bin = BigInt.encode(n);
        
        if (n_bin.length > MAX_N_BYTES)
            throw new Exception("N is too large for FPE encryption");
        
        m_mac.updateBigEndian(cast(uint)(n_bin.length));
        m_mac.update(n_bin.ptr, n_bin.length);
        
        m_mac.updateBigEndian(cast(uint)(tweak.length));
        m_mac.update(tweak.ptr, tweak.length);
        
        m_mac_n_t = unlock(m_mac.finished());
    }

    
    BigInt opCall(size_t round_no, const(BigInt)* R)
    {
        SecureVector!ubyte r_bin = BigInt.encodeLocked(R);

        m_mac.update(m_mac_n_t);
        m_mac.updateBigEndian(cast(uint)(round_no));
        
        m_mac.updateBigEndian(cast(uint)(r_bin.length));
        m_mac.update(r_bin.ptr, r_bin.length);
        
        SecureVector!ubyte X = m_mac.finished();
        return BigInt(X.ptr, X.length);
    }
    
private:
    Unique!MessageAuthenticationCode m_mac;
    Vector!ubyte m_mac_n_t;
}