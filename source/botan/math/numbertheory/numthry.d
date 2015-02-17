/**
* Number Theory Functions
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.math.numbertheory.numthry;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

public import botan.math.bigint.bigint;
public import botan.math.numbertheory.pow_mod;
public import botan.math.numbertheory.primes;
public import botan.utils.types;
import botan.rng.rng;
import botan.hash.hash;
import botan.utils.parsing;
import std.algorithm;
import botan.math.numbertheory.reducer;
import botan.utils.bit_ops;
import botan.math.mp.mp_core;
import botan.utils.rounding;
import botan.algo_factory.algo_factory : AlgorithmFactory;
import botan.constants;
import std.conv : to;

/**
* Fused multiply-add
* Params:
*  a = an integer
*  b = an integer
*  c = an integer
* Returns: (a*b)+c
*/
/*
* Multiply-Add Operation
*/
BigInt mulAdd()(auto const ref BigInt a, auto const ref BigInt b, auto const ref BigInt c)
{
    if (c.isNegative() || c.isZero())
        throw new InvalidArgument("mulAdd: Third argument must be > 0");
    
    BigInt.Sign sign = BigInt.Positive;
    if (a.sign() != b.sign())
        sign = BigInt.Negative;
    
    const size_t a_sw = a.sigWords();
    const size_t b_sw = b.sigWords();
    const size_t c_sw = c.sigWords();
    
    BigInt r = BigInt(sign, std.algorithm.max(a.length + b.length, c_sw) + 1);
    SecureVector!word workspace = SecureVector!word(r.length);
    
    bigint_mul(r.mutablePtr(), r.length, workspace.ptr, a.ptr, a.length, a_sw, b.ptr, b.length, b_sw);
    
    const size_t r_size = std.algorithm.max(r.sigWords(), c_sw);
    bigint_add2(r.mutablePtr(), r_size, c.ptr, c_sw);
    return r;
}


/**
* Fused subtract-multiply
* Params:
*  a = an integer
*  b = an integer
*  c = an integer
* Returns: (a-b)*c
*/
BigInt subMul()(auto const ref BigInt a, auto const ref BigInt b, auto const ref BigInt c)
{
    if (a.isNegative() || b.isNegative())
        throw new InvalidArgument("subMul: First two arguments must be >= 0");
    
    BigInt r = a.dup;
    r -= b;
    r *= c;
    return r.move();
}

/**
* Return the absolute value
* Params:
*  n = an integer
* Returns: absolute value of n
*/
 BigInt abs()(auto const ref BigInt n) { return n.abs(); }

/**
* Compute the greatest common divisor
* Params:
*  x = a positive integer
*  y = a positive integer
* Returns: gcd(x,y)
*/
BigInt gcd()(auto const ref BigInt a, auto const ref BigInt b)
{
    if (a.isZero() || b.isZero()) return BigInt(0);
    if (a == 1 || b == 1)         return BigInt(1);
    
    BigInt x = a.dup, y = b.dup;
    x.setSign(BigInt.Positive);
    y.setSign(BigInt.Positive);
    size_t shift = std.algorithm.min(lowZeroBits(x), lowZeroBits(y));
    
    x >>= shift;
    y >>= shift;
    
    while (x.isNonzero())
    {
        x >>= lowZeroBits(x);
        y >>= lowZeroBits(y);
        if (x >= y) { x -= y; x >>= 1; }
        else         { y -= x; y >>= 1; }
    }
    
    return (y << shift);
}

/**
* Least common multiple
* Params:
*  x = a positive integer
*  y = a positive integer
* Returns: z, smallest integer such that z % x == 0 and z % y == 0
*/
BigInt lcm()(auto const ref BigInt a, auto const ref BigInt b)
{
    return ((a * b) / gcd(a, b));
}


/**
* Params:
*  x = an integer
* Returns: (x*x)
*/
BigInt square()(auto const ref BigInt x)
{
    const size_t x_sw = x.sigWords();
    
    BigInt z = BigInt(BigInt.Positive, roundUp!size_t(2*x_sw, 16));
    SecureVector!word workspace = SecureVector!word(z.length);
    
    bigint_sqr(z.mutablePtr(), z.length, workspace.ptr, x.ptr, x.length, x_sw);
    return z;
}

/**
* Modular inversion
* Params:
*  x = a positive integer
*  modulus = a positive integer
* Returns: y st (x*y) % modulus == 1
*/
BigInt inverseMod()(auto const ref BigInt n, auto const ref BigInt mod)
{
    if (mod.isZero())
        throw new BigInt.DivideByZero();
    if (mod.isNegative() || n.isNegative())
        throw new InvalidArgument("inverseMod: arguments must be non-negative");
    
    if (n.isZero() || (n.isEven() && mod.isEven()))
        return BigInt(0); // fast fail checks
    
    if (mod.isOdd())
        return inverseModOddModulus(n, mod);
    
    BigInt u = mod.dup, v = n.dup;
    BigInt A = BigInt(1);
    BigInt B = BigInt(0);
    BigInt C = BigInt(0);
    BigInt D = BigInt(1);
    
    while (u.isNonzero())
    {
        const size_t u_zero_bits = lowZeroBits(u);
        u >>= u_zero_bits;
        foreach (size_t i; 0 .. u_zero_bits)
        {
            if (A.isOdd() || B.isOdd())
            { A += n; B -= mod; }
            A >>= 1; B >>= 1;
        }
        
        const size_t v_zero_bits = lowZeroBits(v);
        v >>= v_zero_bits;
        foreach (size_t i; 0 .. v_zero_bits)
        {
            if (C.isOdd() || D.isOdd())
            { C += n; D -= mod; }
            C >>= 1; D >>= 1;
        }
        
        if (u >= v) { u -= v; A -= C; B -= D; }
        else         { v -= u; C -= A; D -= B; }
    }
    
    if (v != 1)
        return BigInt(0); // no modular inverse
    
    while (D.isNegative()) D += mod;
    while (D >= mod) D -= mod;
    
    return D.move();
}


/**
* Compute the Jacobi symbol. If n is prime, this is equivalent
* to the Legendre symbol.
* @see http://mathworld.wolfram.com/JacobiSymbol.html
*
* Params:
*  a = is a non-negative integer
*  n = is an odd integer > 1
* Returns: (n / m)
*/
int jacobi()(auto const ref BigInt a, auto const ref BigInt n)
{
    if (a.isNegative())
        throw new InvalidArgument("jacobi: first argument must be non-negative");
    if (n.isEven() || n < 2)
        throw new InvalidArgument("jacobi: second argument must be odd and > 1");
    
    BigInt x = a.dup, y = n.dup;
    int J = 1;
    
    while (y > 1)
    {
        x %= y;
        if (x > y / 2)
        {
            x = y - x;
            if (y % 4 == 3)
                J = -J;
        }
        if (x.isZero())
            return 0;
        
        size_t shifts = lowZeroBits(x);
        x >>= shifts;
        if (shifts % 2)
        {
            word y_mod_8 = y % 8;
            if (y_mod_8 == 3 || y_mod_8 == 5)
                J = -J;
        }
        
        if (x % 4 == 3 && y % 4 == 3)
            J = -J;
        std.algorithm.swap(x, y);
    }
    return J;
}

/**
* Modular exponentation
* Params:
*  b = an integer base
*  x = a positive exponent
*  m = a positive modulus
* Returns: (b^x) % m
*/
BigInt powerMod()(auto const ref BigInt base, auto const ref BigInt exp, auto const ref BigInt mod)
{
    auto pow_mod = scoped!PowerMod(mod);

    /*
    * Calling setBase before setExponent means we end up using a
    * minimal window. This makes sense given that here we know that any
    * precomputation is wasted.
    */
    pow_mod.setBase(base);
    pow_mod.setExponent(exp);
    return pow_mod.execute();
}


/**
* Compute the square root of x modulo a prime using the
* Shanks-Tonnelli algorithm
*
* Params:
*  x = the input
*  p = the prime
* Returns: y such that (y*y)%p == x, or -1 if no such integer
*/

/*
* Shanks-Tonnelli algorithm
*/
BigInt ressol()(auto const ref BigInt a, auto const ref BigInt p)
{
    if (a < 0)
        throw new InvalidArgument("ressol(): a to solve for must be positive");
    if (p <= 1)
        throw new InvalidArgument("ressol(): prime must be > 1");
    
    if (a == 0)
        return BigInt(0);
    if (p == 2)
        return a.dup;
    
    if (jacobi(a, p) != 1) { // not a quadratic residue
        auto bi = -BigInt(1);
        return bi.move();
    }
    
    if (p % 4 == 3)
        return powerMod(a, ((p+1) >> 2), p);
    
    size_t s = lowZeroBits(p - 1);
    BigInt q = p >> s;
    
    q -= 1;
    q >>= 1;
    
    ModularReducer mod_p = ModularReducer(p);
    
    BigInt r = powerMod(a, q, p);
    BigInt n = mod_p.multiply(a, mod_p.square(r));
    r = mod_p.multiply(r, a);
    
    if (n == 1)
        return r.move();
    
    // find random non quadratic residue z
    BigInt z = 2;
    while (jacobi(z, p) == 1) // while z quadratic residue
        ++z;
    
    BigInt c = powerMod(z, (q << 1) + 1, p);
    
    while (n > 1)
    {
        q = n.dup();
        
        size_t i = 0;
        while (q != 1)
        {
            q = mod_p.square(q);
            ++i;
        }
        
        if (s <= i) {
            auto bi = -BigInt(1);
            return bi.move();
        }
        c = powerMod(c, BigInt.powerOf2(s-i-1), p);
        r = mod_p.multiply(r, c);
        c = mod_p.square(c);
        n = mod_p.multiply(n, c);
        s = i;
    }
    
    return r.move();
}

/*
* Compute -input^-1 mod 2^MP_WORD_BITS. Returns zero if input
* is even. If input is odd, input and 2^n are relatively prime
* and an inverse exists.
*/
word montyInverse(word input)
{
    word b = input;
    word x2 = 1, x1 = 0, y2 = 0, y1 = 1;
    
    // First iteration, a = n+1
    word q = bigint_divop(1, 0, b);
    word r = (MP_WORD_MAX - q*b) + 1;
    word x = x2 - q*x1;
    word y = y2 - q*y1;
    
    word a = b;
    b = r;
    x2 = x1;
    x1 = x;
    y2 = y1;
    y1 = y;
    
    while (b > 0)
    {
        q = a / b;
        r = a - q*b;
        x = x2 - q*x1;
        y = y2 - q*y1;
        
        a = b;
        b = r;
        x2 = x1;
        x1 = x;
        y2 = y1;
        y1 = y;
    }
    
    // Now invert in addition space
    y2 = (MP_WORD_MAX - y2) + 1;
    
    return y2;
}

/**
* Params:
*  x = a positive integer
* Returns: count of the zero bits in x, or, equivalently, the largest
*            value of n such that 2^n divides x evenly. Returns zero if
*            n is less than or equal to zero.
*/
size_t lowZeroBits()(auto const ref BigInt n)
{
    size_t low_zero = 0;
    
    if (n.isPositive() && n.isNonzero())
    {
        for (size_t i = 0; i != n.length; ++i)
        {
            const word x = n.wordAt(i);
            
            if (x)
            {
                low_zero += ctz(x);
                break;
            }
            else
                low_zero += BOTAN_MP_WORD_BITS;
        }
    }
    
    return low_zero;
}

/**
* Check for primality using Miller-Rabin
* Params:
*  n = a positive integer to test for primality
*  rng = a random number generator
*  prob = chance of false positive is bounded by 1/2**prob
*  is_random = true if n was randomly chosen by us
* Returns: true if all primality tests passed, otherwise false
*/
bool isPrime()(auto const ref BigInt n, RandomNumberGenerator rng, size_t prob = 56, bool is_random = false)
{
    import std.range : assumeSorted, SortedRange, empty;
    if (n == 2)
        return true;
    if (n <= 1 || n.isEven())
        return false;
    
    // Fast path testing for small numbers (<= 65521)
    if (n <= PRIMES[PRIME_TABLE_SIZE-1])
    {
        const ushort num = cast(ushort) n.wordAt(0);
        auto r = assumeSorted(PRIMES[0..$]);
        return !r.equalRange(num).empty;
    }

    const size_t test_iterations = mrTestIterations(n.bits(), prob, is_random);
    const BigInt n_minus_1 = n - 1;
    const size_t s = lowZeroBits(n_minus_1);
    FixedExponentPowerMod pow_mod = FixedExponentPowerMod(n_minus_1 >> s, n);
    ModularReducer reducer = ModularReducer(n);
    
    foreach (size_t i; 0 .. test_iterations)
    {
        auto bi = BigInt(2);
        const BigInt a = BigInt.randomInteger(rng, bi, n_minus_1);
        BigInt y = (*pow_mod)(a);
        if (mrWitness(y, reducer, n_minus_1, s))
            return false;
    }
    
    return true;
}

bool quickCheckPrime(const ref BigInt n, RandomNumberGenerator rng)
{ return isPrime(n, rng, 32); }

bool checkPrime(const ref BigInt n, RandomNumberGenerator rng)
{ return isPrime(n, rng, 56); }

bool verifyPrime(const ref BigInt n, RandomNumberGenerator rng)
{ return isPrime(n, rng, 80); }

/**
* Randomly generate a prime
* Params:
*  rng = a random number generator
*  bits = how large the resulting prime should be in bits
*  coprime = a positive integer the result should be coprime to
*  equiv = a non-negative number that the result should be
                    equivalent to modulo equiv_mod
*  equiv_mod = the modulus equiv should be checked against
* Returns: random prime with the specified criteria
*/
BigInt randomPrime()(RandomNumberGenerator rng,
                     size_t bits, const ref BigInt coprime,
                     size_t equiv = 1, size_t modulo = 2)
{
    if (bits <= 1)
        throw new InvalidArgument("randomPrime: Can't make a prime of " ~ to!string(bits) ~ " bits");
    else if (bits == 2)
        return ((rng.nextByte() % 2) ? BigInt(2) : BigInt(3));
    else if (bits == 3)
        return ((rng.nextByte() % 2) ? BigInt(5) : BigInt(7));
    else if (bits == 4)
        return ((rng.nextByte() % 2) ? BigInt(11) : BigInt(13));
    
    if (coprime <= 0)
        throw new InvalidArgument("randomPrime: coprime must be > 0");
    if (modulo % 2 == 1 || modulo == 0)
        throw new InvalidArgument("randomPrime: Invalid modulo value");
    if (equiv >= modulo || equiv % 2 == 0)
        throw new InvalidArgument("randomPrime: equiv must be < modulo, and odd");
    
    while (true)
    {
        BigInt p = BigInt(rng, bits);
        
        // Force lowest and two top bits on
        p.setBit(bits - 1);
        p.setBit(bits - 2);
        p.setBit(0);
        
        if (p % modulo != equiv)
            p += (modulo - p % modulo) + equiv;
        
        const size_t sieve_size = std.algorithm.min(bits / 2, PRIME_TABLE_SIZE);
        SecureVector!ushort sieve = SecureVector!ushort(sieve_size);
        
        for (size_t j = 0; j != sieve.length; ++j)
            sieve[j] = cast(ushort)( p % PRIMES[j]);
        
        size_t counter = 0;
        while (true)
        {
            if (counter == 4096 || p.bits() > bits)
                break;
            
            bool passes_sieve = true;
            ++counter;
            p += modulo;
            
            if (p.bits() > bits)
                break;
            
            for (size_t j = 0; j != sieve.length; ++j)
            {
                sieve[j] = cast(ushort)((sieve[j] + modulo) % PRIMES[j]);
                if (sieve[j] == 0)
                    passes_sieve = false;
            }
            
            if (!passes_sieve || gcd(p - 1, coprime) != 1)
                continue;
            if (isPrime(p, rng, 64, true))
                return p.move;
        }
    }
}

/// ditto
BigInt randomPrime()(RandomNumberGenerator rng,
    size_t bits, const BigInt coprime = 1,
    size_t equiv = 1, size_t modulo = 2)
{
    return randomPrime(rng, bits, coprime, equiv, modulo);
}

/**
* Return a random 'safe' prime, of the form p=2*q+1 with q prime
* Params:
*  rng = a random number generator
*  bits = is how long the resulting prime should be
* Returns: prime randomly chosen from safe primes of length bits
*/
BigInt randomSafePrime(RandomNumberGenerator rng, size_t bits)
{
    if (bits <= 64)
        throw new InvalidArgument("randomSafePrime: Can't make a prime of " ~ to!string(bits) ~ " bits");
    
    BigInt p;
    do
        p = (randomPrime(rng, bits - 1) << 1) + 1;
    while (!isPrime(p, rng, 64, true));
    return p;
}

/**
* Generate DSA parameters using the FIPS 186 kosherizer
* Params:
*  rng = a random number generator
*  af = an algorithm factory
*  p_out = where the prime p will be stored
*  q_out = where the prime q will be stored
*  pbits = how long p will be in bits
*  qbits = how long q will be in bits
* Returns: random seed used to generate this parameter set
*/
Vector!ubyte generateDsaPrimes(RandomNumberGenerator rng,
                               AlgorithmFactory af,
                               ref BigInt p_out, ref BigInt q_out,
                               size_t pbits, size_t qbits)
{
    while (true)
    {
        Vector!ubyte seed = Vector!ubyte(qbits / 8);
        rng.randomize(seed.ptr, seed.length);
        
        if (generateDsaPrimes(rng, af, p_out, q_out, pbits, qbits, seed))
            return seed;
    }
}


/**
* Generate DSA parameters using the FIPS 186 kosherizer
* Params:
*  rng = a random number generator
*  af = an algorithm factory
*  p_out = where the prime p will be stored
*  q_out = where the prime q will be stored
*  pbits = how long p will be in bits
*  qbits = how long q will be in bits
*  seed_c = the seed used to generate the parameters
* Returns: true if seed generated a valid DSA parameter set, otherwise
             false. p_out and q_out are only valid if true was returned.
*/
bool generateDsaPrimes()(RandomNumberGenerator rng,
                         AlgorithmFactory af,
                         ref BigInt p_out, ref BigInt q_out,
                         size_t pbits, size_t qbits,
                         auto const ref Vector!ubyte seed_c)
{
    if (!fips1863ValidSize(pbits, qbits))
        throw new InvalidArgument(
            "FIPS 186-3 does not allow DSA domain parameters of " ~ to!string(pbits) ~ "/" ~ to!string(qbits) ~ " bits long");
    
    if (seed_c.length * 8 < qbits)
        throw new InvalidArgument("Generating a DSA parameter set with a " ~ to!string(qbits) ~ 
                                   "long q requires a seed at least as many bits long");
    
    Unique!HashFunction hash = af.makeHashFunction("SHA-" ~ to!string(qbits));
    
    const size_t HASH_SIZE = hash.outputLength;
    
    struct Seed
    {
    public:
        this()(auto const ref Vector!ubyte s) { m_seed = s.dup(); }
        
        ref T opCast(T : Vector!ubyte)() { return m_seed; }
        
        alias m_seed this;
        
        ref Seed opUnary(string op)()
            if (op == "++")
        {
            for (size_t j = m_seed.length; j > 0; --j)
                if (++m_seed[j-1])
                    break;
            return this;
        }
    private:
        Vector!ubyte m_seed;
    }
    
    Seed seed = Seed(seed_c);
    
    q_out.binaryDecode(hash.process(seed));
    q_out.setBit(qbits-1);
    q_out.setBit(0);
    
    if (!isPrime(q_out, rng))
        return false;
    
    const size_t n = (pbits-1) / (HASH_SIZE * 8), b = (pbits-1) % (HASH_SIZE * 8);
    
    BigInt X;
    Vector!ubyte V = Vector!ubyte(HASH_SIZE * (n+1));
    
    foreach (size_t j; 0 .. 4096)
    {
        for (size_t k = 0; k <= n; ++k)
        {
            ++seed;
            hash.update(seed);
            hash.flushInto(&V[HASH_SIZE * (n-k)]);
        }
        
        X.binaryDecode(&V[HASH_SIZE - 1 - b/8], V.length - (HASH_SIZE - 1 - b/8));
        X.setBit(pbits-1);
        
        p_out = X - (X % (q_out*2) - 1);
        
        if (p_out.bits() == pbits && isPrime(p_out, rng))
            return true;
    }
    return false;
}

/*
* Check if this size is allowed by FIPS 186-3
*/
bool fips1863ValidSize(size_t pbits, size_t qbits)
{
    if (qbits == 160)
        return (pbits == 512 || pbits == 768 || pbits == 1024);
    
    if (qbits == 224)
        return (pbits == 2048);
    
    if (qbits == 256)
        return (pbits == 2048 || pbits == 3072);
    
    return false;
}

/*
* If the modulus is odd, then we can avoid computing A and C. This is
* a critical path algorithm in some instances and an odd modulus is
* the common case for crypto, so worth special casing. See note 14.64
* in Handbook of Applied Cryptography for more details.
*/
BigInt inverseModOddModulus(const ref BigInt n, const ref BigInt mod)
{
    BigInt u = mod.dup;
    BigInt v = n.dup;
    BigInt B = 0;
    BigInt D = 1;
    
    while (u.isNonzero())
    {
        const size_t u_zero_bits = lowZeroBits(u);
        u >>= u_zero_bits;
        foreach (size_t i; 0 .. u_zero_bits)
        {
            if (B.isOdd())
            { B -= mod; }
            B >>= 1;
        }
        
        const size_t v_zero_bits = lowZeroBits(v);
        v >>= v_zero_bits;
        foreach (size_t i; 0 .. v_zero_bits)
        {
            if (D.isOdd())
            { D -= mod; }
            D >>= 1;
        }
        
        if (u >= v) { u -= v; B -= D; }
        else        { v -= u; D -= B; }
    }
    
    if (v != 1)
        return BigInt(0); // no modular inverse
    
    while (D.isNegative()) D += mod;
    while (D >= mod) D -= mod;
    
    return D.move();
}

bool mrWitness(T : ModularReducer)(ref BigInt y,
                                   auto ref T reducer_n,
                                   const ref BigInt n_minus_1, size_t s)
{
    if (y == 1 || y == n_minus_1)
        return false;
    
    foreach (size_t i; 1 .. s)
    {
        y = reducer_n.square(y);
        
        if (y == 1) // found a non-trivial square root
            return true;
        if (y == n_minus_1) // -1, trivial square root, so give up
            return false;
    }
    
    return true; // fails Fermat test
}

size_t mrTestIterations(size_t n_bits, size_t prob, bool random)
{
    const size_t base = (prob + 2) / 2; // worst case 4^-t error rate
    
    /*
    * For randomly chosen numbers we can use the estimates from
    * http://www.math.dartmouth.edu/~carlp/PDF/paper88.pdf‎
    *
    * These values are derived from the inequality for p(k,t) given on
    * the second page.
    */
    if (random && prob <= 80)
    {
        if (n_bits >= 1536)
            return 2; // < 2^-89
        if (n_bits >= 1024)
            return 4; // < 2^-89
        if (n_bits >= 512)
            return 5; // < 2^-80
        if (n_bits >= 256)
            return 11; // < 2^-80
    }
    
    return base;
}
