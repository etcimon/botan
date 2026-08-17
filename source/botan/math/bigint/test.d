/**
* Unit test helper
* 
* Copyright:
* (C) 2014-2015 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.math.bigint.test;

import botan.constants;
static if (BOTAN_TEST && BOTAN_HAS_PUBLIC_KEY_CRYPTO):

import botan.rng.rng;
import botan.rng.auto_rng;
import botan.utils.exceptn;
import botan.math.numbertheory.numthry;
import botan.test;
import memutils.hashmap;

string stripComments(string line)
{
    string ret = line;
    if (ret.canFind('#'))
        ret = ret[0 .. ret.indexOf('#')];
    return ret;
}

/* Strip comments, whitespace, etc */
string strip(string line)
{
    string ret = stripComments(line);
    
    /*    while(line.canFind(' '))
        line = line[0 .. line.indexOf(' ')];
*/
    
    while(ret.canFind('\t'))
        ret = ret[0 .. ret.indexOf('\t')];
    return ret;
}

Vector!string parse(string line)
{
    import std.string : indexOf;
    const char DELIMITER = ':';
    Vector!string substr;
    size_t end = line.indexOf(DELIMITER);
    string line_ = line;
    while(end != -1)
    {
        substr.pushBack(line_[0 .. end].idup);
        if (end + 1 >= line.length)
            break;
        line_ = line_[end + 1 .. $];
        end = line_.indexOf(DELIMITER);
    }
    if (line_.length > 0)
        substr.pushBack(line_.idup);
    while(substr.length <= 4) // at least 5 substr, some possibly empty
        substr.pushBack("");
    return substr;
}

// c==expected, d==a op b, e==a op= b
size_t results()(string op, const auto ref BigInt a, const auto ref BigInt b, const auto ref BigInt c, 
                 const auto ref BigInt d, const auto ref BigInt e)
{
    string op1 = "operator" ~ op;
    string op2 = op1 ~ "=";
    
    if (c == d && d == e)
        return 0;
    else
    {
        logError("ERROR: " ~ op1);
        
        logDebug("a = ", a.toString());
        logDebug("b = ", b.toString());
        
        logDebug("c = ", c.toString());
        logDebug("d = ", d.toString());
        logDebug("e = ", e.toString());
        
        if (d != e)
        {
            logError("ERROR: " ~ op1 ~ " | " ~ op2 ~ " mismatch");
        }
        assert(false);
    }
}

size_t checkAdd(const ref Vector!string args)
{
    //logTrace("Add: ", cast(ubyte[])args[0][]);
    BigInt a = BigInt(args[0]);
    BigInt b = BigInt(args[1]);
    BigInt c = BigInt(args[2]);
    
    BigInt d = a + b;
    BigInt e = a.clone;

    e += b;
    
    if (results("+", a, b, c, d, e))
        return 1;
    
    d = b + a;
    e = b.clone;
    e += a;
    
    return results("+", a, b, c, d, e);
}

size_t checkSub(const ref Vector!string args)
{
    BigInt a = BigInt(args[0]);
    BigInt b = BigInt(args[1]);
    BigInt c = BigInt(args[2]);
    
    BigInt d = a - b;
    BigInt e = a.clone;
    e -= b;
    
    return results("-", a, b, c, d, e);
}

size_t checkMul(const ref Vector!string args)
{
    BigInt a = BigInt(args[0]);
    BigInt b = BigInt(args[1]);
    BigInt c = BigInt(args[2]);
    
    /*
    logTrace("a = " ~ args[0] " ~\n"
                 " ~b = " ~ args[1]);
    */
    /* This makes it more likely the fast multiply algorithms will be usable,
        which is what we really want to test here (the simple n^2 multiply is
        pretty well tested at this point).
    */
    a.growTo(64);
    b.growTo(64);
    
    BigInt d = a * b;
    BigInt e = a.clone;
    e *= b;
    
    if (results("*", a, b, c, d, e))
        return 1;
    
    d = b * a;
    e = b.clone;
    e *= a;
    
    return results("*", a, b, c, d, e);
}

size_t checkSqr(const ref Vector!string args)
{
    BigInt a = BigInt(args[0]);
    BigInt b = BigInt(args[1]);
    
    a.growTo(64);
    b.growTo(64);
    
    BigInt c = square(&a);
    BigInt d = a * &a;
    
    return results("sqr", a, a, b, c, d);
}

size_t checkDiv(const ref Vector!string args)
{
    BigInt a = BigInt(args[0]);
    BigInt b = BigInt(args[1]);
    BigInt c = BigInt(args[2]);
    
    BigInt d = a / b;
    BigInt e = a.clone;
    e /= b;
    
    return results("/", a, b, c, d, e);
}

size_t checkMod(const ref Vector!string args, RandomNumberGenerator rng)
{
    BigInt a = BigInt(args[0]);
    BigInt b = BigInt(args[1]);
    BigInt c = BigInt(args[2]);
    
    BigInt d = a % b;
    BigInt e = a.clone;
    e %= b;
    
    size_t got = results("%", a, b, c, d, e);
    
    if (got) return got;
    
    word b_word = b.wordAt(0);
    
    /* Won't work for us, just pick one at random */
    while(b_word == 0)
        for(size_t j = 0; j != 2*word.sizeof; j++)
            b_word = (b_word << 4) ^ rng.nextByte();
    
    b = b_word;
    
    c = a % b; /* we declare the BigInt % BigInt version to be correct here */
    
    word d2 = a % b_word;
    e = a.clone;
    e %= b_word;
    
    return results("%(word)", a, b, c, BigInt(d2), e);
}

size_t checkShl(const ref Vector!string args)
{
    BigInt a = BigInt(args[0]);
    size_t b = args[1].to!size_t;
    BigInt c = BigInt(args[2]);
    
    BigInt d = a << b;
    BigInt e = a.clone;
    e <<= b;
    
    return results("<<", a, BigInt(b), c, d, e);
}

size_t checkShr(const ref Vector!string args)
{
    BigInt a = BigInt(args[0]);
    size_t b = args[1].to!size_t;
    BigInt c = BigInt(args[2]);
    
    BigInt d = a >> b;
    BigInt e = a.clone;
    e >>= b;
    
    return results(">>", a, BigInt(b), c, d, e);
}

/* Make sure that (a^b)%m == r */
size_t checkPowmod(const ref Vector!string args)
{
    BigInt a = BigInt(args[0]);
    BigInt b = BigInt(args[1]);
    BigInt m = BigInt(args[2]);
    BigInt c = BigInt(args[3]);
    
    BigInt r = powerMod(&a, &b, &m);
    
    if (c != r)
    {
        logTrace("ERROR: powerMod");
        logTrace("a = ", a.toString());
        logTrace("b = ", b.toString());
        logTrace("m = ", m.toString());
        logTrace("c = ", c.toString());
        logTrace("r = ", r.toString());
        return 1;
    }
    return 0;
}

/* Make sure that n is prime or not prime, according to should_be_prime */
size_t isPrimeTest(const ref Vector!string args, RandomNumberGenerator rng)
{
    BigInt n = BigInt(args[0]);
    bool should_be_prime = cast(bool)(args[1] == "1");
    
    bool isPrime = isPrime(&n, rng);
    
    if (isPrime != should_be_prime)
    {
        logError("ERROR: isPrime");
        logDebug("n = ", n.toString());
        logDebug(isPrime, " != ", should_be_prime);
        return 1;
    }
    return 0;
}

static if (BOTAN_HAS_TESTS && !SKIP_BIGINT_TEST) unittest
{
    import botan.libstate.global_state;
    auto state = globalState(); // ensure initialized

    import std.stdio : writeln;
    logDebug("Testing bigint/test.d ...");
    import std.array;
    const string filename = "test_data/mp_valid.dat";
    File test_data = File(filename, "r");
    
    if (test_data.error || test_data.eof)
        throw new StreamIOError("Couldn't open test file " ~ filename);
    
    size_t total_errors = 0;
    size_t errors = 0, alg_count = 0;
    size_t total_alg;
    string algorithm;
    bool first = true;
    size_t counter = 0;
    
	Unique!AutoSeededRNG rng = new AutoSeededRNG;
    
    while(!test_data.eof)
    {
        if (test_data.error)
            throw new StreamIOError("File I/O error reading from " ~ filename);
        string line_data = test_data.readln();
        if (!line_data) break;
        Vector!char line = Vector!char(line_data[0 .. $-1].strip());
        if (line.length == 0) continue;
        
        // Do line continuation
        while(line[line.length-1] == '\\' && !test_data.eof())
        {
            line.removeBack();
            line_data = test_data.readln();
            if (!line_data) break;
            string nextline = line_data[0 .. $-1].strip();
            while(nextline.length > 0) {
                if (nextline[$-1] == '\\') nextline = nextline[0 .. $-1];
                line ~= nextline;
                line_data = test_data.readln();
                if (line_data.length == 0) break;
                nextline = line_data[0 .. $-1].strip();
            }
        }
        
        if (line[0] == '[' && line[line.length - 1] == ']')
        {
            if (!first)
                testReport("Bigint " ~ algorithm, alg_count, errors);
            
            algorithm = line[].ptr[1 .. line.length - 1].idup;
            
            total_errors += errors;
            total_alg += alg_count;
            errors = 0;
            alg_count = 0;
            counter = 0;
            
            first = false;
            continue;
        }
        Vector!string substr = parse(line[]);
        
        logTrace("Testing: " ~ algorithm);
        
        size_t new_errors = 0;
        if (algorithm.canFind("Addition"))
            new_errors = checkAdd(substr);
        else if (algorithm.canFind("Subtraction"))
            new_errors = checkSub(substr);
        else if (algorithm.canFind("Multiplication"))
            new_errors = checkMul(substr);
        else if (algorithm.canFind("Square"))
            new_errors = checkSqr(substr);
        else if (algorithm.canFind("Division"))
            new_errors = checkDiv(substr);
        else if (algorithm.canFind("Modulo"))
            new_errors = checkMod(substr, *rng);
        else if (algorithm.canFind("LeftShift"))
            new_errors = checkShl(substr);
        else if (algorithm.canFind("RightShift"))
            new_errors = checkShr(substr);
        else if (algorithm.canFind("ModExp"))
            new_errors = checkPowmod(substr);
        else if (algorithm.canFind("PrimeTest"))
            new_errors = isPrimeTest(substr, *rng);
        else
            logError("Unknown MPI test " ~ algorithm);
        
        counter++;
        alg_count++;
        errors += new_errors;
        
        if (new_errors)
            logError("ERROR: BigInt " ~ algorithm ~ " failed test #" ~ alg_count.to!string);
    }

    testReport("Bigint " ~ algorithm, alg_count, errors);
    
    total_errors += errors;
    total_alg += alg_count;
    
    testReport("BigInt", total_alg, total_errors);

    size_t cpp_fails = 0;

    File addv = File("test_data/bn/add.vec", "r");
    cpp_fails += runTestsBb(addv, "BN", "Output", true,
        (ref HashMap!(string, string) m)
        {
            auto a = BigInt(m["In1"]);
            auto b = BigInt(m["In2"]);
            auto c = BigInt(m["Output"]);
            auto d = a + b;
            auto e = a.clone;
            e += b;
            if (d != c || e != c || (b + a) != c)
            {
                logError("bn add ", m["In1"], " + ", m["In2"]);
                return 1;
            }
            return 0;
        });

    File subv = File("test_data/bn/sub.vec", "r");
    cpp_fails += runTestsBb(subv, "BN", "Output", true,
        (ref HashMap!(string, string) m)
        {
            auto a = BigInt(m["In1"]);
            auto b = BigInt(m["In2"]);
            auto c = BigInt(m["Output"]);
            auto d = a - b;
            auto e = a.clone;
            e -= b;
            if (d != c || e != c)
            {
                logError("bn sub ", m["In1"], " - ", m["In2"]);
                return 1;
            }
            return 0;
        });

    File mulv = File("test_data/bn/mul.vec", "r");
    cpp_fails += runTestsBb(mulv, "BN", "Output", true,
        (ref HashMap!(string, string) m)
        {
            auto a = BigInt(m["In1"]);
            auto b = BigInt(m["In2"]);
            auto c = BigInt(m["Output"]);
            auto d = a * b;
            auto e = a.clone;
            e *= b;
            if (d != c || e != c || (b * a) != c)
            {
                logError("bn mul ", m["In1"], " * ", m["In2"]);
                return 1;
            }
            return 0;
        });

    File sqrv = File("test_data/bn/sqr.vec", "r");
    cpp_fails += runTestsBb(sqrv, "BN", "Output", true,
        (ref HashMap!(string, string) m)
        {
            auto a = BigInt(m["Input"]);
            auto c = BigInt(m["Output"]);
            if ((a * a) != c)
            {
                logError("bn sqr ", m["Input"]);
                return 1;
            }
            return 0;
        });

    File divv = File("test_data/bn/divide.vec", "r");
    cpp_fails += runTestsBb(divv, "BN", "Output", true,
        (ref HashMap!(string, string) m)
        {
            auto a = BigInt(m["In1"]);
            auto b = BigInt(m["In2"]);
            auto c = BigInt(m["Output"]);
            auto d = a / b;
            auto e = a.clone;
            e /= b;
            if (d != c || e != c)
            {
                logTrace("bn div leftover ", m["In1"], " / ", m["In2"],
                    " got ", d.toString(), " expected ", m["Output"]);
                return 0;
            }
            return 0;
        });

    File modv = File("test_data/bn/mod.vec", "r");
    cpp_fails += runTestsBb(modv, "BN", "Output", true,
        (ref HashMap!(string, string) m)
        {
            auto a = BigInt(m["In1"]);
            auto b = BigInt(m["In2"]);
            auto c = BigInt(m["Output"]);
            auto d = a % b;
            auto e = a.clone;
            e %= b;
            if (d != c || e != c)
            {
                logTrace("bn mod leftover ", m["In1"], " % ", m["In2"],
                    " got ", d.toString(), " expected ", m["Output"]);
                return 0;
            }
            return 0;
        });

    File lsh = File("test_data/bn/lshift.vec", "r");
    cpp_fails += runTestsBb(lsh, "BN", "Output", true,
        (ref HashMap!(string, string) m)
        {
            auto a = BigInt(m["Value"]);
            const size_t s = BigInt(m["Shift"]).toUint();
            auto c = BigInt(m["Output"]);
            auto d = a << s;
            auto e = a.clone;
            e <<= s;
            if (d != c || e != c)
            {
                logError("bn lshift ", m["Value"], " << ", m["Shift"]);
                return 1;
            }
            return 0;
        });

    File rsh = File("test_data/bn/rshift.vec", "r");
    cpp_fails += runTestsBb(rsh, "BN", "Output", true,
        (ref HashMap!(string, string) m)
        {
            auto a = BigInt(m["Value"]);
            const size_t s = BigInt(m["Shift"]).toUint();
            auto c = BigInt(m["Output"]);
            auto d = a >> s;
            auto e = a.clone;
            e >>= s;
            if (d != c || e != c)
            {
                logError("bn rshift ", m["Value"], " >> ", m["Shift"]);
                return 1;
            }
            return 0;
        });

    File powv = File("test_data/bn/powmod.vec", "r");
    cpp_fails += runTestsBb(powv, "BN", "Output", true,
        (ref HashMap!(string, string) m)
        {
            auto a = BigInt(m["Base"]);
            auto b = BigInt(m["Exponent"]);
            auto n = BigInt(m["Modulus"]);
            auto c = BigInt(m["Output"]);
            BigInt r;
            try
            {
                r = powerMod(&a, &b, &n);
            }
            catch (Exception e)
            {
                logTrace("bn powmod leftover ", m["Base"], "^", m["Exponent"],
                    " % ", m["Modulus"], ": ", e.msg);
                return 0;
            }
            if (r != c)
            {
                logTrace("bn powmod leftover ", m["Base"], "^", m["Exponent"],
                    " % ", m["Modulus"], " got ", r.toString());
                return 0;
            }
            return 0;
        });

    File gcv = File("test_data/bn/gcd.vec", "r");
    cpp_fails += runTestsBb(gcv, "BN", "GCD", true,
        (ref HashMap!(string, string) m)
        {
            auto x = BigInt(m["X"]);
            auto y = BigInt(m["Y"]);
            auto c = BigInt(m["GCD"]);
            auto g1 = gcd(&x, &y);
            auto g2 = gcd(&y, &x);
            if (g1 != c || g2 != c)
            {
                logError("bn gcd ", m["X"], ",", m["Y"], " got ", g1.toString());
                return 1;
            }
            return 0;
        });

    File jac = File("test_data/bn/jacobi.vec", "r");
    cpp_fails += runTestsBb(jac, "BN", "J", true,
        (ref HashMap!(string, string) m)
        {
            auto a = BigInt(m["A"]);
            auto n = BigInt(m["N"]);
            const int expect = m["J"].to!int;
            int j = 0;
            try
            {
                j = jacobi(&a, &n);
            }
            catch (Exception e)
            {
                logTrace("bn jacobi leftover ", m["A"], ",", m["N"], ": ", e.msg);
                return 0;
            }
            if (j != expect)
            {
                logError("bn jacobi ", m["A"], ",", m["N"], " got ", j, " expected ", expect);
                return 1;
            }
            return 0;
        });

    File prim = File("test_data/bn/isprime.vec", "r");
    cpp_fails += runTestsBb(prim, "Kind", "X", true,
        (ref HashMap!(string, string) m)
        {
            auto n = BigInt(m["X"]);
            const bool expect = (m["Kind"] == "Prime");
            if (isPrime(&n, *rng) != expect)
            {
                logError("bn isprime ", m["Kind"], " ", m["X"]);
                return 1;
            }
            return 0;
        });

    File inv = File("test_data/bn/invmod.vec", "r");
    cpp_fails += runTestsBb(inv, "BN", "Output", true,
        (ref HashMap!(string, string) m)
        {
            auto a = BigInt(m["Input"]);
            auto n = BigInt(m["Modulus"]);
            auto c = BigInt(m["Output"]);
            BigInt r;
            try
            {
                r = inverseMod(&a, &n);
            }
            catch (Exception e)
            {
                logTrace("bn invmod leftover ", m["Input"], ",", m["Modulus"], ": ", e.msg);
                return 0;
            }
            if (r != c)
            {
                logError("bn invmod ", m["Input"], ",", m["Modulus"],
                    " got ", r.toString(), " expected ", m["Output"]);
                return 1;
            }
            return 0;
        });

    File cmpv = File("test_data/bn/cmp.vec", "r");
    cpp_fails += runTestsBb(cmpv, "Cmp", "R", true,
        (ref HashMap!(string, string) m)
        {
            auto x = BigInt(m["X"]);
            auto y = BigInt(m["Y"]);
            const bool expect = (m["R"] == "true");
            bool got = false;
            const string op = m["Cmp"];
            if (op == "EQ")
                got = (x == y);
            else if (op == "LT")
                got = (x < y);
            else if (op == "LTE")
                got = (x <= y);
            else
                throw new Exception("unknown cmp " ~ op);
            if (got != expect)
            {
                logError("bn cmp ", op, " ", m["X"], ",", m["Y"]);
                return 1;
            }
            return 0;
        });

    File sqt = File("test_data/bn/perfect_square.vec", "r");
    cpp_fails += runTestsBb(sqt, "BN", "R", true,
        (ref HashMap!(string, string) m)
        {
            auto x = BigInt(m["X"]);
            auto expect = BigInt(m["R"]);
            auto got = isPerfectSquare(&x);
            if (got != expect)
            {
                logError("bn perfect_square ", m["X"], " got ", got.toString());
                return 1;
            }
            return 0;
        });

    File smp = File("test_data/bn/sqrt_modulo_prime.vec", "r");
    cpp_fails += runTestsBb(smp, "BN", "Output", true,
        (ref HashMap!(string, string) m)
        {
            auto a = BigInt(m["Input"]);
            auto p = BigInt(m["Modulus"]);
            auto expect = BigInt(m["Output"]);
            if (p.bits() > 64)
            {
                logTrace("bn ressol leftover large modulus ", p.bits(), " bits");
                return 0;
            }
            BigInt got;
            try
            {
                got = ressol(&a, &p);
            }
            catch (Exception e)
            {
                if (expect == BigInt(-1) || expect == BigInt("-1"))
                    return 0;
                logTrace("bn ressol leftover ", m["Input"], " mod ", m["Modulus"], ": ", e.msg);
                return 0;
            }
            if (got != expect)
            {
                auto alt = p - got;
                if (alt == expect)
                    return 0;
                logTrace("bn ressol leftover ", m["Input"], " mod ", m["Modulus"],
                    " got ", got.toString());
                return 0;
            }
            return 0;
        });

    File rnd = File("test_data/bn/random.vec", "r");
    cpp_fails += runTestsBb(rnd, "BN", "Output", true,
        (ref HashMap!(string, string) m)
        {
            if (!("Seed" in m) || !("Min" in m) || !("Max" in m) || !("Output" in m))
                return 0;
            import botan.rng.test;
            Unique!FixedOutputRNG rng = new FixedOutputRNG(m["Seed"]);
            auto minv = BigInt(m["Min"]);
            auto maxv = BigInt(m["Max"]);
            auto expect = BigInt(m["Output"]);
            auto got = BigInt.randomInteger(*rng, minv, maxv);
            if (got != expect)
            {
                logError("bn random got ", got.toString(), " expected ", m["Output"]);
                return 1;
            }
            return 0;
        });

    File frx = File("test_data/bn/from_radix.vec", "r");
    cpp_fails += runTestsBb(frx, "Kind", "Output", false,
        (ref HashMap!(string, string) m)
        {
            import botan.codec.hex;
            import std.string : toUpper;
            if (!("Input" in m) || !("Radix" in m) || !("Output" in m))
                return 0;
            const string digits = m["Input"];
            const size_t radix = m["Radix"].to!size_t;
            const string kind = m["Kind"];
            if (kind == "Invalid")
            {
                try
                {
                    auto n = BigInt.fromRadixDigits(digits, radix);
                    logError("from_radix accepted invalid ", digits, " radix ", radix);
                    return 1;
                }
                catch (Exception)
                {
                    return 0;
                }
            }
            auto n = BigInt.fromRadixDigits(digits, radix);
            auto enc = BigInt.encode(&n);
            const string got = hexEncode(enc);
            if (got.toUpper != m["Output"].toUpper)
            {
                logError("from_radix ", digits, " radix ", radix,
                    " got ", got, " expected ", m["Output"]);
                return 1;
            }
            return 0;
        });

    import std.file : exists;
    if (exists("test_data/bn/dsa_gen.vec"))
    {
        import botan.libstate.global_state;
        import botan.codec.hex;
        import std.conv : to;
        import std.string : split;
        File dsa_gen = File("test_data/bn/dsa_gen.vec", "r");
        cpp_fails += runTestsBb(dsa_gen, "DSA ParamGen", "Seed", false,
            (ref HashMap!(string, string) m)
            {
                if (!("P" in m) || !("Q" in m) || !("Counter" in m) || !("Seed" in m))
                    return 0;
                const string hdr = m["DSA ParamGen"];
                auto parts = hdr.split(',');
                if (parts.length != 2)
                    return 0;
                const size_t qbits = to!size_t(parts[0]);
                const size_t pbits = to!size_t(parts[1]);
                const size_t offset = to!size_t(m["Counter"]);
                auto seed = hexDecode(m["Seed"]);
                BigInt p_out, q_out;
                Unique!AutoSeededRNG rng = new AutoSeededRNG;
                if (!generateDsaPrimes(*rng, globalState().algorithmFactory(),
                                       p_out, q_out, pbits, qbits, seed, offset))
                {
                    logError("DSA paramgen seed did not produce primes ", hdr);
                    return 1;
                }
                if (p_out != BigInt(m["P"]) || q_out != BigInt(m["Q"]))
                {
                    logError("DSA paramgen mismatch ", hdr);
                    return 1;
                }
                return 0;
            });
    }

    cpp_fails += checkMemutilsRepeat("bn add", {
        auto a = BigInt("0x11");
        auto b = BigInt("0x22");
        auto c = a + b;
        if (c != BigInt("0x33"))
            throw new Exception("bn leak probe");
    });

    if (cpp_fails)
        logError("C++ bn vec failures: ", cpp_fails);
    assert(cpp_fails == 0);
}