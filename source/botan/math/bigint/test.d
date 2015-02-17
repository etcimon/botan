/**
* Unit test helper
* 
* Copyright:
* (C) 2014-2015 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
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
size_t results()(string op, auto const ref BigInt a, auto const ref BigInt b, auto const ref BigInt c, 
                 auto const ref BigInt d, auto const ref BigInt e)
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
    BigInt e = a.dup;

    e += b;
    
    if (results("+", a, b, c, d, e))
        return 1;
    
    d = b + a;
    e = b.dup;
    e += a;
    
    return results("+", a, b, c, d, e);
}

size_t checkSub(const ref Vector!string args)
{
    BigInt a = BigInt(args[0]);
    BigInt b = BigInt(args[1]);
    BigInt c = BigInt(args[2]);
    
    BigInt d = a - b;
    BigInt e = a.dup;
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
    BigInt e = a.dup;
    e *= b;
    
    if (results("*", a, b, c, d, e))
        return 1;
    
    d = b * a;
    e = b.dup;
    e *= a;
    
    return results("*", a, b, c, d, e);
}

size_t checkSqr(const ref Vector!string args)
{
    BigInt a = BigInt(args[0]);
    BigInt b = BigInt(args[1]);
    
    a.growTo(64);
    b.growTo(64);
    
    BigInt c = square(a);
    BigInt d = a * a;
    
    return results("sqr", a, a, b, c, d);
}

size_t checkDiv(const ref Vector!string args)
{
    BigInt a = BigInt(args[0]);
    BigInt b = BigInt(args[1]);
    BigInt c = BigInt(args[2]);
    
    BigInt d = a / b;
    BigInt e = a.dup;
    e /= b;
    
    return results("/", a, b, c, d, e);
}

size_t checkMod(const ref Vector!string args, RandomNumberGenerator rng)
{
    BigInt a = BigInt(args[0]);
    BigInt b = BigInt(args[1]);
    BigInt c = BigInt(args[2]);
    
    BigInt d = a % b;
    BigInt e = a.dup;
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
    e = a.dup;
    e %= b_word;
    
    return results("%(word)", a, b, c, BigInt(d2), e);
}

size_t checkShl(const ref Vector!string args)
{
    BigInt a = BigInt(args[0]);
    size_t b = args[1].to!size_t;
    BigInt c = BigInt(args[2]);
    
    BigInt d = a << b;
    BigInt e = a.dup;
    e <<= b;
    
    return results("<<", a, BigInt(b), c, d, e);
}

size_t checkShr(const ref Vector!string args)
{
    BigInt a = BigInt(args[0]);
    size_t b = args[1].to!size_t;
    BigInt c = BigInt(args[2]);
    
    BigInt d = a >> b;
    BigInt e = a.dup;
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
    
    BigInt r = powerMod(a, b, m);
    
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
    
    bool isPrime = isPrime(n, rng);
    
    if (isPrime != should_be_prime)
    {
        logError("ERROR: isPrime");
        logDebug("n = ", n.toString());
        logDebug(isPrime, " != ", should_be_prime);
        return 1;
    }
    return 0;
}

static if (!SKIP_BIGINT_TEST) unittest
{
    import botan.libstate.global_state;
    auto state = globalState(); // ensure initialized

    import std.stdio : writeln;
    logDebug("Testing bigint/test.d ...");
    import std.array;
    const string filename = "../test_data/mp_valid.dat";
    File test_data = File(filename, "r");
    
    if (test_data.error || test_data.eof)
        throw new StreamIOError("Couldn't open test file " ~ filename);
    
    size_t total_errors = 0;
    size_t errors = 0, alg_count = 0;
    size_t total_alg;
    string algorithm;
    bool first = true;
    size_t counter = 0;
    
    auto rng = AutoSeededRNG();
    
    while(!test_data.eof)
    {
        if (test_data.error)
            throw new StreamIOError("File I/O error reading from " ~ filename);
        string line_data = test_data.readln();
        if (!line_data) break;
        Vector!ubyte line = Vector!ubyte(line_data[0 .. $-1].strip());
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
                if (!line_data) break;
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
            new_errors = checkMod(substr, rng);
        else if (algorithm.canFind("LeftShift"))
            new_errors = checkShl(substr);
        else if (algorithm.canFind("RightShift"))
            new_errors = checkShr(substr);
        else if (algorithm.canFind("ModExp"))
            new_errors = checkPowmod(substr);
        else if (algorithm.canFind("PrimeTest"))
            new_errors = isPrimeTest(substr, rng);
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
}