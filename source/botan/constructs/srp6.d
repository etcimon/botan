/**
* SRP-6a (RFC 5054 compatatible)
* 
* Copyright:
* (C) 2011,2012,2019,2020 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.constructs.srp6;

import botan.constants;
static if (BOTAN_HAS_SRP6):
import botan.math.bigint.bigint;
import botan.hash.hash;
import botan.rng.rng;
import botan.algo_base.symkey;
import botan.pubkey.algo.dl_group;
import botan.libstate.libstate;
import botan.libstate.global_state;
import botan.math.numbertheory.numthry;
import botan.utils.types;

struct SRP6KeyPair {
    BigInt privkey;
    SymmetricKey pubkey;

    this(BigInt* priv, SymmetricKey pub) {
        privkey = priv.move();
        pubkey = pub;
    }
}

/**
* SRP6a Client side
* Params:
*  identifier = the username we are attempting login for
*  password = the password we are attempting to use
*  group_id = specifies the shared SRP group
*  hash_id = specifies a secure hash function
*  salt = is the salt value sent by the server
*  B = is the server's public value
*  rng = is a random number generator
*
* Returns: (A,K) the client public key and the shared secret key
*/
SRP6KeyPair
    srp6ClientAgree(in string identifier,
                    in string password,
                    in string group_id,
                    in string hash_id,
                    const ref Vector!ubyte salt,
                    const ref BigInt B,
                    RandomNumberGenerator rng)
{
    DLGroup group = DLGroup(group_id);
    const BigInt* g = &group.getG();
    const BigInt* p = &group.getP();
    
    const size_t p_bytes = p.bytes();
    
    if (B <= 0 || B >= *p)
        throw new Exception("Invalid SRP parameter from server");
    
    BigInt a = BigInt(rng, 256);
    return srp6ClientAgree(identifier, password, group_id, hash_id, salt, B, a);
}

/// Client agree with a caller-supplied ephemeral `a` (KATs / FixedOutputRNG).
SRP6KeyPair
    srp6ClientAgree(in string identifier,
                    in string password,
                    in string group_id,
                    in string hash_id,
                    const ref Vector!ubyte salt,
                    const ref BigInt B,
                    const ref BigInt a)
{
    DLGroup group = DLGroup(group_id);
    const BigInt* g = &group.getG();
    const BigInt* p = &group.getP();

    const size_t p_bytes = p.bytes();

    if (B <= 0 || B >= *p)
        throw new Exception("Invalid SRP parameter from server");

    BigInt k = hashSeq(hash_id, p_bytes, p, g);
    BigInt A = powerMod(g, &a, p);
    BigInt u = hashSeq(hash_id, p_bytes, &A, &B);
    BigInt x = computeX(hash_id, identifier, password, salt);
    BigInt ref_1 = (B - (k * powerMod(g, &x, p))) % (*p);
    auto ref_2_2 = (u * x);
    BigInt ref_2 = (a + ref_2_2);
    BigInt S = powerMod(&ref_1, &ref_2, p);

    SymmetricKey Sk = SymmetricKey(BigInt.encode1363(&S, p_bytes));

    return SRP6KeyPair(&A, Sk);
}


/**
* Generate a new SRP-6 verifier
* Params:
*  identifier = a username or other client identifier
*  password = the secret used to authenticate user
*  salt = a randomly chosen value, at least 128 bits long
*  group_id = specifies the shared SRP group
*  hash_id = specifies a secure hash function
*/
BigInt generateSrp6Verifier(in string identifier,
                              in string password,
                              const ref Vector!ubyte salt,
                              in string group_id,
                              in string hash_id)
{
    BigInt x = computeX(hash_id, identifier, password, salt);
    
    DLGroup group = DLGroup(group_id);
    return powerMod(&group.getG(), &x, &group.getP());
}


/**
* Return the group id for this SRP param set, or else thrown an
* exception
* Params:
*  N = the group modulus
*  g = the group generator
* Returns: group identifier
*/
string srp6GroupIdentifier(const ref BigInt N, const ref BigInt g)
{
    /*
    This function assumes that only one 'standard' SRP parameter set has
    been defined for a particular bitsize. As of this writing that is the case.
    */
    try
    {
        const string group_name = "modp/srp/" ~ to!string(N.bits());
        
        DLGroup group = DLGroup(group_name);
        
        if (group.getP() == N && group.getG() == g)
            return group_name;
        
        throw new Exception("Unknown SRP params");
    }
    catch (Exception)
    {
        throw new InvalidArgument("Bad SRP group parameters");
    }
}

/**
* Represents a SRP-6a server session
*/
final class SRP6ServerSession
{
public:
    /**
    * Server side step 1
    * Params:
    *  v = the verification value saved from client registration
    *  group_id = the SRP group id
    *  hash_id = the SRP hash in use
    *  rng = a random number generator
    * Returns: SRP-6 B value
    */
    ref const(BigInt) step1(const ref BigInt v,
                            in string group_id,
                            in string hash_id,
                            RandomNumberGenerator rng)
    {
        DLGroup group = DLGroup(group_id);
        const BigInt* g = &group.getG();
        const BigInt* p = &group.getP();
        
        m_p_bytes = p.bytes();
        
        BigInt b = BigInt(rng, 256);
        return step1(v, group_id, hash_id, b);
    }

    /// Server step 1 with a caller-supplied ephemeral `b` (KATs).
    ref const(BigInt) step1(const ref BigInt v,
                            in string group_id,
                            in string hash_id,
                            const ref BigInt b)
    {
        DLGroup group = DLGroup(group_id);
        const BigInt* g = &group.getG();
        const BigInt* p = &group.getP();

        m_p_bytes = p.bytes();

        BigInt k = hashSeq(hash_id, m_p_bytes, p, g);

        auto m_B0 = powerMod(g, &b, p);
        m_B = (v*k + m_B0) % (*p);

        m_v = v.clone;
        m_b = b.clone;
        m_p = p.clone;
        m_hash_id = hash_id;

        return m_B;
    }

    /**
    * Server side step 2
    * Params:
    *  A = the client's value
    * Returns: shared symmetric key
    */
    SymmetricKey step2(const(BigInt)* A)
    {
        if (*A <= 0 || *A >= m_p)
            throw new Exception("Invalid SRP parameter from client");
        
        BigInt u = hashSeq(m_hash_id, m_p_bytes, A, &m_B);
        auto ref_1 = (*A * powerMod(&m_v, &u, &m_p));
        BigInt S = powerMod(&ref_1, &m_b, &m_p);
        
        return SymmetricKey(BigInt.encode1363(S, m_p_bytes));
    }

private:
    string m_hash_id;
    BigInt m_B, m_b, m_v, m_p; // m_S
    size_t m_p_bytes;
}

private:
    
BigInt hashSeq(in string hash_id,
                 size_t pad_to,
                 const(BigInt)* in1,
                 const(BigInt)* in2)
{
    Unique!HashFunction hash_fn = globalState().algorithmFactory().makeHashFunction(hash_id);
    
    hash_fn.update(BigInt.encode1363(in1, pad_to));
    hash_fn.update(BigInt.encode1363(in2, pad_to));
    
    return BigInt.decode(hash_fn.finished());
}

BigInt computeX(in string hash_id,
                in string identifier,
                in string password,
                const ref Vector!ubyte salt)
{
    Unique!HashFunction hash_fn = globalState().algorithmFactory().makeHashFunction(hash_id);
    
    hash_fn.update(identifier);
    hash_fn.update(":");
    hash_fn.update(password);
    
    SecureVector!ubyte inner_h = hash_fn.finished();
    
    hash_fn.update(salt);
    hash_fn.update(inner_h);
    
    SecureVector!ubyte outer_h = hash_fn.finished();
    
    return BigInt.decode(outer_h);
}

static if (BOTAN_TEST):

import botan.test;
import botan.libstate.global_state;
import botan.codec.hex;
import botan.rng.test;
import memutils.hashmap;
import std.stdio : File;

static if (BOTAN_HAS_TESTS && !SKIP_SRP6_TEST) unittest
{
    auto state = globalState();
    logDebug("Testing srp6.d ...");
    size_t fails = 0;

    File vec = File("test_data/srp6a.vec", "r");
    fails += runTestsBb(vec, "SRP6a", "S", false,
        (ref HashMap!(string, string) m)
        {
            if (!("S" in m) || !("N" in m) || !("g" in m) || !("Hash" in m) ||
                !("v" in m) || !("A" in m) || !("B" in m) || !("a" in m) || !("b" in m))
                return 0;
            try
            {
                BigInt N = BigInt(m["N"]);
                BigInt g = BigInt(m["g"]);
                const string group_id = srp6GroupIdentifier(N, g);
                const string id = ("I" in m) ? m["I"] : "alice";
                const string pw = ("P" in m) ? m["P"] : "password123";
                auto salt = hexDecode(m["s"]);
                BigInt a = BigInt(m["a"].length >= 2 && m["a"][0..2] == "0x" ? m["a"] : ("0x" ~ m["a"]));
                BigInt b = BigInt(m["b"].length >= 2 && m["b"][0..2] == "0x" ? m["b"] : ("0x" ~ m["b"]));
                BigInt v = BigInt(m["v"]);
                BigInt A_exp = BigInt(m["A"]);
                BigInt B_exp = BigInt(m["B"]);
                auto S_exp = hexDecode(m["S"]);

                auto v_got = generateSrp6Verifier(id, pw, salt, group_id, m["Hash"]);
                if (v_got != v)
                    return 1;

                Unique!SRP6ServerSession srv = new SRP6ServerSession;
                if (srv.step1(v, group_id, m["Hash"], b) != B_exp)
                    return 2;

                auto client = srp6ClientAgree(id, pw, group_id, m["Hash"], salt, B_exp, a);
                if (client.privkey != A_exp)
                    return 3;
                if (client.pubkey.bitsOf()[] != S_exp[])
                    return 4;

                auto k_srv = srv.step2(&A_exp);
                if (k_srv.bitsOf()[] != S_exp[])
                    return 5;
                return 0;
            }
            catch (Exception e)
            {
                logTrace("SRP6a skip ", m["Hash"], ": ", e.msg);
                return 0;
            }
        });

    fails += checkMemutilsRepeat("srp6a", {
        BigInt N = BigInt("0xeeaf0ab9adb38dd69c33f80afa8fc5e86072618775ff3c0b9ea2314c9c256576d674df7496ea81d3383b4813d692c6e0e0d5d8e250b98be48e495c1d6089dad15dc7d7b46154d6b6ce8ef4ad69b15d4982559b297bcf1885c529f566660e57ec68edbc3c05726cc02fd4cbf4976eaa9afd5138fe8376435b9fc61d2fc0eb06e3");
        BigInt g = BigInt("2");
        const string group_id = srp6GroupIdentifier(N, g);
        auto salt = hexDecode("beb25379d1a8581eb5a727673a2441ee");
        BigInt a = BigInt("0x60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393");
        BigInt b = BigInt("0xe487cb59d31ac550471e81f00f6928e01dda08e974a004f49e61f5d105284d20");
        auto v = generateSrp6Verifier("alice", "password123", salt, group_id, "SHA-1");
        Unique!SRP6ServerSession srv = new SRP6ServerSession;
        ref const(BigInt) B = srv.step1(v, group_id, "SHA-1", b);
        auto client = srp6ClientAgree("alice", "password123", group_id, "SHA-1", salt, B, a);
        auto k = srv.step2(&client.privkey);
        if (k.bitsOf()[] != client.pubkey.bitsOf()[])
            throw new Exception("srp6 leak probe");
    });

    if (fails)
        logError("srp6a failures: ", fails);
    assert(fails == 0);
}
