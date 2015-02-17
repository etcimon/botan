/**
* SRP-6a (RFC 5054 compatatible)
* 
* Copyright:
* (C) 2011,2012 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
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
import botan.math.numbertheory.numthry;
import botan.utils.types;

struct SRP6KeyPair {
    BigInt privkey;
    SymmetricKey pubkey;

    this()(auto ref BigInt priv, SymmetricKey pub) {
        privkey = priv.move();
        pubkey = pub;
    }
}

/**
* SRP6a Client side
* Params:
*  username = the username we are attempting login for
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
    
    BigInt k = hashSeq(hash_id, p_bytes, *p, *g);
    
    BigInt a = BigInt(rng, 256);
    
    BigInt A = powerMod(*g, a, *p);
    
    BigInt u = hashSeq(hash_id, p_bytes, A, B);
    
    BigInt x = computeX(hash_id, identifier, password, salt);
    
    BigInt S = powerMod((B - (k * powerMod(*g, x, *p))) % (*p), (a + (u * x)), *p);
    
    SymmetricKey Sk = SymmetricKey(BigInt.encode1363(S, p_bytes));
    
    return SRP6KeyPair(A, Sk);
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
    return powerMod(group.getG(), x, group.getP());
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
    catch (Throwable)
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
        
        BigInt k = hashSeq(hash_id, m_p_bytes, *p, *g);
        
        BigInt b = BigInt(rng, 256);
        
        m_B = (v*k + powerMod(*g, b, *p)) % (*p);
        
        m_v = v.dup;
        m_b = b.move();
        m_p = p.dup;
        m_hash_id = hash_id;
        
        return m_B;
    }

    /**
    * Server side step 2
    * Params:
    *  A = the client's value
    * Returns: shared symmetric key
    */
    SymmetricKey step2()(auto const ref BigInt A)
    {
        if (A <= 0 || A >= m_p)
            throw new Exception("Invalid SRP parameter from client");
        
        BigInt u = hashSeq(m_hash_id, m_p_bytes, A, m_B);
        
        BigInt S = powerMod(A * powerMod(m_v, u, m_p), m_b, m_p);
        
        return SymmetricKey(BigInt.encode1363(S, m_p_bytes));
    }

private:
    string m_hash_id;
    BigInt m_B, m_b, m_v, m_p; // m_S
    size_t m_p_bytes;
}

private:
    
BigInt hashSeq()(in string hash_id,
                 size_t pad_to,
                 auto const ref BigInt in1,
                 auto const ref BigInt in2)
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
