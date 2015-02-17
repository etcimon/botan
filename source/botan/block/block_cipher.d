/**
* Block Cipher Base Class
* 
* Copyright:
* (C) 1999-2009 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.block.block_cipher;

import botan.constants;
public import botan.algo_base.transform;
public import botan.algo_base.sym_algo;

/**
* This class represents a block cipher object.
*/
interface BlockCipher : SymmetricAlgorithm
{
public:

    /**
    * Returns: block size of this algorithm
    */
    abstract size_t blockSize() const;

    /**
    * Returns: native parallelism of this cipher in blocks
    */
    abstract @property size_t parallelism() const;

    /**
    * Returns: prefererred parallelism of this cipher in bytes
    */
    final size_t parallelBytes() const
    {
        return parallelism * this.blockSize() * BOTAN_BLOCK_CIPHER_PAR_MULT;
    }

    /**
    * Encrypt a block.
    * 
    * Params:
    *  input = The plaintext block to be encrypted as a ubyte array.
    *  output = The ubyte array designated to hold the encrypted block.
    * 
    * Notes: Both arguments must be of length blockSize().
    */
    final void encrypt(const(ubyte)* input, ubyte* output)
    { encryptN(input, output, 1); }

    /**
    * Decrypt a block.
    * Params:
    *  input = The ciphertext block to be decypted as a ubyte array.
    *  output = The ubyte array designated to hold the decrypted block.
    * Notes: Both parameters must be of length blockSize().
    */
    final void decrypt(const(ubyte)* input, ubyte* output)
    { decryptN(input, output, 1); }

    /**
    * Encrypt a block.
    * Params:
    *  block = the plaintext block to be encrypted
    * Notes: Must be of length blockSize(). Will hold the result when the function
    * has finished.
    */
    final void encrypt(ubyte* block) { encryptN(cast(const(ubyte)*)block, block, 1); }
    
    /**
    * Decrypt a block.
    * Params:
    *  block = the ciphertext block to be decrypted
    * Notes: Must be of length blockSize(). Will hold the result when the function
    * has finished.
    */
    final void decrypt(ubyte* block) { decryptN(cast(const(ubyte)*)block, block, 1); }

    /**
    * Encrypt a block.
    * Params:
    *  block = the plaintext block to be encrypted
    * Notes: Must be of length blockSize(). Will hold the result when the function
    * has finished.
    */
    final void encrypt(ref ubyte[] block) 
    in { assert(block.length == this.blockSize()); }
    body { encryptN(block.ptr, block.ptr, 1); }
    
    /**
    * Decrypt a block.
    * Params:
    *  block = the ciphertext block to be decrypted
    * Notes: Must be of length blockSize(). Will hold the result when the function
    * has finished.
    */
    final void decrypt(ref ubyte[] block) 
    in { assert(block.length >= this.blockSize()); }
    body { decryptN(block.ptr, block.ptr, 1); }

    /**
    * Encrypt one or more blocks
    * Params:
    *  block = the input/output buffer (multiple of blockSize())
    */
    final void encrypt(Alloc)(ref Vector!( ubyte, Alloc ) block)
    in { assert(block.length >= this.blockSize()); }
    body {
        return encryptN(block.ptr, block.ptr, block.length / this.blockSize());
    }

    /**
    * Decrypt one or more blocks
    * Params:
    *  block = the input/output buffer (multiple of blockSize())
    */
    final void decrypt(Alloc)(ref Vector!( ubyte, Alloc ) block)
    in { assert(block.length >= this.blockSize()); }
    body {
        return decryptN(block.ptr, block.ptr, block.length / this.blockSize());
    }

    /**
    * Encrypt one or more blocks
    * Params:
    *  input = the input buffer (multiple of blockSize())
    *  output = the output buffer (same size as input)
    */
    final void encrypt(Alloc, Alloc2)(auto const ref Vector!( ubyte, Alloc ) input,
                                              ref Vector!( ubyte, Alloc2 ) output)
    in { assert(input.length >= this.blockSize()); }
    body {
        return encryptN(input.ptr, output.ptr, input.length / this.blockSize());
    }
    
    /**
    * Decrypt one or more blocks
    * Params:
    *  input = the input buffer (multiple of blockSize())
    *  output = the output buffer (same size as input)
    */
    final void decrypt(Alloc, Alloc2)(auto const ref Vector!( ubyte, Alloc ) input,
                                              ref Vector!( ubyte, Alloc2 ) output)
    in { assert(input.length >= this.blockSize()); }
    body {
        return decryptN(input.ptr, output.ptr, input.length / this.blockSize());
    }
    /**
    * Encrypt one or more blocks
    * Params:
    *  input = the input buffer (multiple of blockSize())
    *  output = the output buffer (same size as input)
    */
    final void encrypt(ubyte[] input, ref ubyte[] output)
    in { assert(input.length >= this.blockSize()); }
    body {
        return encryptN(input.ptr, output.ptr, input.length / blockSize());
    }
    
    /**
    * Decrypt one or more blocks
    * Params:
    *  input = the input buffer (multiple of blockSize())
    *  output = the output buffer (same size as input)
    */
    final void decrypt(ubyte[] input, ref ubyte[] output)
    in { assert(input.length >= this.blockSize()); }
    body {
        return decryptN(input.ptr, output.ptr, input.length / this.blockSize());
    }

    /**
    * Encrypt one or more blocks
    * Params:
    *  input = the input buffer (multiple of blockSize())
    *  output = the output buffer (same size as input)
    *  blocks = the number of blocks to process
    */
    abstract void encryptN(const(ubyte)* input, ubyte* output, size_t blocks);

    /**
    * Decrypt one or more blocks
    * Params:
    *  input = the input buffer (multiple of blockSize())
    *  output = the output buffer (same size as input)
    *  blocks = the number of blocks to process
    */
    abstract void decryptN(const(ubyte)* input, ubyte* output, size_t blocks);

    /**
    * Returns: new object representing the same algorithm as this
    */
    abstract BlockCipher clone() const;
}

/**
* Represents a block cipher with a single fixed block size
*/ 
abstract class BlockCipherFixedParams(size_t BS, size_t KMIN, size_t KMAX = 0, size_t KMOD = 1) : BlockCipher, SymmetricAlgorithm
{
public:
    enum { BLOCK_SIZE = BS }
    override size_t blockSize() const { return BS; }

    KeyLengthSpecification keySpec() const
    {
        return KeyLengthSpecification(KMIN, KMAX, KMOD);
    }

    abstract void clear();
    this() { clear(); } // TODO: Write some real constructors for each object.
}

static if (BOTAN_TEST):

import botan.test;
import botan.libstate.libstate;
import botan.algo_factory.algo_factory;
import botan.codec.hex;
import core.atomic;
import memutils.hashmap;

shared size_t total_tests;

size_t blockTest(string algo, string key_hex, string in_hex, string out_hex)
{
    const SecureVector!ubyte key = hexDecodeLocked(key_hex);
    const SecureVector!ubyte pt = hexDecodeLocked(in_hex);
    const SecureVector!ubyte ct = hexDecodeLocked(out_hex);

    AlgorithmFactory af = globalState().algorithmFactory();
    
    const auto providers = af.providersOf(algo);
    size_t fails = 0;
    
    if (providers.empty)
        throw new Exception("Unknown block cipher " ~ algo);
    
    foreach (provider; providers[])
    {

        atomicOp!"+="(total_tests, 1);
        const BlockCipher proto = af.prototypeBlockCipher(algo, provider);
        
        if (!proto)
        {
            logError("Unable to get " ~ algo ~ " from " ~ provider);
            ++fails;
            continue;
        }
        
        Unique!BlockCipher cipher = proto.clone();
        cipher.setKey(key);
        SecureVector!ubyte buf = pt.dup;
        
        cipher.encrypt(buf);
        atomicOp!"+="(total_tests, 1);
        if (buf != ct)
        {
            logTrace(buf[], " Real");
            logTrace(ct[], " Expected");
            ++fails;
            buf = ct.dup;
        }

        cipher.decrypt(buf);

        atomicOp!"+="(total_tests, 1);
        if (buf != pt)
        {
            logTrace(buf[], " Real");
            logTrace(pt[], " Expected");
            ++fails;
        }
    }
    //logTrace("Finished ", algo, " Fails: ", fails);
    assert(fails == 0);
    return fails;
}

static if (!SKIP_BLOCK_TEST) unittest {


    logDebug("Testing block_cipher.d ...");
    size_t test_bc(string input)
    {
        logDebug("Testing file `" ~ input ~ " ...");
        File vec = File(input, "r");
        return runTestsBb(vec, "BlockCipher", "Out", true,
              (ref HashMap!(string, string) m) {
                  return blockTest(m["BlockCipher"], m["Key"], m["In"], m["Out"]);
              });
    }
    
    logTrace("Running tests ...");
    size_t fails = runTestsInDir("../test_data/block", &test_bc);


    testReport("block_cipher", total_tests, fails);
}
