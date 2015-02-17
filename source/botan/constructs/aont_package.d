/**
* Rivest's Package Tranform
* 
* Copyright:
* (C) 2009 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.constructs.aont_package;

import botan.constants;
static if (BOTAN_HAS_AONT):

// todo: write unit tests

import botan.block.block_cipher;
import botan.rng.rng;
import botan.filters.filters;
import botan.stream.ctr;
import botan.utils.get_byte;
import botan.utils.xor_buf;
import botan.algo_base.symkey;

/**
* Rivest's Package Tranform
* Params:
*  rng = the random number generator to use
*  cipher = the block cipher to use
*  input = the input data buffer
*  input_len = the length of the input data in bytes
*  output = the output data buffer (must be at least
*          input_len + cipher.BLOCK_SIZE bytes long)
*/
void aontPackage(RandomNumberGenerator rng,
                 BlockCipher cipher,
                 const(ubyte)* input, size_t input_len,
                 ubyte* output)
{
    import std.algorithm : fill;
    const size_t BLOCK_SIZE = cipher.blockSize();
    
    if (!cipher.validKeylength(BLOCK_SIZE))
        throw new InvalidArgument("AONT::package: Invalid cipher");
    
    // The all-zero string which is used both as the CTR IV and as K0
    Vector!ubyte all_zeros = Vector!ubyte(BLOCK_SIZE*2);
    zeroise(all_zeros);
    
    SymmetricKey package_key = SymmetricKey(rng, BLOCK_SIZE);
    
    Pipe pipe = Pipe(new StreamCipherFilter(new CTRBE(cipher), package_key));
    
    pipe.processMsg(input, input_len);
    pipe.read(output, pipe.remaining());
    
    // Set K0 (the all zero key)
    cipher.setKey(SymmetricKey(all_zeros));
    
    SecureVector!ubyte buf = SecureVector!ubyte(BLOCK_SIZE);

    const size_t blocks = (input_len + BLOCK_SIZE - 1) / BLOCK_SIZE;
    
    ubyte* final_block = output + input_len;
    clearMem(final_block, BLOCK_SIZE);
    
    // XOR the hash blocks into the final block
    foreach (size_t i; 0 .. blocks)
    {
        const size_t left = std.algorithm.min(BLOCK_SIZE, input_len - BLOCK_SIZE * i);
        
        zeroise(buf);
        copyMem(buf.ptr, output + (BLOCK_SIZE * i), left);
        
        for (size_t j = 0; j != i.sizeof; ++j)
            buf[BLOCK_SIZE - 1 - j] ^= get_byte((i).sizeof-1-j, i);
        
        cipher.encrypt(buf.ptr);
        
        xorBuf(final_block, buf.ptr, BLOCK_SIZE);
    }
    
    // XOR the random package key into the final block
    xorBuf(final_block, package_key.ptr, BLOCK_SIZE);
}

/**
* Rivest's Package Tranform (Inversion)
* Params:
*  cipher = the block cipher to use
*  input = the input data buffer
*  input_len = the length of the input data in bytes
*  output = the output data buffer (must be at least
*          input_len - cipher.BLOCK_SIZE bytes long)
*/
void aontUnpackage(BlockCipher cipher,
                    const(ubyte)* input, size_t input_len,
                    ubyte* output)
{
    const size_t BLOCK_SIZE = cipher.blockSize();
    
    if (!cipher.validKeylength(BLOCK_SIZE))
        throw new InvalidArgument("AONT::unpackage: Invalid cipher");
    
    if (input_len < BLOCK_SIZE)
        throw new InvalidArgument("AONT::unpackage: Input too short");
    
    // The all-zero string which is used both as the CTR IV and as K0
    Vector!ubyte all_zeros = Vector!ubyte(BLOCK_SIZE*2);
    all_zeros.zeroise();
    
    cipher.setKey(SymmetricKey(all_zeros));
    
    SecureVector!ubyte package_key = SecureVector!ubyte(BLOCK_SIZE);
    SecureVector!ubyte buf = SecureVector!ubyte(BLOCK_SIZE);
    
    // Copy the package key (masked with the block hashes)
    copyMem(package_key.ptr, input + (input_len - BLOCK_SIZE), BLOCK_SIZE);
    
    const size_t blocks = ((input_len - 1) / BLOCK_SIZE);
    
    // XOR the blocks into the package key bits
    foreach (size_t i; 0 .. blocks)
    {
        const size_t left = std.algorithm.min(BLOCK_SIZE,
                                              input_len - BLOCK_SIZE * (i+1));
        
        zeroise(buf);
        copyMem(buf.ptr, input + (BLOCK_SIZE * i), left);
        
        for (size_t j = 0; j != (i).sizeof; ++j)
            buf[BLOCK_SIZE - 1 - j] ^= get_byte((i).sizeof-1-j, i);
        
        cipher.encrypt(buf.ptr);
        
        xorBuf(package_key.ptr, buf.ptr, BLOCK_SIZE);
    }
    
    Pipe pipe = Pipe(new StreamCipherFilter(new CTRBE(cipher), SymmetricKey(package_key)));
    
    pipe.processMsg(input, input_len - BLOCK_SIZE);
    
    pipe.read(output, pipe.remaining());


}