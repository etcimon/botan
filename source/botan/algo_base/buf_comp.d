/**
* Buffered Computation
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/

module botan.algo_base.buf_comp;

import memutils.vector;
import botan.utils.get_byte;
import botan.utils.types;

/**
* This class represents any kind of computation which uses an internal
* state, such as hash functions or MACs
*/
interface BufferedComputation
{
public:

    /**
    * Add new input to process.
    * 
    * Params:
    *  input = the input to process as a ubyte array
    */
    final void update(in ubyte[] input) { addData(input.ptr, input.length); }

    /**
    * Add new input to process.
    * 
    * Params:
    *  input = the input to process as a ubyte array
    *  length = of param in in bytes
    */
    final void update(const(ubyte)* input, size_t length) { addData(input, length); }

    /**
    * Add new input to process.
    * Params:
    *  input = the input to process as a reference type
    */
    final void update(T, ALLOC)(auto const ref RefCounted!(Vector!(T, ALLOC)) input)
    {
        addData(input.ptr, input.length);
    }

    /**
    * Add new input to process.
    * 
    * Params:
    *  input = the input to process as a $(D Vector)
    */
    final void update(T, ALLOC)(auto const ref Vector!(T, ALLOC) input)
    {
        addData(input.ptr, input.length);
    }

    /**
    * Add an integer in big-endian order
    * 
    * Params:
    *  input = the value
    */
    final void updateBigEndian(T)(in T input)
    {
        foreach (size_t i; 0 .. T.sizeof)
        {
            ubyte b = get_byte(i, input);
            addData(&b, 1);
        }
    }

    /**
    * Add new input to process.
    * 
    * Params:
    *  str = The input to process as a string. 
    * 
    * Notes: Will be interpreted as a ubyte array based on the strings encoding.
    */
    final void update(in string str)
    {
        addData(str.ptr, str.length);
    }

    /**
    * Process a single ubyte.
    * 
    * Params:
    *  input = the ubyte to process
    */
    final void update(ubyte input) { addData(&input, 1); }

    /**
    * Complete the computation and retrieve the final result.
    * 
    * Params:
    *  output = The ubyte array to be filled with the result.
    * 
    * Notes: Must be of length outputLength()
    */
    final void flushInto(ref ubyte[] output) 
    in { assert(output.length == outputLength); }
    body { finalResult(output.ptr); }

    /**
    * Complete the computation and retrieve the
    * final result.
    * 
    * Params:
    *  output = The ubyte array to be filled with the result.
    * 
    * Notes: Must be of length outputLength()
    */
    final void flushInto(ubyte* output) { finalResult(output); }

    /**
    * Complete the computation and retrieve the final result.
    * 
    * Returns: $(D SecureVector) holding the result
    */
    final SecureVector!ubyte finished()
    {
        SecureVector!ubyte output = SecureVector!ubyte(outputLength());
        finalResult(output.ptr);
        return output.move;
    }

    /**
    * Update and finalize computation. Does the same as calling $(D update())
    * and $(D finished()) consecutively.
    * 
    * Params:
    *  input = the input to process as a ubyte array
    *  length = the length of the ubyte array
    * 
    * Returns: The result of the call to $(D finished())
    */
    final SecureVector!ubyte process(in ubyte[] input)
    {
        addData(input.ptr, input.length);
        return finished();
    }

    /**
    * Update and finalize computation. Does the same as calling $(D update())
    * and $(D finished()) consecutively.
    * 
    * Params:
    *  input = the input to process as a ubyte array
    *  length = the length of the ubyte array
    * 
    * Returns: The result of the call to $(D finished())
    */
    final SecureVector!ubyte process(const(ubyte)* input, size_t length)
    {
        addData(input, length);
        return finished();
    }

    /**
    * Update and finalize computation. Does the same as calling $(D update())
    * and $(D finished()) consecutively.
    * Params:
    *  input = the input to process
    * 
    * Returns: The result of the call to $(D finished())
    */
    final SecureVector!ubyte process(ALLOC)(auto const ref RefCounted!(Vector!(ubyte, ALLOC), ALLOC) input)
    {
        addData(input.ptr, input.length);
        return finished();
    }

    /**
    * Update and finalize computation. Does the same as calling $(D update())
    * and $(D finished()) consecutively.
    * Params:
    *  input = the input to process
    * 
    * Returns: The result of the call to $(D finished())
    */
    final SecureVector!ubyte process(ALLOC)(auto const ref Vector!(ubyte, ALLOC) input)
    {
        addData(input.ptr, input.length);
        return finished();
    }

    /**
    * Update and finalize computation. Does the same as calling $(D update())
    * and $(D finished()) consecutively.
    * Params:
    *  input = the input to process as a string
    * 
    * Returns: The result of the call to $(D finished())
    */
    final SecureVector!ubyte process(in string input)
    {
        update(input);
        return finished();
    }

    final void addData(T)(in T input, size_t length) {
        addData(cast(const(ubyte)*)input, length);
    }

    /**
    * Returns: Length of the output of this function in bytes
    */
    abstract @property size_t outputLength() const;

protected:
    /**
    * Add more data to the computation
    * 
    * Params:
    *  input = is an input buffer
    *  length = is the length of input in bytes
    */
    abstract void addData(const(ubyte)* input, size_t length);

    /**
    * Write the final output to out
    * 
    * Params:
    *  output = An output buffer of size $(D outputLength())
    */
    abstract void finalResult(ubyte* output);
}