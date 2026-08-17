/**
* Memory Operations
* 
* Copyright:
* (C) 2017 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.utils.mem_ops;
import botan.utils.types;
public import botan_math.mem_ops;
import std.algorithm : min;
import std.traits : isPointer;


Vector!T unlock(T, ALLOC)(const auto ref Vector!(T, ALLOC) input)
    if (is(ALLOC == SecureMem))
{
    return Vector!T(input.ptr[0 .. input.length]);
}

RefCounted!(Vector!T) unlock(T, ALLOC)(const auto ref RefCounted!(Vector!(T, ALLOC), ALLOC) input)
    if (is(ALLOC == SecureMem))
{
    return RefCounted!(Vector!T)(input[]);
}

/**
* Zeroise the values then free the memory
* Params:
*  vec = the vector to zeroise and free
*/
void zap(T, Alloc)(ref Vector!(T, Alloc) vec)
{
    import std.traits : hasIndirections;
    import botan.utils.ct : secureScrubMemory;
    static if (!hasIndirections!T)
    {
        if (vec.ptr && vec.length)
            secureScrubMemory(vec.ptr, T.sizeof * vec.length);
    }
    vec.destroy();
}

size_t bufferInsert(T, Alloc)(ref Vector!(T, Alloc) buf, size_t buf_offset, in T* input, size_t input_length)
{
    import std.algorithm : max;
    const size_t to_copy = min(input_length, buf.length - buf_offset);
    buf.resize(max(buf.length, buf_offset + to_copy));
    copyMem(buf.ptr + buf_offset, input, to_copy);
    return to_copy;
}

size_t bufferInsert(T, Alloc, Alloc2)(ref Vector!(T, Alloc) buf, size_t buf_offset, const ref Vector!(T, Alloc2) input)
{
    import std.algorithm : max;
    const size_t to_copy = min(input.length, buf.length - buf_offset);
    buf.resize(max(buf.length, buf_offset + to_copy));
    copyMem(&buf[buf_offset], input.ptr, to_copy);
    return to_copy;
}

/**
* Memory comparison. Early-out `==` by default (`BOTAN_HAS_CT` false).
* Constant-time when `version(CT)` (`BOTAN_HAS_CT`).
* `n` is the number of bytes compared (historical sameMem contract).
*/
bool sameMem(T)(in T* p1, in T* p2, in size_t n)
    if (!isPointer!T)
{
    import botan.utils.ct : constantTimeCompare;
    return constantTimeCompare(cast(const(ubyte)*) p1, cast(const(ubyte)*) p2, n);
}

pure:

/**
* Set memory to a fixed value
* Params:
*  ptr = a pointer to an array
*  n = the number of Ts pointed to by ptr
*  val = the value to set each ubyte to
*/
void setMem(T)(T* ptr, size_t n, ubyte val)
    if (!isPointer!T)
{
    import core.stdc.string : memset;
    //logDebug("memset ops: ", cast(void*)ptr, " L:", T.sizeof*n);
    memset(ptr, val, T.sizeof*n);
}

/**
* Zeroise the values; length remains unchanged
* Params:
*  vec = the vector to zeroise
*/
void zeroise(T, Alloc)(ref Vector!(T, Alloc) vec)
{
    clearMem(vec.ptr, vec.length);
}

void zeroise(T)(T[] mem) {
    clearMem(mem.ptr, mem.length);
}

