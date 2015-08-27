/**
* Exceptions
* 
* Copyright:
* (C) 1999-2009 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.utils.exceptn;

import botan.utils.types;
import botan.utils.parsing;
import std.exception;
import std.conv : to;
@safe pure nothrow :
class RangeError : Exception
{
    @safe pure nothrow this(in string err)
    { super("Out of bounds: " ~ err); }
}

/**
* InvalidArgument Exception
*/
class InvalidArgument : Exception
{
    @safe pure nothrow this(in string err)
    { super("Invalid argument: " ~ err); }
}

/**
* InvalidState Exception
*/
class InvalidState : Exception
{
    @safe pure nothrow this(in string err)
    { super(err); }
}

/**
* Logic_Error Exception
*/
final class LogicError : Exception
{
    @safe pure nothrow this(in string err)
    { super(err); }
}

/**
* LookupError Exception
*/
class LookupError : Exception
{
    @safe pure nothrow this(in string err)
    { super(err); }
}

/**
* InternalError Exception
*/
class InternalError : Exception
{
    @safe pure nothrow this(in string err) 
    { super("Internal error: " ~ err); }
}

/**
* InvalidKeyLength Exception
*/
final class InvalidKeyLength : InvalidArgument
{
    @safe pure nothrow this(in string name, size_t length) {
        super(name ~ " cannot accept a key of length " ~
              to!string(length));
    }
}

/**
* InvalidIVLength Exception
*/
final class InvalidIVLength : InvalidArgument
{
    @safe pure nothrow this(in string mode, size_t bad_len) {
        super("IV length " ~ to!string(bad_len) ~ " is invalid for " ~ mode);
    }
}

/**
* PRNGUnseeded Exception
*/
final class PRNGUnseeded : InvalidState
{
    @safe pure nothrow this(in string algo) {
        super("PRNG not seeded: " ~ algo);
    }
}

/**
* PolicyViolation Exception
*/
final class PolicyViolation : InvalidState
{
    @safe pure nothrow this(in string err) {
        super("TLSPolicy violation: " ~ err);
    }
}

/**
* AlgorithmNotFound Exception
*/
final class AlgorithmNotFound : LookupError
{
    @safe pure nothrow this(in string name) {
        super("Could not find any algorithm named \"" ~ name ~ "\"");
    }
}

/**
* InvalidAlgorithmName Exception
*/
final class InvalidAlgorithmName : InvalidArgument
{
    @safe pure nothrow this(in string name) {
        super("Invalid algorithm name: " ~ name);
    }
}

/**
* EncodingError Exception
*/
final class EncodingError : InvalidArgument
{
    @safe pure nothrow this(in string name) {
        super("Encoding error: " ~ name);
    }
}

/**
* DecodingError Exception
*/
class DecodingError : InvalidArgument
{
    @safe pure nothrow this(in string name) 
    {
        super("Decoding error: " ~ name);
    }
}

/**
* IntegrityFailure Exception
*/
final class IntegrityFailure : Exception
{
    @safe pure nothrow this(in string msg) {
        super("Integrity failure: " ~ msg);
    }
}

/**
* InvalidOID Exception
*/
final class InvalidOID : DecodingError
{
    @safe pure nothrow this(in string oid) {
        super("Invalid ASN.1 OID: " ~ oid);
    }
}

/**
* StreamIOError Exception
*/
final class StreamIOError : Exception
{
    @safe pure nothrow this(in string err) {
        super("I/O error: " ~ err);
    }
}

/**
* Self Test Failure Exception
*/
final class SelfTestFailure : InternalError
{
    @safe pure nothrow this(in string err) {
        super("Self test failed: " ~ err);
    }
}

/**
* Memory Allocation Exception
*/
final class MemoryExhaustion : Exception
{
    @safe pure nothrow this(in string err) {
        super("Memory Exhaustion: " ~ err);
    }

    string what() const nothrow pure
    { return "Ran out of memory, allocation failed"; }
}