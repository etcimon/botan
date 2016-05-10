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
	@safe pure nothrow this(in string err, Throwable next = null, string file = __FILE__, int line = __LINE__)
	{ super("Out of bounds: " ~ err, next, file, line); }
}

/**
* InvalidArgument Exception
*/
class InvalidArgument : Exception
{
	@safe pure nothrow this(in string err, Throwable next = null, string file = __FILE__, int line = __LINE__)
	{ super("Invalid argument: " ~ err, next, file, line); }
}

/**
* InvalidState Exception
*/
class InvalidState : Exception
{
	@safe pure nothrow this(in string err, Throwable next = null, string file = __FILE__, int line = __LINE__)
	{ super(err, next, file, line); }
}

/**
* Logic_Error Exception
*/
final class LogicError : Exception
{
	@safe pure nothrow this(in string err, Throwable next = null, string file = __FILE__, int line = __LINE__)
	{ super(err, next, file, line); }
}

/**
* LookupError Exception
*/
class LookupError : Exception
{
	@safe pure nothrow this(in string err, Throwable next = null, string file = __FILE__, int line = __LINE__)
	{ super(err, next, file, line); }
}

/**
* InternalError Exception
*/
class InternalError : Exception
{
	@safe pure nothrow this(in string err, Throwable next = null, string file = __FILE__, int line = __LINE__) 
	{ super("Internal error: " ~ err, next, file, line); }
}

/**
* InvalidKeyLength Exception
*/
final class InvalidKeyLength : InvalidArgument
{
	@safe pure nothrow this(in string name, size_t length, Throwable next = null, string file = __FILE__, int line = __LINE__) {
        super(name ~ " cannot accept a key of length " ~
			to!string(length), next, file, line);
    }
}

/**
* InvalidIVLength Exception
*/
final class InvalidIVLength : InvalidArgument
{
	@safe pure nothrow this(in string mode, size_t bad_len, Throwable next = null, string file = __FILE__, int line = __LINE__) {
		super("IV length " ~ to!string(bad_len) ~ " is invalid for " ~ mode, next, file, line);
    }
}

/**
* PRNGUnseeded Exception
*/
final class PRNGUnseeded : InvalidState
{
	@safe pure nothrow this(in string algo, Throwable next = null, string file = __FILE__, int line = __LINE__) {
		super("PRNG not seeded: " ~ algo, next, file, line);
    }
}

/**
* PolicyViolation Exception
*/
final class PolicyViolation : InvalidState
{
	@safe pure nothrow this(in string err, Throwable next = null, string file = __FILE__, int line = __LINE__) {
		super("TLSPolicy violation: " ~ err, next, file, line);
    }
}

/**
* AlgorithmNotFound Exception
*/
final class AlgorithmNotFound : LookupError
{
	@safe pure nothrow this(in string name, Throwable next = null, string file = __FILE__, int line = __LINE__) {
		super("Could not find any algorithm named \"" ~ name ~ "\"", next, file, line);
    }
}

/**
* InvalidAlgorithmName Exception
*/
final class InvalidAlgorithmName : InvalidArgument
{
	@safe pure nothrow this(in string name, Throwable next = null, string file = __FILE__, int line = __LINE__) {
		super("Invalid algorithm name: " ~ name, next, file, line);
    }
}

/**
* EncodingError Exception
*/
final class EncodingError : InvalidArgument
{
	@safe pure nothrow this(in string name, Throwable next = null, string file = __FILE__, int line = __LINE__) {
		super("Encoding error: " ~ name, next, file, line);
    }
}

/**
* DecodingError Exception
*/
class DecodingError : InvalidArgument
{
	@safe pure nothrow this(in string name, Throwable next = null, string file = __FILE__, int line = __LINE__) 
    {
		super("Decoding error: " ~ name, next, file, line);
    }
}

/**
* IntegrityFailure Exception
*/
final class IntegrityFailure : Exception
{
	@safe pure nothrow this(in string msg, Throwable next = null, string file = __FILE__, int line = __LINE__) {
		super("Integrity failure: " ~ msg, next, file, line);
    }
}

/**
* InvalidOID Exception
*/
final class InvalidOID : DecodingError
{
	@safe pure nothrow this(in string oid, Throwable next = null, string file = __FILE__, int line = __LINE__) {
		super("Invalid ASN.1 OID: " ~ oid, next, file, line);
    }
}

/**
* StreamIOError Exception
*/
final class StreamIOError : Exception
{
	@safe pure nothrow this(in string err, Throwable next = null, string file = __FILE__, int line = __LINE__) {
		super("I/O error: " ~ err, next, file, line);
    }
}

/**
* Self Test Failure Exception
*/
final class SelfTestFailure : InternalError
{
	@safe pure nothrow this(in string err, Throwable next = null, string file = __FILE__, int line = __LINE__) {
		super("Self test failed: " ~ err, next, file, line);
    }
}

/**
* Memory Allocation Exception
*/
final class MemoryExhaustion : Exception
{
	@safe pure nothrow this(in string err, Throwable next = null, string file = __FILE__, int line = __LINE__) {
		super("Memory Exhaustion: " ~ err, next, file, line);
    }

    string what() const nothrow pure
    { return "Ran out of memory, allocation failed"; }
}