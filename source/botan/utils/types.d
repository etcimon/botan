/**
* Low Level Types
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.utils.types;

public import memutils.vector : Vector, Array, SecureVector, SecureArray;
public import memutils.utils;
public import memutils.refcounted;
public import memutils.unique;
public import botan.utils.exceptn;
public import std.typecons : scoped;

alias Scoped(T) = typeof(scoped!T());

/**
* The two possible directions for cipher filters, determining whether they
* actually perform encryption or decryption.
*/
alias CipherDir = bool;
enum : CipherDir { ENCRYPTION, DECRYPTION }

struct Pair(T, U) {
    import std.typecons : Tuple;
    Tuple!(T,U) m_obj;

    @property inout(T) first() inout {
        return m_obj[0];
    }

    @property inout(U) second() inout {
        return m_obj[1];
    }

    this(T a, U b) {
        m_obj = Tuple!(T,U)(a, b);
    }

    this(in T a, in U b) {
        m_obj = Tuple!(T,U)(*cast(T*) &a,*cast(U*) &b);
    }

    alias m_obj this;
}

Pair!(T, U) makePair(T, U)(const T first, const U second)
{
    return Pair!(UnConst!T, UnConst!U)(first, second);
}

Pair!(T, U) makePair(T, U)(T first, U second)
{
    return Pair!(T, U)(first, second);
}


private template UnConst(T) {
    static if (is(T U == const(U))) {
        alias UnConst = U;
    } else static if (is(T V == immutable(V))) {
        alias UnConst = V;
    } else alias UnConst = T;
}


/**
* Existence check for values
*/
bool valueExists(T, Alloc)(auto const ref Vector!(T, Alloc) vec, in T val)
{
    for (size_t i = 0; i != vec.length; ++i)
        if (vec[i] == val)
            return true;
    return false;
}