/**
* Argon2 PHC string format (C++ argon2fmt)
*
* Copyright:
* (C) 2018,2019,2022 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.passhash.argon2fmt;

import botan.constants;
static if (BOTAN_HAS_ARGON2_FMT && BOTAN_HAS_ARGON2 && BOTAN_HAS_BLAKE2B):

import botan.pbkdf.argon2;
import botan.rng.rng;
import botan.codec.base64;
import botan.utils.parsing;
import botan.utils.mem_ops;
import botan.utils.exceptn;
import botan.utils.types;
import std.conv : to;

private string stripPadding(string s)
{
    while (s.length && s[$ - 1] == '=')
        s = s[0 .. $ - 1];
    return s;
}

private string argon2ModeLetter(ubyte y)
{
    if (y == 0)
        return "d";
    if (y == 1)
        return "i";
    if (y == 2)
        return "id";
    throw new InvalidArgument("Unknown Argon2 family type");
}

/**
* Generate an Argon2 PHC string (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`).
* Params:
*  password = passphrase
*  password_len = length of password
*  rng = used to draw the salt
*  p = parallelism
*  M = memory in KiB
*  t = iterations
*  y = 0 Argon2d, 1 Argon2i, 2 Argon2id
*  salt_len = salt length (default 16)
*  output_len = hash length (default 32)
* Returns: PHC encoded string
*/
string generateArgon2Pwhash(const(char)* password, size_t password_len,
                            RandomNumberGenerator rng,
                            size_t p, size_t M, size_t t,
                            ubyte y = 2,
                            size_t salt_len = 16,
                            size_t output_len = 32)
{
    Vector!ubyte salt = Vector!ubyte(salt_len);
    rng.randomize(salt.ptr, salt.length);

    Unique!Argon2 argon = new Argon2(y, M, t, p);
    SecureVector!ubyte output = SecureVector!ubyte(output_len);
    argon.derive(output.ptr, output.length,
                 cast(const(ubyte)*)password, password_len,
                 salt.ptr, salt.length,
                 null, 0, null, 0, t);

    const string enc_salt = stripPadding(base64Encode(salt));
    const string enc_output = stripPadding(base64Encode(output));
    return "$argon2" ~ argon2ModeLetter(y) ~
           "$v=19$m=" ~ to!string(M) ~
           ",t=" ~ to!string(t) ~
           ",p=" ~ to!string(p) ~
           "$" ~ enc_salt ~ "$" ~ enc_output;
}

/// ditto
string generateArgon2Pwhash(in string password,
                            RandomNumberGenerator rng,
                            size_t p, size_t M, size_t t,
                            ubyte y = 2,
                            size_t salt_len = 16,
                            size_t output_len = 32)
{
    return generateArgon2Pwhash(password.ptr, password.length, rng, p, M, t, y, salt_len, output_len);
}

/**
* Verify an Argon2 PHC string. Returns false on malformed input or mismatch.
*/
bool checkArgon2Pwhash(const(char)* password, size_t password_len, in string input_hash)
{
    try
    {
        auto parts = splitter(input_hash, '$');
        if (parts.length != 5)
            return false;

        ubyte family = 0;
        if (parts[0] == "argon2d")
            family = 0;
        else if (parts[0] == "argon2i")
            family = 1;
        else if (parts[0] == "argon2id")
            family = 2;
        else
            return false;

        if (parts[1] != "v=19")
            return false;

        auto params = splitter(parts[2], ',');
        if (params.length != 3)
            return false;

        size_t M = 0, t = 0, p = 0;
        foreach (param_str; params[])
        {
            auto param = splitter(param_str, '=');
            if (param.length != 2)
                return false;
            const size_t val = to!size_t(param[1]);
            if (param[0] == "m")
                M = val;
            else if (param[0] == "t")
                t = val;
            else if (param[0] == "p")
                p = val;
            else
                return false;
        }

        auto salt = unlock(base64Decode(parts[3]));
        auto hash = unlock(base64Decode(parts[4]));
        if (hash.length < 4)
            return false;

        Unique!Argon2 argon = new Argon2(family, M, t, p);
        SecureVector!ubyte generated = SecureVector!ubyte(hash.length);
        argon.derive(generated.ptr, generated.length,
                     cast(const(ubyte)*)password, password_len,
                     salt.ptr, salt.length,
                     null, 0, null, 0, t);
        return sameMem(generated.ptr, hash.ptr, generated.length);
    }
    catch (Exception)
    {
        return false;
    }
}

/// ditto
bool checkArgon2Pwhash(in string password, in string hash)
{
    return checkArgon2Pwhash(password.ptr, password.length, hash);
}

static if (BOTAN_HAS_TESTS && !SKIP_ARGON2_FMT_TEST) unittest
{
    import botan.test;
    import botan.codec.hex;
    import botan.libstate.global_state;
    import botan.rng.test;
    import memutils.hashmap;
    import std.stdio : File;

    auto state = globalState();
    logDebug("Testing argon2fmt.d ...");
    size_t fails = 0;

    File vec = File("test_data/passhash/argon2.vec", "r");
    fails += runTestsBb(vec, "Argon2Pass", "Passhash", true,
        (ref HashMap!(string, string) m)
        {
            if (!("Password" in m) || !("Passhash" in m))
                return 0;
            const string header = m["Argon2Pass"];
            const string password = m["Password"];
            const string passhash = m["Passhash"];
            if (header == "Verify")
            {
                if (!checkArgon2Pwhash(password, passhash))
                {
                    logError("argon2 verify rejected ", passhash);
                    return 1;
                }
                return 0;
            }
            if (header == "Generate")
            {
                auto salt = hexDecode(m["Salt"]);
                const ubyte y = to!ubyte(m["Mode"]);
                const size_t M = to!size_t(m["M"]);
                const size_t t = to!size_t(m["T"]);
                const size_t p = to!size_t(m["P"]);
                const size_t out_len = to!size_t(m["OutLen"]);
                Unique!FixedOutputRNG rng = new FixedOutputRNG(salt);
                const string generated = generateArgon2Pwhash(password, *rng, p, M, t, y, salt.length, out_len);
                if (generated != passhash)
                {
                    logError("argon2 generate got ", generated, " expected ", passhash);
                    return 1;
                }
                if (!checkArgon2Pwhash(password, generated))
                {
                    logError("argon2 generated hash not accepted");
                    return 1;
                }
                return 0;
            }
            throw new Exception("Unexpected header in Argon2 password hash test file");
        });

    fails += checkMemutilsRepeat("argon2fmt", {
        Unique!FixedOutputRNG rng = new FixedOutputRNG(hexDecode("31323334353637383961626364656667"));
        const string h = generateArgon2Pwhash("pass", *rng, 1, 8, 1, 2, 16, 32);
        if (!checkArgon2Pwhash("pass", h))
            throw new Exception("argon2fmt leak probe");
    });

    if (fails)
        logError("argon2fmt failures: ", fails);
    assert(fails == 0);
}
