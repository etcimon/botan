/**
* Version Information
* 
* Copyright:
* (C) 1999-2011 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.utils.version_;

import botan.constants;
import botan.utils.types;
import botan.utils.parsing;
/*
 * These are intentionally compiled so an application running against a 
 * shared library can test the true version they are running against.
*/

/**
* Get a human-readable string identifying the version of Botan.
* No particular format should be assumed.
* Returns: version string
*/
string versionString()
{        
    /*
    It is intentional that this string is a compile-time constant;
    it makes it much easier to find in binaries.
    */
    return "Botan " ~ BOTAN_VERSION_MAJOR.to!string ~ "."
            ~ BOTAN_VERSION_MINOR.to!string ~ "." 
            ~ BOTAN_VERSION_PATCH.to!string ~ " ("
            ~ BOTAN_VERSION_RELEASE_TYPE.to!string
            ~ ", dated " ~ BOTAN_VERSION_DATESTAMP.to!string
            ~ ", revision " ~ BOTAN_VERSION_VC_REVISION.to!string
            ~ ", distribution " ~ BOTAN_DISTRIBUTION_INFO.to!string ~ ")";
}

/**
* Return the date this version of botan was released, in an integer of
* the form YYYYMMDD. For instance a version released on May 21, 2013
* would return the integer 20130521. If the currently running version
* is not an official release, this function will return 0 instead.
*
* Returns: release date, or zero if unreleased
*/
uint versionDatestamp() { return BOTAN_VERSION_DATESTAMP; }

/**
* Get the major version number.
* Returns: major version number
*/
uint versionMajor() { return BOTAN_VERSION_MAJOR; }

/**
* Get the minor version number.
* Returns: minor version number
*/
uint versionMinor() { return BOTAN_VERSION_MINOR; }

/**
* Get the patch number.
* Returns: patch number
*/
uint versionPatch() { return BOTAN_VERSION_PATCH; }

/*
* Allows compile-time version checks
*/
long BOTAN_VERSION_CODE_FOR(ubyte a, ubyte b, ubyte c) {
    return ((a << 16) | (b << 8) | (c));
}

/**
* Compare using BOTAN_VERSION_CODE_FOR, as in
*  static assert (BOTAN_VERSION_CODE > BOTAN_VERSION_CODE_FOR(1,8,0), "Botan version too old");
*/
static long BOTAN_VERSION_CODE = BOTAN_VERSION_CODE_FOR(BOTAN_VERSION_MAJOR, BOTAN_VERSION_MINOR, BOTAN_VERSION_PATCH);