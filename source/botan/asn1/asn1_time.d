/**
* ASN.1 Time Representation
* 
* Copyright:
* (C) 1999-2007,2012 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.asn1.asn1_time;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

import std.datetime;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.utils.charset;
import botan.utils.parsing;
import botan.utils.types;
import std.conv : to;
import std.array : Appender;

alias X509Time = RefCounted!X509TimeImpl;

/**
* X.509 Time
*/
final class X509TimeImpl : ASN1Object
{
public:

    this() { }

    /*
    * DER encode a X509Time
    */
    override void encodeInto(ref DEREncoder der) const
    {
        if (m_tag != ASN1Tag.GENERALIZED_TIME && m_tag != ASN1Tag.UTC_TIME)
            throw new InvalidArgument("X509Time: Bad encoding m_tag");
        
        der.addObject(m_tag, ASN1Tag.UNIVERSAL,
                       transcode(toString(), LOCAL_CHARSET, LATIN1_CHARSET));
    }

    /*
    * Decode a BER encoded X509Time
    */
    override void decodeFrom(ref BERDecoder source)
    {
        BERObject ber_time = source.getNextObject();
        
        setTo(transcode(ber_time.toString(),
                         LATIN1_CHARSET,
                         LOCAL_CHARSET),
               ber_time.type_tag);
    }

    /*
    * Return a string representation of the time
    */
    override string toString() const
    {
        if (timeIsSet() == false)
            throw new InvalidState("toTimeString: No time set");
        
        uint full_year = m_year;
        
        if (m_tag == ASN1Tag.UTC_TIME)
        {
            if (m_year < 1950 || m_year >= 2050)
                throw new EncodingError("X509Time: The time " ~ readableString() ~ " cannot be encoded as a UTCTime");
            
            full_year = (m_year >= 2000) ? (m_year - 2000) : (m_year - 1900);
        }
        
        string repr = to!string(full_year*10000000000 +
                                m_month*100000000 +
                                m_day*1000000 +
                                m_hour*10000 +
                                m_minute*100 +
                                m_second) ~ "Z";
        
        uint desired_size = (m_tag == ASN1Tag.UTC_TIME) ? 13 : 15;
        
        while (repr.length < desired_size)
            repr = "0" ~ repr;
        
        return repr;
    }

    /*
    * Return a human readable string representation
    */
    string readableString() const
    {
        if (timeIsSet() == false)
            throw new InvalidState("readableString: No time set");
        import std.string : format;
        
        return format("%04d/%02d/%02d %02d:%02d:%02d UTC", m_year, m_month, m_day, m_hour, m_minute, m_second);
    }

    /*
    * Return if the time has been set somehow
    */
    bool timeIsSet() const
    {
        return (m_year != 0);
    }

    string toPrettyString() const { return readableString(); }

    /*
    * Compare this time against another
    */
    int cmp(in X509Time other) const
    {
        if (timeIsSet() == false)
            throw new InvalidState("cmp: No time set");
        
        const int EARLIER = -1, LATER = 1, SAME_TIME = 0;
        
        if (m_year < other.m_year)          return EARLIER;
        if (m_year > other.m_year)          return LATER;
        if (m_month < other.m_month)        return EARLIER;
        if (m_month > other.m_month)        return LATER;
        if (m_day < other.m_day)            return EARLIER;
        if (m_day > other.m_day)            return LATER;
        if (m_hour < other.m_hour)          return EARLIER;
        if (m_hour > other.m_hour)          return LATER;
        if (m_minute < other.m_minute)      return EARLIER;
        if (m_minute > other.m_minute)      return LATER;
        if (m_second < other.m_second)      return EARLIER;
        if (m_second > other.m_second)      return LATER;
        
        return SAME_TIME;
    }

    /*
    * Set the time with a human readable string
    */
    void setTo(in string time_str)
    {
        if (time_str == "")
        {
            m_year = m_month = m_day = m_hour = m_minute = m_second = 0;
            m_tag = ASN1Tag.NO_OBJECT;
            return;
        }
        
        Vector!string params;
        Vector!ubyte current;
        
        for (size_t j = 0; j != time_str.length; ++j)
        {
            if (isDigit(time_str[j]))
                current ~= time_str[j];
            else
            {
                if (current.length > 0)
                    params.pushBack(cast(string) current[].idup);
                current.clear();
            }
        }
        if (current.length > 0)
            params.pushBack(cast(string) current[].idup);
        
        if (params.length < 3 || params.length > 6)
            throw new InvalidArgument("Invalid time specification " ~ time_str);
        
        m_year      = to!uint(params[0]);
        m_month     = to!uint(params[1]);
        m_day       = to!uint(params[2]);
        m_hour      = (params.length >= 4) ? to!uint(params[3]) : 0;
        m_minute    = (params.length >= 5) ? to!uint(params[4]) : 0;
        m_second    = (params.length == 6) ? to!uint(params[5]) : 0;

        foreach(string param; params[]) delete param;

        m_tag = (m_year >= 2050) ? ASN1Tag.GENERALIZED_TIME : ASN1Tag.UTC_TIME;
        
        if (!passesSanityCheck())
            throw new InvalidArgument("Invalid time specification " ~ time_str);
    }


    /*
    * Set the time with an ISO time format string
    */
    void setTo(in string t_spec, ASN1Tag spec_tag)
    {
        if (spec_tag == ASN1Tag.GENERALIZED_TIME)
        {
            if (t_spec.length != 13 && t_spec.length != 15)
                throw new InvalidArgument("Invalid GeneralizedTime: " ~ t_spec);
        }
        else if (spec_tag == ASN1Tag.UTC_TIME)
        {
            if (t_spec.length != 11 && t_spec.length != 13)
                throw new InvalidArgument("Invalid UTCTime: " ~ t_spec);
        }
        else
        {
            throw new InvalidArgument("Invalid time m_tag " ~ to!string(spec_tag) ~ " val " ~ t_spec);
        }
        
        if (t_spec[t_spec.length-1] != 'Z')
            throw new InvalidArgument("Invalid time encoding: " ~ t_spec);
        
        const size_t YEAR_SIZE = (spec_tag == ASN1Tag.UTC_TIME) ? 2 : 4;
        
        Vector!(string) params;
        Vector!ubyte current;
        current.reserve(YEAR_SIZE);
        foreach (size_t j; 0 .. YEAR_SIZE)
            current ~= t_spec[j];
        params.pushBack(current[].idup);
        current.clear();
        
        for (size_t j = YEAR_SIZE; j != t_spec.length - 1; ++j)
        {
            current ~= t_spec[j];
            if (current.length == 2)
            {
                params.pushBack(current[].idup);
                current.clear();
            }
        }
        
        m_year    = to!uint(params[0]);
        m_month   = to!uint(params[1]);
        m_day     = to!uint(params[2]);
        m_hour    = to!uint(params[3]);
        m_minute  = to!uint(params[4]);
        m_second  = (params.length == 6) ? to!uint(params[5]) : 0;
        m_tag     = spec_tag;
        
        foreach(string param; params[]) delete param;

        if (spec_tag == ASN1Tag.UTC_TIME)
        {
            if (m_year >= 50) m_year += 1900;
            else              m_year += 2000;
        }
        
        if (!passesSanityCheck())
            throw new InvalidArgument("Invalid time specification " ~ t_spec);
    }

    /*
    * Create a X509Time from a time point
    */
    this(in SysTime time)
    {
        m_year   = time.year;
        m_month  = time.month;
        m_day    = time.day;
        m_hour   = time.hour;
        m_minute = time.minute;
        m_second = time.second;
        
        m_tag = (m_year >= 2050) ? ASN1Tag.GENERALIZED_TIME : ASN1Tag.UTC_TIME;

        if (!passesSanityCheck())
            throw new InvalidArgument("Invalid time specification from SysTime");
    }
    
    /*
    * Create an X509Time
    */
    this(in string t_spec, ASN1Tag t)
    {
        m_tag = t;
        logTrace("Time ctor: ", t_spec);
        setTo(t_spec, m_tag);
    }

    /*
    * Create an X509Time
    */
    this(in string time_str)
    {
        logTrace("Time ctor: ", time_str);
        setTo(time_str);
    }

    /*
    * Compare two X509Times for in various ways
    */
    bool opEquals(in X509Time t2) const
    { return (cmp(t2) == 0); }

    int opCmp(in X509Time t2) const
    { return cmp(t2); }


private:
    /*
    * Do a general sanity check on the time
    */
    bool passesSanityCheck() const
    {
        //logTrace("Decoded time: ", readableString());
        if (m_year < 1950 || m_year > 2100)
            return false;
        if (m_month == 0 || m_month > 12)
            return false;
        if (m_day == 0 || m_day > 31)
            return false;
        if (m_hour >= 24 || m_minute > 60 || m_second > 60)
            return false;
        return true;
    }

    uint m_year, m_month, m_day, m_hour, m_minute, m_second;
    ASN1Tag m_tag;
}