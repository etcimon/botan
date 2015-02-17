/**
* EAC ASN.1 Objects
* 
* Copyright:
* (C) 2007-2008 FlexSecure GmbH
*      2008-2010 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.cert.cvc.eac_asn_obj;

import botan.constants;
static if (BOTAN_HAS_CARD_VERIFIABLE_CERTIFICATES):

import botan.asn1.asn1_obj;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.utils.rounding;
import botan.utils.charset;
import botan.utils.parsing;
import std.datetime;
import botan.utils.types;
import std.array : Appender;

alias ASN1Car = RefCounted!ASN1CarImpl;
alias ASN1Chr = RefCounted!ASN1ChrImpl;
alias ASN1Cex = RefCounted!ASN1CexImpl;
alias ASN1Ced = RefCounted!ASN1CedImpl;
alias EACTime = RefCounted!EACTimeImpl;

/**
* This class represents CVC EAC Time objects.
* It only models year, month and day. Only limited sanity checks of
* the inputted date value are performed.
*/
class EACTimeImpl : ASN1Object
{
public:

    /*
    * DER encode a EACTime
    */
    override void encodeInto(ref DEREncoder der) const
    {
        der.addObject(m_tag, ASN1Tag.APPLICATION, encodedEacTime());
    }

    /*
    * Decode a BER encoded EACTime
    */
    override void decodeFrom(ref BERDecoder source)
    {
        BERObject obj = source.getNextObject();
        
        if (obj.type_tag != this.m_tag)
            throw new BERDecodingError("Tag mismatch when decoding");
        if (obj.value.length != 6)
        {
            throw new DecodingError("EACTime decoding failed: decoded length was not 6");
        }
        
        try
        {
            uint tmp_year = decTwoDigit(obj.value[0], obj.value[1]);
            uint tmp_mon = decTwoDigit(obj.value[2], obj.value[3]);
            uint tmp_day = decTwoDigit(obj.value[4], obj.value[5]);
            year = tmp_year + 2000;
            month = tmp_mon;
            day = tmp_day;
        }
        catch (InvalidArgument e)
        {
            throw new DecodingError("EACTime decoding failed (" ~ e.msg ~ ")");
        }
        
    }

    /**
    * Return a string representation of the time
    * Returns: date string
    */
    override string toString() const
    {
        if (timeIsSet() == false)
            throw new InvalidState("toString: No time set");
        
        return to!string(year * 10000 + month * 100 + day);
    }


    /**
    * Get a this objects value as a readable formatted string.
    * Returns: date string
    */
    string readableString() const
    {
        if (timeIsSet() == false)
            throw new InvalidState("readableString: No time set");
        
        import std.string : format;
        return format("%04d/%02d/%02d", year, month, day);
    }

    /**
    * Find out whether this object's values have been set.
    * Returns: true if this object's internal values are set
    */
    bool timeIsSet() const
    {
        return (year != 0);
    }

    /**
    * Compare this to another EACTime object.
    * Returns: -1 if this object's date is earlier than
    * other, +1 in the opposite case, and 0 if both dates are
    * equal.
    */
    int cmp(in EACTimeImpl other) const
    {
        if (timeIsSet() == false)
            throw new InvalidState("cmp: No time set");
        
        const int EARLIER = -1, LATER = 1, SAME_TIME = 0;
        
        if (year < other.year)      return EARLIER;
        if (year > other.year)      return LATER;
        if (month < other.month)    return EARLIER;
        if (month > other.month)    return LATER;
        if (day < other.day)        return EARLIER;
        if (day > other.day)        return LATER;
        
        return SAME_TIME;
    }


    /**
    * Set this' value by a human readable string
    * Params:
    *  str = a string in the format "yyyy mm dd",
    * e.g. "2007 08 01"
    */
    void setTo(in string time_str = "")
    {
        if (time_str == "")
        {
            year = month = day = 0;
            return;
        }
        
        Vector!string params;
        Vector!ubyte current;
        current.reserve(time_str.length);
        
        for (uint j = 0; j != time_str.length; ++j)
        {
            if (isDigit(time_str[j]))
                current ~= time_str[j];
            else
            {
                if (current.length > 0)
                    params.pushBack(current[].idup); // fixme: GC allocations
                current.clear();
            }
        }
        if (current.length > 0)
            params.pushBack(current[].idup);
        
        if (params.length != 3)
            throw new InvalidArgument("Invalid time specification " ~ time_str);
        
        year    = to!uint(params[0]);
        month   = to!uint(params[1]);
        day     = to!uint(params[2]);
        
        if (!passesSanityCheck())
            throw new InvalidArgument("Invalid time specification " ~ time_str ~ " => " ~ year.to!string ~ "-" ~ month.to!string ~ "-" ~ day.to!string);
    }

    /**
    * Add the specified number of years to this.
    *
    * Params:
    *  years = the number of years to add
    */
    void addYears(uint years)
    {
        year += years;
    }


    /**
    * Add the specified number of months to this.
    *
    * Params:
    *  months = the number of months to add
    */
    void addMonths(uint months)
    {
        year += months/12;
        month += months % 12;
        if (month > 12)
        {
            year += 1;
            month -= 12;
        }
    }

    /**
    * Get the year value of this objects.
    * Returns: year value
    */
    uint getYear() const { return year; }

    /**
    * Get the month value of this objects.
    * Returns: month value
    */
    uint getMonth() const { return month; }

    /**
    * Get the day value of this objects.
    * Returns: day value
    */
    uint getDay() const { return day; }

    /*
    * Create an EACTime
    */
    this(in SysTime time, ASN1Tag t = (cast(ASN1Tag) 0))
    {
        m_tag = t;
        
        year = time.year;
        month = time.month;
        day    = time.day;
    }

    /*
    * Create an EACTime
    */
    this(in string t_spec = "", ASN1Tag t = (cast(ASN1Tag) 0))
    {
        m_tag = t;
        setTo(t_spec);
    }

    /*
    * Create an EACTime
    */
    this(uint y, uint m, uint d, ASN1Tag t = (cast(ASN1Tag) 0))
    {
        year = y;
        month = m;
        day = d;
        m_tag = t;
    }

    /*
    * Compare two EACTimes for in various ways
    */
    bool opEquals(in EACTimeImpl t2) const
    {
        return (cmp(t2) == 0);
    }
    
    int opCmp(in EACTimeImpl t2) const
    {
        return cmp(t2);
    }

    ~this() {}
private:
    /*
    * make the value an octet string for encoding
    */
    Vector!ubyte encodedEacTime() const
    {
        Vector!ubyte result;
        result.reserve(6);
        result ~= encTwoDigitArr(year).ptr[0..2];
        result ~= encTwoDigitArr(month).ptr[0..2];
        result ~= encTwoDigitArr(day).ptr[0..2];
        return result;
    }

    /*
    * Do a general sanity check on the time
    */
    bool passesSanityCheck() const
    {
        if (year < 2000 || year > 2099)
            return false;
        if (month == 0 || month > 12)
            return false;
        if (day == 0 || day > 31)
            return false;
        
        return true;
    }

    uint year, month, day;
    ASN1Tag m_tag;
}

/**
* This class represents CVC CEDs. Only limited sanity checks of
* the inputted date value are performed.
*/
final class ASN1CedImpl : EACTimeImpl
{
public:
    /**
    * Construct a CED from a string value.
    *
    * Params:
    *  str = a string in the format "yyyy mm dd",
    * e.g. "2007 08 01"
    */
    this(in string str = "") {
        super(str, (cast(ASN1Tag)37));
    }

    /**
    * Construct a CED from a time point
    */
    this(in SysTime time) {
        super(time, (cast(ASN1Tag)37));
    }

    /**
    * Copy constructor (for general EACTime objects).
    *
    * Params:
    *  other = the object to copy from
    */
    this(in EACTime other)
    {
        super(other.getYear(), other.getMonth(), other.getDay(), (cast(ASN1Tag)37));
    }

    this(const ref EACTime other)
    {
        super(other.getYear(), other.getMonth(), other.getDay(), (cast(ASN1Tag)37));
    }

    this(const ref ASN1Ced other) {
        super(other.getYear(), other.getMonth(), other.getDay(), (cast(ASN1Tag)37));
    }
}

/**
* This class represents CVC CEXs. Only limited sanity checks of
* the inputted date value are performed.
*/
final class ASN1CexImpl : EACTimeImpl
{
public:
    /**
    * Construct a CEX from a string value.
    *
    * Params:
    *  str = a string in the format "yyyy mm dd",
    * e.g. "2007 08 01"
    */
    this(in string str = "") 
    {
        super(str, (cast(ASN1Tag)36));
    }

    this(in SysTime time)
    {
        super(time, (cast(ASN1Tag)36));
    }

    this(const ref EACTime other)
    {
        super(other.getYear(), other.getMonth(), other.getDay(), (cast(ASN1Tag)36));
    }

    this(in EACTimeImpl other)
    {
        super(other.getYear(), other.getMonth(), other.getDay(), (cast(ASN1Tag)36));
    }
    
    this(const ref ASN1Cex other) {
        super(other.getYear(), other.getMonth(), other.getDay(), (cast(ASN1Tag)36));
    }
}

/**
* Base class for car/chr of cv certificates.
*/
class ASN1EACString : ASN1Object
{
public:
    /*
    * DER encode an ASN1EACString
    */
    override void encodeInto(ref DEREncoder encoder) const
    {
        string value = iso8859();
        encoder.addObject(tagging(), ASN1Tag.APPLICATION, value);
    }
    
    /*
    * Decode a BER encoded ASN1EACString
    */
    override void decodeFrom(ref BERDecoder source)
    {
        BERObject obj = source.getNextObject();
        
        if (obj.type_tag != this.m_tag)
        {
            Appender!string ss;
            ss ~= "ASN1EACString tag mismatch, tag was " ~ obj.type_tag.to!string ~ " expected " ~ this.m_tag.to!string;
            
            throw new DecodingError(ss.data);
        }

        CharacterSet charset_is = LATIN1_CHARSET;
        
        try
        {
            m_iso_8859_str = transcode(obj.toString(), charset_is, LOCAL_CHARSET);
            m_tag = obj.type_tag;
        }
        catch(InvalidArgument inv_arg)
        {
            throw new DecodingError("ASN1EACString decoding failed: " ~ inv_arg.msg);
        }
    }
    

    /**
    * Get this objects string value.
    * Returns: string value
    */
    string value() const
    {
        return transcode(m_iso_8859_str, LATIN1_CHARSET, LOCAL_CHARSET);
    }

    /**
    * Get this objects string value.
    * Returns: string value in iso8859 encoding
    */
    string iso8859() const
    {
        return m_iso_8859_str;
    }

    /*
    * Return the type of this string object
    */
    ASN1Tag tagging() const
    {
        return m_tag;
    }

    /*
    * Create an ASN1EACString
    */
    this(in string str, ASN1Tag t)
    {
        m_tag = t;
        m_iso_8859_str = transcode(str, LOCAL_CHARSET, LATIN1_CHARSET);
        
        if (!sanityCheck())
            throw new InvalidArgument("ASN1EACString contains illegal characters");
    }

    bool opEquals(in ASN1EACString rhs) const
    {
        return (iso8859() == rhs.iso8859());
    }

    bool opCmp(string op)(in ASN1EACString rhs)
        if (op == "!=")
    {
        return !(lhs == rhs);
    }

    ~this() {}
protected:
    // checks for compliance to the alphabet defined in TR-03110 v1.10, 2007-08-20
    // p. 43
    bool sanityCheck() const
    {
        const(ubyte)* rep = cast(const(ubyte)*) m_iso_8859_str.ptr;
        const size_t rep_len = m_iso_8859_str.length;
        
        foreach (size_t i; 0 .. rep_len)
        {
            if ((rep[i] < 0x20) || ((rep[i] >= 0x7F) && (rep[i] < 0xA0)))
                return false;
        }
        
        return true;
    }

    string m_iso_8859_str;
    ASN1Tag m_tag;
}

/**
* This class represents CARs of CVCs. (String tagged with 2)
*/
final class ASN1CarImpl : ASN1EACString
{
public:
    /**
    * Create a CAR with the specified content.
    *
    * Params:
    *  str = the CAR value
    */
    this(in string str = "")
    {
        super(str, (cast(ASN1Tag)2));

    }

    this(const ref ASN1Car other) {
        super(m_iso_8859_str, m_tag);
    }
        
}

/**
* This class represents CHRs of CVCs (tag 32)
*/
final class ASN1ChrImpl : ASN1EACString
{
public:
    /**
    * Create a CHR with the specified content.
    *
    * Params:
    *  str = the CHR value
    */
    this(in string str = "")
    {
        super(str, (cast(ASN1Tag)32));
    }

    this(const ref ASN1Chr other) {
        super(m_iso_8859_str, m_tag);
    }

}


Vector!ubyte encTwoDigit(uint input)
{
    ubyte[2] res = encTwoDigitArr(input);
    return Vector!ubyte(res.ptr[0 .. 2]);
}

ubyte[2] encTwoDigitArr(uint input)
{
    ubyte[2] result;
    input %= 100;
    if (input < 10)
        result[0] = 0x00;
    else
    {
        uint y_first_pos = roundDown!uint(input, 10) / 10;
        result[0] = cast(ubyte) y_first_pos;
    }
    
    uint y_sec_pos = input % 10;
    result[1] = cast(ubyte) y_sec_pos;
    return result;
}

uint decTwoDigit(ubyte b1, ubyte b2)
{
    uint upper = b1;
    uint lower = b2;
    
    if (upper > 9 || lower > 9)
        throw new InvalidArgument("CVC decTwoDigit value too large");
    
    return upper*10 + lower;
}