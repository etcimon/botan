/**
* HTTP utilities
* 
* Copyright:
* (C) 2013 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.utils.http_util.http_util;

import botan.utils.types;
import memutils.hashmap;
import botan.utils.parsing;
import botan.codec.hex;
import std.datetime;
import std.stdio;
import std.conv;
import std.string;
import std.array : Appender;

struct HTTPResponse
{
public:

    this(uint status_code, in string status_message,
         in string _body, HashMapRef!(string, string) headers)
    {
        m_status_code = status_code;
        m_status_message = status_message;
        m_body = _body;
        m_headers = headers;
    }

    uint statusCode() const { return m_status_code; }

    string _body() const { return m_body; }

    const(HashMapRef!(string, string)) headers() const { return m_headers; }

    string statusMessage() const { return m_status_message; }

    void throwUnlessOk()
    {
        if (statusCode() != 200)
            throw new Exception("HTTP error: " ~ statusMessage());
    }

    string toString()
    {
        Appender!string output;
        output ~= "HTTP " ~ statusCode().to!string ~ " " ~ statusMessage() ~ "\n";
        foreach (const ref string k, const ref string v; headers())
            output ~= "Header '" ~ k ~ "' = '" ~ v ~ "'\n";
        output ~= "Body " ~ to!string(_body().length) ~ " bytes:\n";
        output ~= cast(string) _body();
        return output.data;
    }

private:
    uint m_status_code;
    string m_status_message = "Uninitialized";
    string m_body;
    HashMapRef!(string, string) m_headers;
}

HTTPResponse httpSync()(in string verb,
                   in string url,
                   in string content_type,
                   auto const ref Vector!ubyte _body,
                   size_t allowable_redirects)
{
	HashMapRef!(string, string) headers;
	if (!tcp_message_handler)
		throw new Exception("No HTTP Handler Defined");
    const auto protocol_host_sep = url.indexOf("://");
    if (protocol_host_sep == -1)
        throw new Exception("Invalid URL " ~ url);
    const string protocol = url[0 .. protocol_host_sep];

    string buff = url[protocol_host_sep + 3 .. $];

    const auto host_loc_sep = buff.indexOf('/');
    
    string hostname, loc;
    
    if (host_loc_sep == -1)
    {
        hostname = buff[0 .. $];
        loc = "/";
    }
    else
    {
        hostname = buff[0 .. host_loc_sep];
        loc = url[host_loc_sep .. $];
    }
    
    import std.array : Appender;
    Appender!string outbuf;
    
    outbuf ~= verb ~ " " ~ loc ~ " HTTP/1.0\r\n";
    outbuf ~= "Host: " ~ hostname ~ "\r\n";
    
    if (verb == "GET")
    {
        outbuf ~= "Accept: */*\r\n";
        outbuf ~= "Cache-Control: no-cache\r\n";
    }
    else if (verb == "POST")
        outbuf ~= "Content-Length: " ~ _body.length.to!string ~ "\r\n";
    
    if (content_type != "")
        outbuf ~= "Content-Type: " ~ content_type ~ "\r\n";

    outbuf ~= "Connection: close\r\n\r\n";
    outbuf ~= cast(string) _body[];
    
	auto reply = tcp_message_handler(hostname, outbuf.data);

    if (reply.length == 0)
        throw new Exception("No response");

    string http_version;
    uint status_code;
    string status_message;

    ptrdiff_t idx = reply.indexOf(' ');

    if (idx == -1)
        throw new Exception("Not an HTTP response");

    http_version = reply[0 .. idx];

    if (http_version.length == 0 || http_version[0 .. 5] != "HTTP/")
        throw new Exception("Not an HTTP response");

    string reply_front = reply[idx + 1 .. $];
    status_code = parse!uint(reply_front);

    idx = reply.indexOf('\n');

    if (idx == -1)
        throw new Exception("Not an HTTP response");

    status_message = reply[status_code.to!string.length + http_version.to!string.length + 2 .. idx].strip;

    reply = reply[idx + 1 .. $];
    
    string header_line;
    while (true)
    {
        idx = reply.indexOf("\n");
        if (idx < 0)
            throw new Exception("Unterminated HTTP headers");
        header_line = reply[0 .. idx].strip;
        if (!header_line.length)
            break;

        auto sep = header_line.indexOf(':');
        if (sep == -1)
            throw new Exception("Invalid HTTP header " ~ header_line);
        const string key = header_line[0 .. sep].strip;
        const string val = header_line[sep + 1 .. $].strip;
        headers[key] = val;

        reply = reply[idx + 1 .. $];
    }
    
    if (status_code == 301 && headers.get("Location") != "")
    {
        if (allowable_redirects == 0)
            throw new Exception("HTTP redirection count exceeded");
        return GET_sync(headers["Location"], allowable_redirects - 1);
    }
    
    string resp_body = reply[idx + 1 .. $];
    
    const string header_size = headers.get("Content-Length");
    
    if (header_size != "")
    {
        if (resp_body.length != to!size_t(header_size))
            throw new Exception("Content-Length disagreement, header says " ~
                                header_size ~ " got " ~ to!string(resp_body.length));
    }
    
    return HTTPResponse(status_code, status_message, resp_body, headers);
}

string urlEncode(in string input)
{
    import std.array : Appender;
    Appender!string output;
    
    foreach (c; input)
    {
        if (c >= 'A' && c <= 'Z')
            output ~= c;
        else if (c >= 'a' && c <= 'z')
            output ~= c;
        else if (c >= '0' && c <= '9')
            output ~= c;
        else if (c == '-' || c == '_' || c == '.' || c == '~')
            output ~= c;
        else {
            char[2] buf;
            hexEncode(buf.ptr, cast(const(ubyte)*) &c, 1);
            output ~= '%' ~ buf.ptr[0 .. 2];
        }
    }
    
    return output.data;
}

HTTPResponse GET_sync(in string url, size_t allowable_redirects = 1)
{
    return httpSync("GET", url, "", Vector!ubyte(), allowable_redirects);
}

HTTPResponse POST_sync(ALLOC)(in string url, in string content_type,
                                    auto const ref Vector!(ubyte, ALLOC) _body,
                                    size_t allowable_redirects = 1)
{
    return httpSync("POST", url, content_type, _body, allowable_redirects);
}

string delegate(in string hostname, in string message) tcp_message_handler;