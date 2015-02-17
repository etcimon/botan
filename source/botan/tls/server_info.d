/**
* TLS Server Information
* 
* Copyright:
* (C) 2012 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.server_info;

import botan.constants;
static if (BOTAN_HAS_TLS):

import botan.utils.types;

/**
* Represents information known about a TLS server.
*/
struct TLSServerInformation
{
public:
    /**
    * Params:
    *  hostname = the host's DNS name, if known
    *  port = specifies the protocol port of the server (eg for
    *          TCP/UDP). Zero represents unknown.
    */
    this(in string hostname, ushort port = 0)
    {
        m_hostname = hostname; 
        m_port = port; 
    }

    /**
    * Params:
    *  hostname = the host's DNS name, if known
    *  service = is a text string of the service type
    *          (eg "https", "tor", or "git")
    *  port = specifies the protocol port of the server (eg for
    *          TCP/UDP). Zero represents unknown.
    */
    this(in string hostname,
            in string service,
            ushort port = 0)
    {
        m_hostname = hostname;
        m_service = service;
        m_port = port;
    }

    string hostname() const { return m_hostname; }

    string service() const { return m_service; }

    ushort port() const { return m_port; }

    @property bool empty() const { return m_hostname == string.init; }

    bool opEquals(in TLSServerInformation b) const
    {
        return (hostname() == b.hostname()) &&
                (service() == b.service()) &&
                (port() == b.port());
        
    }

    int opCmp(in TLSServerInformation b) const
    {
        if (this == b) return 0;
        else if (isLessThan(b)) return -1;
        else return 1;
    }

    bool isLessThan(in TLSServerInformation b) const
    {
        if (hostname() != b.hostname())
            return (hostname() < b.hostname());
        if (service() != b.service())
            return (service() < b.service());
        if (port() != b.port())
            return (port() < b.port());
        return false; // equal
    }

private:
    string m_hostname, m_service;
    ushort m_port;
}