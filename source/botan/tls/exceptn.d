/**
* TLS Exceptions
* 
* Copyright:
* (C) 2004-2006 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.exceptn;

import botan.constants;
static if (BOTAN_HAS_TLS):

import botan.utils.exceptn;
import botan.tls.alert;

/**
* Exception Base Class
*/
class TLSException : Exception
{
public:
    TLSAlertType type() const nothrow { return m_alert_type; }

    this(TLSAlertType type, in string err_msg = "Unknown error") {
        m_alert_type = type;
        super(err_msg);
    }

private:
    TLSAlertType m_alert_type;
}

/**
* TLS_Unexpected_Message Exception
*/
class TLSUnexpectedMessage : TLSException
{
    this(in string err) 
    {
        super(TLSAlert.UNEXPECTED_MESSAGE, err);
    }
}