/**
* TLS Session Manager
* 
* Copyright:
* (C) 2011 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.session_manager;

import botan.constants;
static if (BOTAN_HAS_TLS):

public import botan.tls.session;
public import botan.tls.server_info;
public import botan.algo_base.sym_algo;
public import botan.rng.rng;
import botan.codec.hex;
import std.datetime;
import core.sync.mutex;
import std.datetime;
import memutils.hashmap;
import botan.tls.magic;

/**
* TLSSessionManager is an interface to systems which can save
* session parameters for supporting session resumption.
*
* Saving sessions is done on a best-effort basis; an implementation is
* allowed to drop sessions due to space constraints.
*
* Implementations should strive to be thread safe
*/
interface TLSSessionManager
{
public:
    /**
    * Try to load a saved session (using session ID)
    * Params:
    *  session_id = the session identifier we are trying to resume
    *  session = will be set to the saved session data (if found),
                or not modified if not found
    * Returns: true if session was modified
    */
    abstract bool loadFromSessionId(const ref Vector!ubyte session_id, ref TLSSession session);

    /**
    * Try to load a saved session (using info about server)
    * Params:
    *  info = the information about the server
    *  session = will be set to the saved session data (if found),
                or not modified if not found
    * Returns: true if session was modified
    */
    abstract bool loadFromServerInfo(in TLSServerInformation info, ref TLSSession session);

    /**
    * Remove this session id from the cache, if it exists
    */
    abstract void removeEntry(const ref Vector!ubyte session_id);


    /**
    * Save a session on a best effort basis; the manager may not in
    * fact be able to save the session for whatever reason; this is
    * not an error. Caller cannot assume that calling save followed
    * immediately by load_from_* will result in a successful lookup.
    *
    * Params:
    *  session = to save
    */
    abstract void save(const ref TLSSession session);

    /**
    * Return the allowed lifetime of a session; beyond this time,
    * sessions are not resumed. Returns 0 if unknown/no explicit
    * expiration policy.
    */
    abstract Duration sessionLifetime() const;

}

/**
* An implementation of TLSSessionManager that does not save sessions at
* all, preventing session resumption.
*/
final class TLSSessionManagerNoop : TLSSessionManager
{
public:
    override bool loadFromSessionId(const ref Vector!ubyte, ref TLSSession)
    { return false; }

    override bool loadFromServerInfo(in TLSServerInformation, ref TLSSession)
    { return false; }

    override void removeEntry(const ref Vector!ubyte) {}

    override void save(const ref TLSSession) {}

    override Duration sessionLifetime() const
    { return Duration.init; }
}

/**
* An implementation of TLSSessionManager that saves values in memory.
*/
final class TLSSessionManagerInMemory : TLSSessionManager
{
public:
    /**
    * Params:
    *  rng = a random number generator
    *  max_sessions = a hint on the maximum number of sessions
    *          to keep in memory at any one time. (If zero, don't cap)
    *  session_lifetime = sessions are expired after this duration has elapsed from initial handshake.
    */
    this(RandomNumberGenerator rng, size_t max_sessions = 1000, Duration session_lifetime = 7200.seconds) 
    {
        m_max_sessions = max_sessions;
        m_session_lifetime = session_lifetime;
        m_rng = rng;
        m_session_key = SymmetricKey(m_rng, 32);
        
    }

    override bool loadFromSessionId(const ref Vector!ubyte session_id, ref TLSSession session)
    {
        
        return loadFromSessionStr(hexEncode(session_id), session);
    }

    override bool loadFromServerInfo(in TLSServerInformation info, ref TLSSession session)
    {
        
        auto str = m_info_sessions.get(info);
        
        if (!str)
            return false;
        
        if (loadFromSessionStr(str, session))
            return true;
        
        /*
        * It existed at one point but was removed from the sessions map,
        * remove m_info_sessions entry as well
        */
        m_info_sessions.remove(info);
        
        return false;
    }

    override void removeEntry(const ref Vector!ubyte session_id)
    {        
        auto key = hexEncode(session_id);
        auto val = m_sessions.get(key);
        
        if (val.length > 0) {
            m_sessions.remove(key);
            removeFromOrdered(key);
        }
    }

    override void save(const ref TLSSession session)
    {
        
        // make some space if too many sessions are found
        if (m_max_sessions != 0)
        {
            int to_remove = cast(int)(m_max_sessions - m_sessions.length);

            foreach (sess_id; m_sessions_ordered[0 .. to_remove])
                m_sessions.remove(sess_id);

            m_sessions_ordered = Vector!string(m_sessions_ordered[to_remove .. $][]);
        }
        
        const string session_id_str = hexEncode(session.sessionId());

        m_sessions[session_id_str] = session.encrypt(m_session_key, m_rng).dupr;
        m_sessions_ordered ~= session_id_str;

        if (session.side() == CLIENT && !session.serverInfo().empty)
            m_info_sessions[session.serverInfo()] = session_id_str;
    }

    override Duration sessionLifetime() const
    { return m_session_lifetime; }

private:
    bool loadFromSessionStr(in string session_str, ref TLSSession session)
    {
        TLSSession sess;
        // assert(lock is held)

        auto val = m_sessions.get(session_str, Array!ubyte.init);
        
        if (val == Array!ubyte.init)
            return false;
        
        try
        {
            sess = TLSSession.decrypt(*val, m_session_key);
        }
        catch (Throwable)
        {
            return false;
        }
        
        // if session has expired, remove it
        const auto now = Clock.currTime();
        
        if (session.startTime() + sessionLifetime() < now)
        {
            m_sessions.remove(session_str);
            removeFromOrdered(session_str);
            return false;
        }

        session = sess.move();
        return true;
    }

    void removeFromOrdered(string val) {

        import std.algorithm : countUntil;
        auto i = m_sessions_ordered[].countUntil(val);
        
        if (i != m_sessions_ordered.length) {
            auto tmp = m_sessions_ordered.ptr[i+1 .. m_sessions_ordered.length];
            m_sessions_ordered[] = Vector!string(m_sessions_ordered[0 .. i]);
            m_sessions_ordered ~= tmp;
        }
        else
            m_sessions_ordered.length = m_sessions_ordered.length - 1;

    }

    size_t m_max_sessions;

    Duration m_session_lifetime;

    RandomNumberGenerator m_rng;
    SymmetricKey m_session_key;

    HashMap!(string, Array!ubyte) m_sessions; // hex(session_id) . session
    Vector!string m_sessions_ordered;
    HashMap!(TLSServerInformation, string) m_info_sessions;
}