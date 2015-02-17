/**
* SQLite3 TLS Session Manager
* 
* Copyright:
* (C) 2012 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.session_manager_sqlite;

import botan.constants;
static if (BOTAN_HAS_TLS && BOTAN_HAS_SQLITE):

import botan.tls.session_manager;
import botan.utils.sqlite3.sqlite3;
import botan.libstate.lookup;
import botan.codec.hex;
import botan.utils.loadstor;
import botan.utils.mem_ops;
import std.datetime;


/**
* An implementation of TLSSessionManager that saves values in a SQLite3
* database file, with the session data encrypted using a passphrase.
*
* Notes:
* For clients, the hostnames associated with the saved
* sessions are stored in the database in plaintext. This may be a
* serious privacy risk in some situations.
*/
final class TLSSessionManagerSQLite : TLSSessionManager
{
public:
    /**
    * Params:
    *  passphrase = used to encrypt the session data
    *  rng = a random number generator
    *  db_filename = filename of the SQLite database file.
                The table names tls_sessions and tls_sessions_metadata
                will be used
    *  max_sessions = a hint on the maximum number of sessions
    *          to keep in memory at any one time. (If zero, don't cap)
    *  session_lifetime = sessions are expired after this duration has elapsed from initial handshake.
    */
    this(in string passphrase,
           RandomNumberGenerator rng,
           in string db_filename,
           size_t max_sessions = 1000,
           Duration session_lifetime = 7200.seconds) 
    {
        m_rng = rng;
        m_max_sessions = max_sessions;
        m_session_lifetime = session_lifetime;
        m_db = new sqlite3_database(db_filename);

        m_db.createTable(
            "create table if not exists tls_sessions "
            ~ "("
            ~ "session_id TEXT PRIMARY KEY, "
            ~ "session_start INTEGER, "
            ~ "hostname TEXT, "
            ~ "hostport INTEGER, "
            ~ "session BLOB"
            ~ ")");
        
        m_db.createTable(
            "create table if not exists tls_sessions_metadata "
            ~ "("
            ~ "passphrase_salt BLOB, "
            ~ "passphrase_iterations INTEGER, "
            ~ "passphrase_check INTEGER "
            ~ ")");
        
        const size_t salts = m_db.rowCount("tls_sessions_metadata");
        
        if (salts == 1)
        {
            // existing db
            sqlite3_statement stmt = sqlite3_statement(m_db, "select * from tls_sessions_metadata");
            
            if (stmt.step())
            {
                Pair!(const(ubyte)*, size_t) salt = stmt.getBlob(0);
                const size_t iterations = stmt.getSizeT(1);
                const size_t check_val_db = stmt.getSizeT(2);
                
                size_t check_val_created;
                m_session_key = deriveKey(passphrase,
                                           salt.first,
                                           salt.second,
                                           iterations,
                                           check_val_created);
                
                if (check_val_created != check_val_db)
                    throw new Exception("TLSSession database password not valid");
            }
        }
        else
        {
            // maybe just zap the salts + sessions tables in this case?
            if (salts != 0)
                throw new Exception("Seemingly corrupted database, multiple salts found");
            
            // new database case
            
            Vector!ubyte salt = unlock(rng.randomVec(16));
            const size_t iterations = 256 * 1024;
            size_t check_val = 0;
            
            m_session_key = deriveKey(passphrase, salt.ptr, salt.length, iterations, check_val);
            
            sqlite3_statement stmt = sqlite3_statement(m_db, "insert into tls_sessions_metadata"
                                                                ~ " values(?1, ?2, ?3)");
            
            stmt.bind(1, salt);
            stmt.bind(2, iterations);
            stmt.bind(3, cast(int) check_val);
            
            stmt.spin();
        }
    }

    ~this()
    {
        destroy(m_db);
    }

    override bool loadFromSessionId(const ref Vector!ubyte session_id, ref TLSSession session)
    {
        sqlite3_statement stmt = sqlite3_statement(m_db, "select session from tls_sessions where session_id = ?1");
        
        stmt.bind(1, hexEncode(session_id));
        
        while (stmt.step())
        {
            Pair!(const(ubyte)*, size_t) blob = stmt.getBlob(0);
            
            try
            {
                session = TLSSession.decrypt(blob.first, blob.second, m_session_key);
                return true;
            }
            catch (Throwable)
            {
            }
        }
        
        return false;
    }

    override bool loadFromServerInfo(in TLSServerInformation server,
                                     ref TLSSession session)
    {
        sqlite3_statement stmt = sqlite3_statement(m_db, "select session from tls_sessions"
                                                       ~ " where hostname = ?1 and hostport = ?2"
                                                       ~ " order by session_start desc");
        
        stmt.bind(1, server.hostname());
        stmt.bind(2, server.port());
        
        while (stmt.step())
        {
            Pair!(const(ubyte)*, size_t) blob = stmt.getBlob(0);
            
            try
            {
                session = TLSSession.decrypt(blob.first, blob.second, m_session_key);
                return true;
            }
            catch (Throwable)
            {
            }
        }
        
        return false;
    }

    override void removeEntry(const ref Vector!ubyte session_id)
    {
        sqlite3_statement stmt = sqlite3_statement(m_db, "delete from tls_sessions where session_id = ?1");
        
        stmt.bind(1, hexEncode(session_id));
        
        stmt.spin();
    }

    override void save(const ref TLSSession session)
    {
        sqlite3_statement stmt = sqlite3_statement(m_db, "insert or replace into tls_sessions"
                               ~ " values(?1, ?2, ?3, ?4, ?5)");
        
        stmt.bind(1, hexEncode(session.sessionId()));
        stmt.bind(2, session.startTime());
        stmt.bind(3, session.serverInfo().hostname());
        stmt.bind(4, session.serverInfo().port());
        stmt.bind(5, session.encrypt(m_session_key, m_rng));
        
        stmt.spin();
        
        pruneSessionCache();
    }

    override Duration sessionLifetime() const
    { return m_session_lifetime; }

private:
    @disable this(const ref TLSSessionManagerSQLite);
    @disable TLSSessionManagerSQLite opAssign(const ref TLSSessionManagerSQLite);

    void pruneSessionCache()
    {
        sqlite3_statement remove_expired = sqlite3_statement(m_db, "delete from tls_sessions where session_start <= ?1");
        
        remove_expired.bind(1, Clock.currTime() - m_session_lifetime);
        
        remove_expired.spin();
        
        const size_t sessions = m_db.rowCount("tls_sessions");
        
        if (sessions > m_max_sessions)
        {
            sqlite3_statement remove_some = sqlite3_statement(m_db, "delete from tls_sessions where session_id in "
                                          ~ "(select session_id from tls_sessions limit ?1)");
            
            remove_some.bind(1, cast(int)(sessions - m_max_sessions));
            remove_some.spin();
        }
    }

    SymmetricKey m_session_key;
    RandomNumberGenerator m_rng;
    size_t m_max_sessions;
    Duration m_session_lifetime;
    sqlite3_database m_db;
}

SymmetricKey deriveKey(in string passphrase,
                        const(ubyte)* salt,
                        size_t salt_len,
                        size_t iterations,
                        ref size_t check_val)
{
    Unique!PBKDF pbkdf = getPbkdf("PBKDF2(SHA-512)");
    
    SecureVector!ubyte x = pbkdf.deriveKey(32 + 2, passphrase, salt, salt_len, iterations).bitsOf();
    
    check_val = make_ushort(x[0], x[1]);
    return SymmetricKey(&x[2], x.length - 2);
}