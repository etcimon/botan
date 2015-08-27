/**
* SQLite wrapper
* 
* Copyright:
* (C) 2012 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.utils.sqlite3.sqlite3;

import botan.constants;
static if (BOTAN_HAS_SQLITE):

import std.exception;
import etc.c.sqlite3;
import botan.utils.types;
import botan.utils.types;
import std.string : toStringz, fromStringz;
import std.datetime;

class sqlite3_database
{
public:
    this(in string db_filename)
    {
        int rc = sqlite3_open(db_filename.toStringz, &m_db);
        
        if (rc)
        {
            const string err_msg = fromStringz(sqlite3_errmsg(m_db)).to!string;
            sqlite3_close(m_db);
            m_db = null;
            throw new Exception("sqlite3_open failed - " ~ err_msg);
        }
    }
    this(in string file);

    ~this()
    {
        if (m_db)
            sqlite3_close(m_db);
        m_db = null;
    }

    size_t rowCount(in string table_name)
    {
        sqlite3_statement stmt = sqlite3_statement(this, "select count(*) from " ~ table_name);
        
        if (stmt.step())
            return stmt.getSizeT(0);
        else
            throw new Exception("Querying size of table " ~ table_name ~ " failed");
    }

    void createTable(in string table_schema)
    {
        char* errmsg = null;
        int rc = sqlite3_exec(m_db, table_schema.toStringz, null, null, &errmsg);
        
        if (rc != SQLITE_OK)
        {
            const string err_msg = fromStringz(errmsg).to!string;
            sqlite3_free(errmsg);
            sqlite3_close(m_db);
            m_db = null;
            throw new Exception("sqlite3_exec for table failed - " ~ err_msg);
        }
    }
private:
    sqlite3* m_db;
}

struct sqlite3_statement
{
public:
    this(sqlite3_database db, in string base_sql)
    {
        int rc = sqlite3_prepare_v2(db.m_db, base_sql.toStringz, -1, &m_stmt, null);
        
        if (rc != SQLITE_OK)
            throw new Exception("sqlite3_prepare failed " ~ base_sql ~ ", code " ~ to!string(rc));
    }

    void bind(int column, in string val)
    {
        int rc = sqlite3_bind_text(m_stmt, column, val.toStringz, -1, SQLITE_TRANSIENT);
        if (rc != SQLITE_OK)
            throw new Exception("sqlite3_bind_text failed, code " ~ to!string(rc));
    }

    void bind(int column, int val)
    {
        int rc = sqlite3_bind_int(m_stmt, column, val);
        if (rc != SQLITE_OK)
            throw new Exception("sqlite3_bind_int failed, code " ~ to!string(rc));
    }

    void bind(int column, SysTime time)
    {
        const int timeval = cast(int)time.toUnixTime();
        bind(column, timeval);
    }

    void bind()(int column, auto const ref Vector!ubyte val)
    {
        int rc = sqlite3_bind_blob(m_stmt, column, cast(void*)val.ptr, cast(int)val.length, SQLITE_TRANSIENT);
        if (rc != SQLITE_OK)
            throw new Exception("sqlite3_bind_text failed, code " ~ to!string(rc));
    }

    Pair!(const(ubyte)*, size_t) getBlob(int column)
    {
        assert(sqlite3_column_type(m_stmt, 0) == SQLITE_BLOB,
                     "Return value is a blob");
        
        const void* session_blob = sqlite3_column_blob(m_stmt, column);
        const int session_blob_size = sqlite3_column_bytes(m_stmt, column);
        
        assert(session_blob_size >= 0, "Blob size is non-negative");
        
        return makePair(cast(const(ubyte)*)(session_blob),
                    cast(size_t)(session_blob_size));
    }

    size_t getSizeT(int column)
    {
        assert(sqlite3_column_type(m_stmt, column) == SQLITE_INTEGER,
                     "Return count is an integer");
        
        const int sessions_int = sqlite3_column_int(m_stmt, column);
        
        assert(sessions_int >= 0, "Expected size_t is non-negative");
        
        return cast(size_t)(sessions_int);
    }

    void spin()
    {
        while (step()) {}
    }

    bool step()
    {
        return (sqlite3_step(m_stmt) == SQLITE_ROW);
    }

    sqlite3_stmt* stmt() { return m_stmt; }

    ~this()
    {
        sqlite3_finalize(m_stmt);
    }
private:
    sqlite3_stmt* m_stmt;
}