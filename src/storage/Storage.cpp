#include "Storage.hpp"
#include <spdlog/spdlog.h>
#include <stdexcept>

Storage::Storage(const std::string& db_path) : db_(nullptr), insert_stmt_(nullptr) {
    if (sqlite3_open(db_path.c_str(), &db_) != SQLITE_OK) {
        throw std::runtime_error("Failed to open SQLite database");
    }

    // Optimize performance: use WAL and normal synchronization to prevent disk bottlenecks
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;", nullptr, nullptr, nullptr);

    const char* schema = R"(
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pid INTEGER,
            ppid INTEGER,
            uid INTEGER,
            comm TEXT,
            filename TEXT,
            ts INTEGER
        );
    )";

    char* err_msg = nullptr;
    if (sqlite3_exec(db_, schema, nullptr, nullptr, &err_msg) != SQLITE_OK) {
        spdlog::error("SQL error: {}", err_msg);
        sqlite3_free(err_msg);
        throw std::runtime_error("Failed to create table");
    }

    const char* insert_sql = "INSERT INTO events (pid, ppid, uid, comm, filename, ts) VALUES (?, ?, ?, ?, ?, ?)";
    if (sqlite3_prepare_v2(db_, insert_sql, -1, &insert_stmt_, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare insert statement");
    }
}

Storage::~Storage() {
    if (insert_stmt_) {
        sqlite3_finalize(insert_stmt_);
    }
    if (db_) {
        sqlite3_close(db_);
    }
}

void Storage::record_event(uint32_t pid, uint32_t ppid, uint32_t uid, const std::string& comm, const std::string& filename, uint64_t ts) {
    std::lock_guard<std::mutex> lock(mu_);
    sqlite3_bind_int(insert_stmt_, 1, pid);
    sqlite3_bind_int(insert_stmt_, 2, ppid);
    sqlite3_bind_int(insert_stmt_, 3, uid);
    sqlite3_bind_text(insert_stmt_, 4, comm.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(insert_stmt_, 5, filename.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(insert_stmt_, 6, ts);

    if (sqlite3_step(insert_stmt_) != SQLITE_DONE) {
        spdlog::error("Failed to insert event into database");
    }
    sqlite3_reset(insert_stmt_);
}

std::vector<ReplayEvent> Storage::load_events() {
    std::vector<ReplayEvent> events;
    std::lock_guard<std::mutex> lock(mu_);
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT pid, ppid, uid, comm, filename, ts FROM events ORDER BY ts ASC";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("Failed to prepare select statement");
        return events;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ReplayEvent e;
        e.pid = sqlite3_column_int(stmt, 0);
        e.ppid = sqlite3_column_int(stmt, 1);
        e.uid = sqlite3_column_int(stmt, 2);
        e.comm = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        e.filename = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        e.ts = sqlite3_column_int64(stmt, 5);
        events.push_back(e);
    }

    sqlite3_finalize(stmt);
    return events;
}
