#pragma once
#include <string>
#include <sqlite3.h>
#include <mutex>
#include <vector>

struct ReplayEvent {
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    std::string comm;
    std::string filename;
    uint64_t ts;
};

class Storage {
public:
    Storage(const std::string& db_path);
    ~Storage();
    
    void record_event(uint32_t pid, uint32_t ppid, uint32_t uid, const std::string& comm, const std::string& filename, uint64_t ts);
    std::vector<ReplayEvent> load_events();

private:
    sqlite3* db_;
    std::mutex mu_;
    sqlite3_stmt* insert_stmt_;
};
