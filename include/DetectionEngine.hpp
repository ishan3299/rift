#pragma once
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <set>
#include "Node.hpp"

struct Alert {
    std::string rule_name;
    std::string severity;
    std::string description;
    uint32_t pid;
    uint64_t timestamp;
};

class DetectionEngine {
public:
    DetectionEngine() = default;
    
    // Process new event and return alerts if any
    std::vector<Alert> process_event(uint32_t type, uint32_t pid, uint32_t ppid, const std::string& comm, const std::string& filename);
    
    // Heuristic: Track if a process has done a network connect and then an execve
    void register_connect(uint32_t pid);
    void register_dup2(uint32_t pid);

private:
    std::set<uint32_t> had_connect_;
    std::set<uint32_t> had_dup2_;
};
