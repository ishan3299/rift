#pragma once
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <set>
#include "Node.hpp"

struct Alert {
    std::string rule_name;
    std::string severity;
    std::string description;
    uint32_t pid;
    uint64_t timestamp;
};

struct RuleConfig {
    std::string name;
    std::string severity;
    std::vector<std::string> match_paths;
    std::vector<std::string> spawn_shells;
    bool enabled = true;
};

class DetectionEngine {
public:
    DetectionEngine(const std::string& config_path = "rules.json");
    
    // Load config from json file
    void load_config(const std::string& config_path);
    
    // Process new event and return alerts if any
    std::vector<Alert> process_event(uint32_t type, uint32_t pid, uint32_t ppid, const std::string& comm, const std::string& filename);
    
    // Heuristic: Track if a process has done a network connect and then an execve
    void register_connect(uint32_t pid);
    void register_dup2(uint32_t pid);

private:
    mutable std::mutex mu_;
    std::set<uint32_t> had_connect_;
    std::set<uint32_t> had_dup2_;
    
    std::unordered_map<std::string, RuleConfig> rules_;
    std::vector<uint32_t> whitelist_pids_;
    std::vector<std::string> whitelist_comms_;
    
    void load_defaults();
};
