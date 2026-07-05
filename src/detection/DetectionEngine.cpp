#include "DetectionEngine.hpp"
#include <chrono>
#include <fstream>
#include <nlohmann/json.hpp>

DetectionEngine::DetectionEngine(const std::string& config_path) {
    load_config(config_path);
}

void DetectionEngine::load_defaults() {
    rules_["SUSPICIOUS_TOOL"] = { "SUSPICIOUS_TOOL", "MEDIUM", {"ncat", "/nc"}, {}, true };
    rules_["REVERSE_SHELL"] = { "REVERSE_SHELL", "CRITICAL", {}, {"/sh", "/bash"}, true };
    rules_["RWX_MEMORY"] = { "RWX_MEMORY", "HIGH", {}, {}, true };
    rules_["PTRACE_ATTACH"] = { "PTRACE_ATTACH", "MEDIUM", {}, {}, true };
    
    whitelist_pids_ = { 1 };
    whitelist_comms_ = { "systemd" };
}

void DetectionEngine::load_config(const std::string& config_path) {
    std::lock_guard<std::mutex> lock(mu_);
    
    std::ifstream f(config_path);
    if (!f.is_open()) {
        load_defaults();
        return;
    }
    
    try {
        nlohmann::json j;
        f >> j;
        
        // Load rules
        if (j.contains("rules") && j["rules"].is_array()) {
            for (const auto& r : j["rules"]) {
                RuleConfig cfg;
                cfg.name = r.value("name", "");
                cfg.severity = r.value("severity", "MEDIUM");
                cfg.enabled = r.value("enabled", true);
                
                if (r.contains("match_paths") && r["match_paths"].is_array()) {
                    for (const auto& p : r["match_paths"]) {
                        cfg.match_paths.push_back(p.get<std::string>());
                    }
                }
                if (r.contains("spawn_shells") && r["spawn_shells"].is_array()) {
                    for (const auto& s : r["spawn_shells"]) {
                        cfg.spawn_shells.push_back(s.get<std::string>());
                    }
                }
                rules_[cfg.name] = cfg;
            }
        } else {
            load_defaults();
            return;
        }
        
        // Load whitelists
        if (j.contains("whitelist") && j["whitelist"].is_object()) {
            auto wl = j["whitelist"];
            if (wl.contains("pids") && wl["pids"].is_array()) {
                for (const auto& p : wl["pids"]) {
                    whitelist_pids_.push_back(p.get<uint32_t>());
                }
            }
            if (wl.contains("comms") && wl["comms"].is_array()) {
                for (const auto& c : wl["comms"]) {
                    whitelist_comms_.push_back(c.get<std::string>());
                }
            }
        }
    } catch (...) {
        load_defaults();
    }
}

std::vector<Alert> DetectionEngine::process_event(uint32_t type, uint32_t pid, uint32_t ppid, const std::string& comm, const std::string& filename) {
    std::lock_guard<std::mutex> lock(mu_);
    std::vector<Alert> alerts;
    uint64_t now = std::chrono::system_clock::now().time_since_epoch().count();

    // Check Whitelists first
    for (uint32_t wpid : whitelist_pids_) {
        if (pid == wpid || ppid == wpid) return alerts;
    }
    for (const auto& wcomm : whitelist_comms_) {
        if (comm == wcomm) return alerts;
    }

    // 0 = EXECVE, 1 = CONNECT, 2 = DUP2 (Matching ebpf enum)
    if (type == 0) { // EXECVE
        // Rule: Reverse Shell Heuristic
        auto rev_it = rules_.find("REVERSE_SHELL");
        if (rev_it != rules_.end() && rev_it->second.enabled) {
            bool is_shell = false;
            for (const auto& sh : rev_it->second.spawn_shells) {
                if (filename.find(sh) != std::string::npos) {
                    is_shell = true;
                    break;
                }
            }
            if (is_shell) {
                if (had_connect_.count(pid) || had_connect_.count(ppid) ||
                    had_dup2_.count(pid) || had_dup2_.count(ppid)) {
                    alerts.push_back({
                        "REVERSE_SHELL",
                        rev_it->second.severity,
                        "Potential reverse shell: shell executed by process with network/redirection history",
                        pid,
                        now
                    });
                }
            }
        }
        
        // Rule: Suspicious Binary Execution
        auto susp_it = rules_.find("SUSPICIOUS_TOOL");
        if (susp_it != rules_.end() && susp_it->second.enabled) {
            bool is_suspicious = false;
            for (const auto& pat : susp_it->second.match_paths) {
                if (filename.find(pat) != std::string::npos) {
                    is_suspicious = true;
                    break;
                }
            }
            if (is_suspicious) {
                 alerts.push_back({
                    "SUSPICIOUS_TOOL",
                    susp_it->second.severity,
                    "Suspicious tool execution detected: " + filename,
                    pid,
                    now
                });
            }
        }

        // Clear history for this PID since a new binary has been exec'd
        had_connect_.erase(pid);
        had_dup2_.erase(pid);
    } else if (type == 3 || type == 4) { // MMAP or MPROTECT
        auto mem_it = rules_.find("RWX_MEMORY");
        if (mem_it != rules_.end() && mem_it->second.enabled) {
            alerts.push_back({
                "RWX_MEMORY",
                mem_it->second.severity,
                "Suspicious RWX memory allocation detected",
                pid,
                now
            });
        }
    } else if (type == 5) { // PTRACE
        auto ptr_it = rules_.find("PTRACE_ATTACH");
        if (ptr_it != rules_.end() && ptr_it->second.enabled) {
            alerts.push_back({
                "PTRACE_ATTACH",
                ptr_it->second.severity,
                "Process attempting to ptrace another process (possible injection)",
                pid,
                now
            });
        }
    }

    return alerts;
}

void DetectionEngine::register_connect(uint32_t pid) {
    std::lock_guard<std::mutex> lock(mu_);
    had_connect_.insert(pid);
}

void DetectionEngine::register_dup2(uint32_t pid) {
    std::lock_guard<std::mutex> lock(mu_);
    had_dup2_.insert(pid);
}
