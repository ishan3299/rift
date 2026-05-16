#include "DetectionEngine.hpp"
#include <chrono>

std::vector<Alert> DetectionEngine::process_event(uint32_t type, uint32_t pid, uint32_t ppid, const std::string& comm, const std::string& filename) {
    std::vector<Alert> alerts;
    uint64_t now = std::chrono::system_clock::now().time_since_epoch().count();

    // 0 = EXECVE, 1 = CONNECT, 2 = DUP2 (Matching ebpf enum)
    if (type == 0) { // EXECVE
        // Rule: Reverse Shell Heuristic
        // If a process that had a network connect or dup2 now execs a shell
        if (filename.find("/sh") != std::string::npos || filename.find("/bash") != std::string::npos) {
            if (had_connect_.count(pid) || had_connect_.count(ppid)) {
                alerts.push_back({
                    "REVERSE_SHELL",
                    "CRITICAL",
                    "Potential reverse shell: shell executed by process with network history",
                    pid,
                    now
                });
            }
        }
        
        // Rule: Suspicious Binary Execution
        if (filename.find("ncat") != std::string::npos || filename.find("nc ") != std::string::npos) {
             alerts.push_back({
                "SUSPICIOUS_TOOL",
                "MEDIUM",
                "Netcat execution detected",
                pid,
                now
            });
        }
    }

    return alerts;
}

void DetectionEngine::register_connect(uint32_t pid) {
    had_connect_.insert(pid);
}

void DetectionEngine::register_dup2(uint32_t pid) {
    had_dup2_.insert(pid);
}
