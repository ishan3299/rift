#pragma once
#include "Node.hpp"
#include <mutex>

class Graph {
public:
    Graph() = default;
    
    // Thread-safe process node addition
    void add_process(uint32_t pid, uint32_t ppid, const std::string& comm, uint64_t ts, uint32_t uts_ns = 0, uint32_t net_ns = 0);
    
    // Dump the current tree state as JSON
    nlohmann::json dump_tree() const;
    
    // Dump text tree
    std::string dump_text() const;

    // Get a flat list of process IDs and names for selection
    std::vector<std::pair<uint32_t, std::string>> get_process_list() const;
    
    // Get detailed info for a specific PID
    nlohmann::json get_node_details(uint32_t pid) const;

private:
    std::string print_node(const std::shared_ptr<Node>& node, const std::string& prefix, bool is_last) const;

    mutable std::mutex mu_;
    std::unordered_map<uint32_t, std::shared_ptr<Node>> process_map_;
    std::vector<std::shared_ptr<Node>> roots_;
    uint64_t next_id_ = 1;
};
