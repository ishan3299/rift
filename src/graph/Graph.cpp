#include "Graph.hpp"
#include <sstream>

void Graph::add_process(uint32_t pid, uint32_t ppid, const std::string& comm, uint64_t ts) {
    std::lock_guard<std::mutex> lock(mu_);
    
    auto node = std::make_shared<Node>(next_id_++, NodeType::PROCESS, comm, pid, ppid, ts);
    process_map_[pid] = node;

    // Ancestry Linking
    if (process_map_.find(ppid) != process_map_.end()) {
        process_map_[ppid]->children.push_back(node);
    } else {
        roots_.push_back(node);
    }
}

nlohmann::json Graph::dump_tree() const {
    std::lock_guard<std::mutex> lock(mu_);
    nlohmann::json j = nlohmann::json::array();
    for (const auto& root : roots_) {
        j.push_back(root->to_json());
    }
    return j;
}

std::string Graph::print_node(const std::shared_ptr<Node>& node, const std::string& prefix, bool is_last) const {
    std::ostringstream oss;
    oss << prefix;
    if (is_last) {
        oss << "└── ";
    } else {
        oss << "├── ";
    }
    
    oss << node->name << " (" << node->pid << ")\n";
    
    std::string child_prefix = prefix + (is_last ? "    " : "│   ");
    for (size_t i = 0; i < node->children.size(); ++i) {
        bool child_last = (i == node->children.size() - 1);
        oss << print_node(node->children[i], child_prefix, child_last);
    }
    return oss.str();
}

std::string Graph::dump_text() const {
    std::lock_guard<std::mutex> lock(mu_);
    std::ostringstream oss;
    oss << "Threat Graph Engine - Process Tree\n";
    for (size_t i = 0; i < roots_.size(); ++i) {
        bool is_last = (i == roots_.size() - 1);
        oss << print_node(roots_[i], "", is_last);
    }
    return oss.str();
}
