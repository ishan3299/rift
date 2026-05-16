#include "Graph.hpp"
#include "ContainerUtils.hpp"
#include <sstream>

void Graph::add_process(uint32_t pid, uint32_t ppid, const std::string& comm, uint64_t ts, uint32_t uts_ns, uint32_t net_ns) {
    std::lock_guard<std::mutex> lock(mu_);
    
    auto node = std::make_shared<Node>(next_id_++, NodeType::PROCESS, comm, pid, ppid, ts);
    node->uts_ns = uts_ns;
    node->net_ns = net_ns;
    node->container_id = ContainerUtils::get_container_id(pid);

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
    
    oss << node->name << " (" << node->pid << ")";
    if (!node->container_id.empty()) {
        oss << " [CID: " << node->container_id << "]";
    }
    oss << "\n";
    
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

std::vector<std::pair<uint32_t, std::string>> Graph::get_process_list() const {
    std::lock_guard<std::mutex> lock(mu_);
    std::vector<std::pair<uint32_t, std::string>> list;
    for (const auto& [pid, node] : process_map_) {
        list.push_back({pid, node->name});
    }
    return list;
}

nlohmann::json Graph::get_node_details(uint32_t pid) const {
    std::lock_guard<std::mutex> lock(mu_);
    if (process_map_.find(pid) != process_map_.end()) {
        auto node = process_map_.at(pid);
        nlohmann::json j = node->to_json();
        j["uts_ns"] = node->uts_ns;
        j["net_ns"] = node->net_ns;
        return j;
    }
    return {};
}
