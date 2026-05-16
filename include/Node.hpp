#pragma once
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <nlohmann/json.hpp>

enum class NodeType {
    PROCESS,
    FILE,
    SOCKET,
    CONTAINER,
    NAMESPACE
};

struct Node {
    uint64_t id;
    NodeType type;
    std::string name;
    std::string path;
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    uint64_t timestamp;
    
    std::vector<std::shared_ptr<Node>> children;

    Node(uint64_t id, NodeType type, std::string name, uint32_t pid, uint32_t ppid, uint64_t ts)
        : id(id), type(type), name(std::move(name)), pid(pid), ppid(ppid), timestamp(ts) {}

    nlohmann::json to_json() const {
        nlohmann::json j;
        j["id"] = id;
        j["name"] = name;
        j["pid"] = pid;
        j["ppid"] = ppid;
        j["timestamp"] = timestamp;
        
        nlohmann::json child_json = nlohmann::json::array();
        for (const auto& child : children) {
            child_json.push_back(child->to_json());
        }
        if (!child_json.empty()) {
            j["children"] = child_json;
        }
        return j;
    }
};
