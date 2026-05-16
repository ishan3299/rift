#pragma once
#include "Storage.hpp"
#include "Graph.hpp"
#include "Dashboard.hpp"
#include <string>

class Replay {
public:
    Replay(const std::string& db_path, Graph& graph, Dashboard& dashboard);
    void run();

private:
    Storage storage_;
    Graph& graph_;
    Dashboard& dashboard_;
};
