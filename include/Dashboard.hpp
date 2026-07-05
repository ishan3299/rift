#pragma once
#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <vector>
#include <string>
#include <mutex>
#include "Graph.hpp"

struct DashboardAlert {
    std::string rule;
    std::string severity;
    std::string desc;
};

class Dashboard {
public:
    Dashboard(Graph& graph);
    void run();
    void add_log(const std::string& log);
    void add_alert(const std::string& rule, const std::string& severity, const std::string& desc);
    void stop();

private:
    Graph& graph_;
    std::vector<std::string> logs_;
    std::vector<DashboardAlert> alerts_;
    std::mutex mu_;
    ftxui::ScreenInteractive screen_;
    bool running_;
    bool graph_dirty_ = true;
};
