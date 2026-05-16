#pragma once
#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <vector>
#include <string>
#include <mutex>
#include "Graph.hpp"

class Dashboard {
public:
    Dashboard(Graph& graph);
    void run();
    void add_log(const std::string& log);
    void add_alert(const std::string& rule, const std::string& desc);
    void stop();

private:
    Graph& graph_;
    std::vector<std::string> logs_;
    std::vector<std::pair<std::string, std::string>> alerts_;
    std::mutex mu_;
    ftxui::ScreenInteractive screen_;
    bool running_;
};
