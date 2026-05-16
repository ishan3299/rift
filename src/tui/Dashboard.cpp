#include "Dashboard.hpp"
#include <thread>
#include <chrono>
#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

using namespace ftxui;

Dashboard::Dashboard(Graph& graph)
    : graph_(graph), screen_(ScreenInteractive::Fullscreen()), running_(true) {}

void Dashboard::add_log(const std::string& log) {
    std::lock_guard<std::mutex> lock(mu_);
    logs_.push_back(log);
    if (logs_.size() > 100) {
        logs_.erase(logs_.begin());
    }
    screen_.PostEvent(Event::Custom);
}

void Dashboard::add_alert(const std::string& rule, const std::string& desc) {
    std::lock_guard<std::mutex> lock(mu_);
    alerts_.push_back({rule, desc});
    screen_.PostEvent(Event::Custom);
}

void Dashboard::stop() {
    running_ = false;
    screen_.ExitLoopClosure()();
}

void Dashboard::run() {
    int selected_process = 0;
    std::vector<std::string> process_entries;
    std::vector<uint32_t> process_pids;

    auto menu = Menu(&process_entries, &selected_process);

    auto renderer = Renderer(menu, [&]() -> Element {
        // Update data
        auto list = graph_.get_process_list();
        process_entries.clear();
        process_pids.clear();
        for (const auto& p : list) {
            process_entries.push_back(std::to_string(p.first) + " - " + p.second);
            process_pids.push_back(p.first);
        }

        // Tree view (Left)
        std::string tree_text = graph_.dump_text();
        auto tree_win = window(text(" Process Tree "), text(tree_text) | yflex);
        
        // Process Selector (Center-Left)
        auto selector_win = window(text(" Select Process (↑/↓) "), menu->Render() | vscroll_indicator | frame | yflex);

        // Details (Center-Right)
        Element details_content = text("Select a process to view details...");
        if (selected_process >= 0 && selected_process < (int)process_pids.size()) {
            auto details = graph_.get_node_details(process_pids[selected_process]);
            if (!details.empty()) {
                Elements lines;
                for (auto it = details.begin(); it != details.end(); ++it) {
                    if (it.key() == "children") continue;
                    lines.push_back(hbox({
                        text(it.key() + ": ") | bold | color(Color::Cyan),
                        text(it.value().dump())
                    }));
                }
                details_content = vbox(std::move(lines));
            }
        }
        auto details_win = window(text(" Task Details "), details_content | yflex);

        // Telemetry (Right)
        Elements log_elements;
        {
            std::lock_guard<std::mutex> lock(mu_);
            for (const auto& l : logs_) {
                log_elements.push_back(text(l));
            }
        }
        auto logs_win = window(text(" Live Telemetry "), vbox(std::move(log_elements)) | vscroll_indicator | frame | yflex);
        
        // Alerts (Bottom)
        Elements alert_elements;
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (alerts_.empty()) {
                alert_elements.push_back(text("No active threats detected.") | center | color(Color::Green));
            } else {
                for (const auto& a : alerts_) {
                    alert_elements.push_back(hbox({
                        text("[" + a.first + "] ") | bold | color(Color::Red),
                        text(a.second)
                    }));
                }
            }
        }
        auto threats_win = window(text(" Threat Intelligence "), vbox(std::move(alert_elements)) | frame | yflex) | size(HEIGHT, EQUAL, 8);

        auto main_layout = vbox({
            hbox({
                tree_win | flex,
                selector_win | size(WIDTH, EQUAL, 30),
                details_win | flex,
                logs_win | flex
            }) | flex,
            threats_win,
            hbox({
                text(" [q] Quit | [↑/↓] Select Process | [Tab] Switch Focus ")
            })
        });

        return main_layout;
    });

    auto component = CatchEvent(renderer, [&](Event event) {
        if (event == Event::Character('q') || event == Event::Escape) {
            screen_.ExitLoopClosure()();
            return true;
        }
        return false;
    });

    // Refresh thread
    std::thread refresh_thread([&]() {
        while (running_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            screen_.PostEvent(Event::Custom);
        }
    });

    screen_.Loop(component);
    running_ = false;
    if (refresh_thread.joinable()) {
        refresh_thread.join();
    }
}
