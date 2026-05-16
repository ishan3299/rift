#include "Dashboard.hpp"
#include <thread>
#include <chrono>

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
    auto renderer = Renderer([&]() -> Element {
        std::string tree_text = graph_.dump_text();
        auto tree_win = window(text(" Process Tree "), text(tree_text) | yflex);
        
        Elements log_elements;
        {
            std::lock_guard<std::mutex> lock(mu_);
            for (const auto& l : logs_) {
                log_elements.push_back(text(l));
            }
        }
        auto logs_win = window(text(" Live Telemetry "), vbox(std::move(log_elements)) | yflex);
        
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
        auto threats_win = window(text(" Threat Intelligence "), vbox(std::move(alert_elements)) | yflex);
        
        auto args_win = window(text(" Decoded Arguments "), text("Select an event to view arguments...")) | size(HEIGHT, EQUAL, 5);

        auto main_layout = vbox({
            hbox({
                tree_win | flex,
                logs_win | flex,
                threats_win | flex
            }) | flex,
            args_win
        });

        return main_layout;
    });

    // Refresh thread
    std::thread refresh_thread([&]() {
        while (running_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            screen_.PostEvent(Event::Custom);
        }
    });

    screen_.Loop(renderer);
    running_ = false;
    if (refresh_thread.joinable()) {
        refresh_thread.join();
    }
}
