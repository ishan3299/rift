#include "Replay.hpp"
#include <thread>
#include <chrono>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

Replay::Replay(const std::string& db_path, Graph& graph, Dashboard& dashboard)
    : storage_(db_path), graph_(graph), dashboard_(dashboard) {}

void Replay::run() {
    auto events = storage_.load_events();
    spdlog::info("Loaded {} events for replay", events.size());
    
    std::thread replay_thread([&, events]() {
        for (const auto& e : events) {
            graph_.add_process(e.pid, e.ppid, e.filename, e.ts);
            
            json j;
            j["timestamp"] = e.ts;
            j["pid"] = e.pid;
            j["ppid"] = e.ppid;
            j["uid"] = e.uid;
            j["comm"] = e.comm;
            j["filename"] = e.filename;
            
            dashboard_.add_log("[REPLAY] " + j.dump());
            
            std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Simulate timeline
        }
        spdlog::info("Replay finished.");
    });
    
    dashboard_.run();
    
    if (replay_thread.joinable()) {
        replay_thread.join();
    }
}
