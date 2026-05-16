#include <iostream>
#include <csignal>
#include <thread>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>
#include "execve_tracker.skel.h"
#include "Graph.hpp"
#include "Dashboard.hpp"

using json = nlohmann::json;

static volatile bool exiting = false;

struct AppContext {
    Graph* graph;
    Dashboard* dashboard;
};

void sig_handler(int sig) {
    exiting = true;
}

// Ensure this matches the struct in BPF program
struct event_t {
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    char comm[16];
    char filename[256];
    uint64_t ts;
};

static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event_t *e = static_cast<const struct event_t*>(data);
    AppContext* app_ctx = static_cast<AppContext*>(ctx);
    
    // Add to graph engine
    app_ctx->graph->add_process(e->pid, e->ppid, std::string(e->filename), e->ts);

    json j;
    j["timestamp"] = e->ts;
    j["pid"] = e->pid;
    j["ppid"] = e->ppid;
    j["uid"] = e->uid;
    j["comm"] = std::string(e->comm);
    j["filename"] = std::string(e->filename);
    
    app_ctx->dashboard->add_log(j.dump());
    
    return 0;
}

int main(int argc, char **argv) {
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");
    spdlog::info("Starting Rift - Linux Threat Graph Engine");

    struct execve_tracker_bpf *skel = execve_tracker_bpf::open();
    if (!skel) {
        spdlog::error("Failed to open BPF skeleton");
        return 1;
    }

    int err = execve_tracker_bpf::load(skel);
    if (err) {
        spdlog::error("Failed to load BPF skeleton: {}", err);
        execve_tracker_bpf::destroy(skel);
        return 1;
    }

    err = execve_tracker_bpf::attach(skel);
    if (err) {
        spdlog::error("Failed to attach BPF skeleton: {}", err);
        execve_tracker_bpf::destroy(skel);
        return 1;
    }

    Graph graph;
    Dashboard dashboard(graph);
    AppContext app_ctx = { &graph, &dashboard };

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, &app_ctx, NULL);
    if (!rb) {
        spdlog::error("Failed to create ring buffer");
        execve_tracker_bpf::destroy(skel);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    spdlog::info("Listening for execve events...");
    
    // Start eBPF polling thread
    std::thread ebpf_thread([&]() {
        while (!exiting) {
            int err = ring_buffer__poll(rb, 100); /* timeout, ms */
            if (err == -EINTR) {
                break;
            }
            if (err < 0) {
                spdlog::error("Error polling ring buffer: {}", err);
                break;
            }
        }
    });

    // Run TUI loop on main thread (blocks until UI exits)
    dashboard.run();

    // Signal thread to exit
    exiting = true;
    
    if (ebpf_thread.joinable()) {
        ebpf_thread.join();
    }

    ring_buffer__free(rb);
    execve_tracker_bpf::destroy(skel);
    
    return 0;
}