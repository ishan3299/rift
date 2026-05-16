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
#include "Storage.hpp"
#include "Replay.hpp"

using json = nlohmann::json;

static volatile bool exiting = false;

struct AppContext {
    Graph* graph;
    Dashboard* dashboard;
    Storage* storage;
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
    
    std::string comm(e->comm);
    std::string filename(e->filename);

    // Add to graph engine
    app_ctx->graph->add_process(e->pid, e->ppid, filename, e->ts);

    // Store in DB if enabled
    if (app_ctx->storage) {
        app_ctx->storage->record_event(e->pid, e->ppid, e->uid, comm, filename, e->ts);
    }

    json j;
    j["timestamp"] = e->ts;
    j["pid"] = e->pid;
    j["ppid"] = e->ppid;
    j["uid"] = e->uid;
    j["comm"] = comm;
    j["filename"] = filename;
    
    app_ctx->dashboard->add_log(j.dump());
    
    return 0;
}

int main(int argc, char **argv) {
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");
    spdlog::info("Starting Rift - Linux Threat Graph Engine");

    std::string mode = "live";
    std::string db_file = "session.db";

    if (argc >= 2) {
        std::string arg1 = argv[1];
        if (arg1 == "record") {
            mode = "record";
            if (argc >= 3) db_file = argv[2];
        } else if (arg1 == "replay") {
            mode = "replay";
            if (argc >= 3) db_file = argv[2];
        } else {
            std::cerr << "Usage: rift [record|replay] [session.db]\n";
            return 1;
        }
    }

    Graph graph;
    Dashboard dashboard(graph);

    if (mode == "replay") {
        spdlog::info("Starting replay mode with DB: {}", db_file);
        Replay replay(db_file, graph, dashboard);
        replay.run();
        return 0;
    }

    Storage* storage_ptr = nullptr;
    if (mode == "record") {
        spdlog::info("Starting record mode with DB: {}", db_file);
        storage_ptr = new Storage(db_file);
    }

    struct execve_tracker_bpf *skel = execve_tracker_bpf::open();
    if (!skel) {
        spdlog::error("Failed to open BPF skeleton");
        if (storage_ptr) delete storage_ptr;
        return 1;
    }

    int err = execve_tracker_bpf::load(skel);
    if (err) {
        spdlog::error("Failed to load BPF skeleton: {}", err);
        execve_tracker_bpf::destroy(skel);
        if (storage_ptr) delete storage_ptr;
        return 1;
    }

    err = execve_tracker_bpf::attach(skel);
    if (err) {
        spdlog::error("Failed to attach BPF skeleton: {}", err);
        execve_tracker_bpf::destroy(skel);
        if (storage_ptr) delete storage_ptr;
        return 1;
    }

    AppContext app_ctx = { &graph, &dashboard, storage_ptr };

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, &app_ctx, NULL);
    if (!rb) {
        spdlog::error("Failed to create ring buffer");
        execve_tracker_bpf::destroy(skel);
        if (storage_ptr) delete storage_ptr;
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
    
    if (storage_ptr) delete storage_ptr;
    
    return 0;
}