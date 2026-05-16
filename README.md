# Rift - Linux Threat Graph Engine

Rift is a production-grade open-source Linux Threat Graph Engine. It operates as a behavioral runtime observability and threat intelligence platform for Linux systems.

By leveraging eBPF, Rift captures deep kernel telemetry and transforms low-level system calls into high-level behavioral intelligence, process relationships, and attack graphs.

## Features (Phase 1)
- **eBPF-based Telemetry:** Collects `execve` events directly from the kernel using eBPF tracepoints.
- **Structured Logging:** Emits JSON-formatted telemetry for SIEM integration and offline analysis.
- **High Performance:** Utilizes eBPF ring buffers for high-throughput, low-overhead event processing.
- **Modern Architecture:** Built with C++20, `libbpf`, `spdlog`, and `fmt`.

## Project Architecture

- **Kernel Layer:** eBPF tracepoints monitor system behavior (e.g., `sys_enter_execve`).
- **Userland Collector:** The C++ agent polls eBPF ring buffers to ingest raw telemetry.
- **Processing Pipeline:** Enriches and formats events (currently JSON output, with a graph engine in development).

## Installation

### Dependencies
Rift requires modern Linux features and development tools.
```bash
sudo apt-get install build-essential cmake clang llvm libbpf-dev linux-headers-$(uname -r) libspdlog-dev libfmt-dev libsqlite3-dev nlohmann-json3-dev pkg-config
```

### Build
```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

## Usage
Run Rift as root to start telemetry collection. By default, it launches an interactive TUI.

```bash
# Live monitoring (TUI)
sudo ./rift

# Record a session to a database (TUI)
sudo ./rift record session.db

# Replay a captured session (TUI)
./rift replay session.db

# Headless mode (for automation/verification)
sudo ./rift --no-tui record session.db
./rift --no-tui replay session.db
```

## Roadmap
- [x] **Phase 1:** Telemetry Foundation (eBPF, JSON output, structured logs)
- [x] **Phase 2:** Graph Engine (Process relationship tracking, ancestry graphing)
- [x] **Phase 3:** Real-time TUI (Interactive terminal UI for threat monitoring)
- [ ] **Phase 4:** Detection Engine (Behavioral correlation, attack signatures)
- [x] **Phase 5:** Storage & Replay (SQLite persistence, session recording)
- [ ] **Phase 6:** Container Awareness (Docker/K8s correlation)
- [ ] **Phase 7:** Advanced Memory Detection (RWX, unbacked execution)

## License
MIT License
