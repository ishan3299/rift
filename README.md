# Rift - Linux Threat Graph Engine

Rift is a production-grade open-source Linux Threat Graph Engine. It operates as a behavioral runtime observability, forensics, and threat intelligence platform for Linux systems.

By leveraging eBPF, Rift captures deep kernel telemetry and transforms low-level system calls into high-level behavioral intelligence, process relationships, and attack graphs with near-zero overhead.

---

## 🚀 Key Features

* **eBPF-Powered Telemetry:** Intercepts kernel events dynamically using low-overhead tracepoints (`execve`, `connect`, `dup2`, `mmap`, `mprotect`, `ptrace`, and `sched_process_exit`).
* **Process Exit & Pruning:** Tracks live process termination. Exited processes are preserved visually as `[exited]` if active child branches exist, and cascade-pruned from memory once the entire subtree terminates.
* **Dynamic Rules Engine (`rules.json`):** Allows runtime configuration of threat signatures, severities, matching paths, and global PID/Comm whitelists without recompiling.
* **Rich TUI Dashboard:** Features a multi-pane FTXUI-based interactive interface with color-coded severity levels (Red for CRITICAL, Salmon for HIGH, Yellow for MEDIUM, Cyan for LOW) and real-time process details.
* **Forensic persistence:** Records event timelines into SQLite databases using performance-optimized WAL (Write-Ahead Logging) mode, enabling offline replaying and forensic analysis.

---

## 🛠️ Project Architecture

```
Kernel Space (eBPF) ➔ Tracepoints Hooked ➔ Ring Buffer (rb)
                                               │
                                               ▼
Userland Agent (C++20) ◄────────────── Poll Callback
         │
         ├─► Graph Engine ➔ Ancestry & Garbage Collection
         ├─► Detection Engine ➔ JSON Rules & Whitelisting
         ├─► Storage Engine ➔ SQLite WAL DB
         └─► TUI Dashboard ➔ FTXUI Screen
```

---

## 📥 Installation

### Dependencies
Rift requires modern Linux kernels and standard build libraries:
```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake clang llvm libbpf-dev linux-headers-$(uname -r) libspdlog-dev libfmt-dev libsqlite3-dev nlohmann-json3-dev pkg-config
```
*(Alternatively, execute the packaged setup helper script: `sudo bash scripts/install_deps.sh`)*

### Build
```bash
mkdir -p build && cd build
cmake ..
make -j$(nproc)
```

---

## ⚙️ Configuration (`rules.json`)
Rift dynamically loads its rule engine and bypass profiles from `rules.json` in the current execution folder:

```json
{
  "rules": [
    {
      "name": "SUSPICIOUS_TOOL",
      "severity": "LOW",
      "match_paths": ["ncat", "/nc"],
      "enabled": true
    },
    {
      "name": "REVERSE_SHELL",
      "severity": "CRITICAL",
      "spawn_shells": ["/sh", "/bash"],
      "enabled": true
    }
  ],
  "whitelist": {
    "pids": [1],
    "comms": ["systemd"]
  }
}
```

---

## 💻 Usage

Run Rift as root to attach the eBPF kernel hooks.

```bash
# Live monitoring (TUI Mode)
sudo ./build/rift

# Record a session to SQLite database
sudo ./build/rift record session.db

# Replay a captured database session offline
./build/rift replay session.db

# Headless mode (CLI output, suited for automation / SIEM pipelines)
sudo ./build/rift --no-tui record session.db
./build/rift --no-tui replay session.db
```

---

## 🧪 Simulating Threats
Use the provided script to generate threat indicators (triggers suspicious memory mmap, Netcat tool calls, and reverse shell simulations):
```bash
python3 scripts/trigger_threats.py
```

---

## 📄 License
MIT License
