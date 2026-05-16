#!/bin/bash
set -e

sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    linux-tools-$(uname -r) \
    linux-tools-common \
    libspdlog-dev \
    libfmt-dev \
    libsqlite3-dev \
    nlohmann-json3-dev \
    libgtest-dev \
    pkg-config
