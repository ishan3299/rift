cmake_minimum_required(VERSION 3.20)
project(Rift VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)
pkg_check_modules(SPDLOG REQUIRED spdlog)
pkg_check_modules(FMT REQUIRED fmt)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)
find_package(nlohmann_json REQUIRED)

# FTXUI via FetchContent
include(FetchContent)
FetchContent_Declare(
  ftxui
  GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI
  GIT_TAG main
)
FetchContent_MakeAvailable(ftxui)

# eBPF Build
set(EBPF_SRC ${CMAKE_SOURCE_DIR}/ebpf/execve_tracker.bpf.c)
set(EBPF_OBJ ${CMAKE_BINARY_DIR}/execve_tracker.bpf.o)
set(EBPF_SKEL ${CMAKE_BINARY_DIR}/execve_tracker.skel.h)

add_custom_command(
    OUTPUT ${EBPF_OBJ}
    COMMAND clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I${CMAKE_SOURCE_DIR}/ebpf -c ${EBPF_SRC} -o ${EBPF_OBJ}
    DEPENDS ${EBPF_SRC}
)

add_custom_command(
    OUTPUT ${EBPF_SKEL}
    COMMAND bpftool gen skeleton ${EBPF_OBJ} > ${EBPF_SKEL}
    DEPENDS ${EBPF_OBJ}
)

add_custom_target(ebpf_skel DEPENDS ${EBPF_SKEL})

# Source files
file(GLOB_RECURSE SRC_FILES 
    "src/*.cpp"
)

# Main executable
add_executable(rift ${SRC_FILES})
add_dependencies(rift ebpf_skel)

# Logic Test
add_executable(test_tui_logic tests/test_tui_logic.cpp src/graph/Graph.cpp)
add_dependencies(test_tui_logic ebpf_skel)
target_include_directories(test_tui_logic PUBLIC ${CMAKE_SOURCE_DIR}/include ${CMAKE_BINARY_DIR})
target_link_libraries(test_tui_logic PRIVATE nlohmann_json::nlohmann_json)

target_include_directories(rift PUBLIC 
    ${CMAKE_SOURCE_DIR}/include 
    ${CMAKE_BINARY_DIR}
    ${CMAKE_SOURCE_DIR}/ebpf
)

target_link_libraries(rift PRIVATE
    ${LIBBPF_LIBRARIES}
    ${SPDLOG_LIBRARIES}
    ${FMT_LIBRARIES}
    ${SQLITE3_LIBRARIES}
    nlohmann_json::nlohmann_json
    ftxui::screen
    ftxui::dom
    ftxui::component
)

target_compile_options(rift PRIVATE -Wall -Wextra -Wpedantic -g)
