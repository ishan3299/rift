#include "Graph.hpp"
#include <iostream>
#include <cassert>

void test_graph_selection() {
    std::cout << "[*] Testing Graph Engine selection logic...\n";
    Graph graph;

    // Simulate some processes
    graph.add_process(100, 1, "/usr/bin/init", 1000);
    graph.add_process(200, 100, "/usr/bin/shell", 1001, 555, 666);
    graph.add_process(300, 200, "/usr/bin/malware", 1002);

    // 1. Check process list
    auto list = graph.get_process_list();
    assert(list.size() == 3);
    std::cout << "[+] Found " << list.size() << " processes in list.\n";

    // 2. Check details for a specific PID
    auto details = graph.get_node_details(200);
    assert(!details.empty());
    assert(details["pid"] == 200);
    assert(details["name"] == "/usr/bin/shell");
    assert(details["uts_ns"] == 555);
    assert(details["net_ns"] == 666);
    std::cout << "[+] Process 200 details verified: " << details.dump() << "\n";

    // 3. Check non-existent PID
    auto no_details = graph.get_node_details(999);
    assert(no_details.empty());
    std::cout << "[+] Non-existent process handling verified.\n";

    std::cout << "[✓] Graph Engine selection logic passed!\n";
}

int main() {
    try {
        test_graph_selection();
    } catch (const std::exception& e) {
        std::cerr << "[!] Test failed: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
