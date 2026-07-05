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

void test_process_exit() {
    std::cout << "[*] Testing Graph Engine exit and pruning logic...\n";
    Graph graph;

    // Build parent-child tree: 100 -> 200 -> 300
    graph.add_process(100, 1, "/usr/bin/parent", 1000);
    graph.add_process(200, 100, "/usr/bin/child", 1001);
    graph.add_process(300, 200, "/usr/bin/grandchild", 1002);

    // 1. Remove parent (100)
    // Parent exits but child is active. Parent node should remain as exited.
    graph.remove_process(100);
    auto details_parent = graph.get_node_details(100);
    assert(!details_parent.empty());
    assert(details_parent["exited"] == true);
    std::cout << "[+] Parent marked as exited but preserved due to active descendants.\n";

    // 2. Remove grandchild (300)
    // Grandchild has no children, so it should be immediately pruned.
    graph.remove_process(300);
    auto details_grandchild = graph.get_node_details(300);
    assert(details_grandchild.empty()); // Pruned!
    std::cout << "[+] Grandchild exited and immediately pruned.\n";

    // 3. Remove child (200)
    // Child has exited, and grandchild (300) had already exited.
    // This triggers cascading pruning: child (200) is pruned, which triggers parent (100) pruning since parent had exited too.
    graph.remove_process(200);
    auto details_child = graph.get_node_details(200);
    assert(details_child.empty()); // Pruned!
    auto details_parent_after = graph.get_node_details(100);
    assert(details_parent_after.empty()); // Pruned!
    std::cout << "[+] Child and parent successfully cascade-pruned.\n";

    assert(graph.get_process_list().empty());
    std::cout << "[✓] Graph Engine exit and pruning logic passed!\n";
}

int main() {
    try {
        test_graph_selection();
        test_process_exit();
    } catch (const std::exception& e) {
        std::cerr << "[!] Test failed: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
