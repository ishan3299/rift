#pragma once
#include <string>
#include <fstream>
#include <regex>

class ContainerUtils {
public:
    static std::string get_container_id(uint32_t pid) {
        std::string path = "/proc/" + std::to_string(pid) + "/cgroup";
        std::ifstream file(path);
        if (!file.is_open()) return "";

        static const std::regex docker_regex(".*/docker/([a-f0-9]{64}).*");
        static const std::regex k8s_regex(".*/kubepods/.*-([a-f0-9]{64}).*");

        std::string line;
        while (std::getline(file, line)) {
            std::smatch match;

            if (std::regex_search(line, match, docker_regex) || std::regex_search(line, match, k8s_regex)) {
                if (match.size() > 1) {
                    return match[1].str().substr(0, 12); // Return short ID
                }
            }
        }
        return "";
    }
};
