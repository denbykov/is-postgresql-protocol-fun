#pragma once

#include <string>

namespace ippf {
    struct connection_data {
        std::string host{};
        std::string port{};
        std::string username{};
        std::string database{};
        std::string password{};
    };
}  // namespace ippf