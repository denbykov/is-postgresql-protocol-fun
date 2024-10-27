#pragma once

#include <cstdint>

namespace ippf::core {
    struct buffer {
        int32_t size{};
        char* data{nullptr};
    };

    struct static_buffer {
        static constexpr int32_t size = 512;
        char data[size];
    };
}  // namespace ippf::core