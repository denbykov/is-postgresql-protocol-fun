#pragma once

#include <array>
#include <cstdint>
#include <vector>

namespace ippf::core {
    using buffer = std::vector<char>;

    constexpr int32_t static_buffer_size = 512;
    using static_buffer = std::array<char, static_buffer_size>;
}  // namespace ippf::core