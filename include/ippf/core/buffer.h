#pragma once

#include <cstdint>
#include <vector>

namespace ippf::core {
    constexpr int32_t default_buffer_size = 512;

    using buffer = std::vector<char>;
}  // namespace ippf::core