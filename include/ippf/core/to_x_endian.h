#pragma once

#include <cstdint>
#include <type_traits>

namespace ippf::core {

    template <typename T>
    T to_big_endian(T in) {
        static_assert(std::is_integral_v<T>, "T must be an integral type");

        if constexpr (sizeof(T) == 1) {
            return in;
        } else if constexpr (sizeof(T) == 2) {
            return (in >> 8) | (in << 8);
        } else if constexpr (sizeof(T) == 4) {
            return ((in >> 24) & 0x000000FF) | ((in >> 8) & 0x0000FF00) |
                   ((in << 8) & 0x00FF0000) | ((in << 24) & 0xFF000000);
        } else if constexpr (sizeof(T) == 8) {
            return ((in >> 56) & 0x00000000000000FF) |
                   ((in >> 40) & 0x000000000000FF00) |
                   ((in >> 24) & 0x0000000000FF0000) |
                   ((in >> 8) & 0x00000000FF000000) |
                   ((in << 8) & 0x000000FF00000000) |
                   ((in << 24) & 0x0000FF0000000000) |
                   ((in << 40) & 0x00FF000000000000) |
                   ((in << 56) & 0xFF00000000000000);
        } else {
            static_assert(sizeof(T) <= 8, "Unsupported integer size");
        }
    }

    template <typename T>
    T convert_to_little_endian(T in) {
        static_assert(std::is_integral_v<T>, "T must be an integral type");

        if constexpr (sizeof(T) == 1) {
            return in;
        } else if constexpr (sizeof(T) == 2) {
            return (in << 8) | (in >> 8);
        } else if constexpr (sizeof(T) == 4) {
            return ((in << 24) & 0xFF000000) | ((in << 8) & 0x00FF0000) |
                   ((in >> 8) & 0x0000FF00) | ((in >> 24) & 0x000000FF);
        } else if constexpr (sizeof(T) == 8) {
            return ((in << 56) & 0xFF00000000000000) |
                   ((in << 40) & 0x00FF000000000000) |
                   ((in << 24) & 0x0000FF0000000000) |
                   ((in << 8) & 0x000000FF00000000) |
                   ((in >> 8) & 0x00000000FF000000) |
                   ((in >> 24) & 0x0000000000FF0000) |
                   ((in >> 40) & 0x000000000000FF00) |
                   ((in >> 56) & 0x00000000000000FF);
        } else {
            static_assert(sizeof(T) <= 8, "Unsupported integer size");
        }
    }

}  // namespace ippf::core