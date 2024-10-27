#pragma once

#include <ippf/core/buffer.h>

#include <concepts>
#include <string_view>

namespace ippf::core {
    template <class T>
    concept Integer = std::is_integral<T>::value;

    template <class T>
    concept String = std::is_convertible_v<T, std::string_view>;

    template <class T>
    concept Copyable = Integer<T> || String<T>;

    template <class T>
    concept Buffer = std::is_convertible_v<T, buffer>;

}  // namespace ippf::core