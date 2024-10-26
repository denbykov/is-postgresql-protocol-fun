#pragma once

#include <concepts>
#include <string_view>

namespace ippf::core {
    template <class T>
    concept Integer = std::is_integral<T>::value;

    template <class T>
    concept String = std::is_convertible_v<T, std::string_view>;

    template <class T>
    concept Copyable = Integer<T> || String<T>;

}  // namespace ippf::core