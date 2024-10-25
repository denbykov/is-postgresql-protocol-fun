#pragma once

#include <concepts>

namespace ippf::core {
    template <class T>
    concept Integer = std::is_integral<T>::value;

    template <class T>
    concept Byte = Integer<T> && sizeof(T) == 1;

}  // namespace ippf::core