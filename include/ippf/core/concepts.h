#pragma once

#include <ippf/core/buffer.h>

#include <concepts>
#include <span>
#include <string_view>
#include <type_traits>

namespace ippf::core {
    using string_view = std::string_view;
    using bytes = std::span<const char>;

    template <class T>
    concept Buffer = std::same_as<T, static_buffer> || std::same_as<T, buffer>;

    template <class T>
    concept Integer = std::is_integral_v<std::decay_t<T>>;

    template <class T>
    concept String = std::same_as<std::decay_t<T>, std::string_view>;

    template <class T>
    concept Bytes = std::same_as<std::decay_t<T>, bytes>;

    template <class T>
    concept Copyable = Integer<T> || String<T> || Bytes<T>;

}  // namespace ippf::core