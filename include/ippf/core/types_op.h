#pragma once

#include <ippf/core/concepts.h>

namespace ippf::core {
    template <Copyable T>
    struct get_size_t;

    template <String T>
    struct get_size_t<T> {
        static int32_t apply(T&& val) {
            return static_cast<int32_t>(val.size()) + 1;
        }
    };

    template <Bytes T>
    struct get_size_t<T> {
        static int32_t apply(T&& val) {
            return static_cast<int32_t>(val.size());
        }
    };

    template <Integer T>
    struct get_size_t<T> {
        static int32_t apply(T&& val) {
            return static_cast<int32_t>(sizeof(T));
        }
    };

    template <Copyable T>
    int32_t get_size(T&& val) {
        return get_size_t<T>::apply(std::forward<T>(val));
    }

}  // namespace ippf::core