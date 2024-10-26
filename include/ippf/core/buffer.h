#pragma once

#include <ippf/core/concepts.h>
#include <ippf/core/to_x_endian.h>

#include <array>
#include <cstdint>
#include <utility>

namespace ippf::core {
    constexpr int32_t static_buffer_size = 512;
    using static_buffer = std::array<char, static_buffer_size>;

    struct buffer {
        int32_t size{};
        char* data{nullptr};
    };

    template <Copyable T>
    struct copy_t;

    template <Integer T>
    struct copy_t<T> {
        static void apply(T&& val, buffer* buf, int32_t& offset) {
            std::memcpy(buf->data + offset, &val, sizeof(val));
            offset += sizeof(val);
        }
    };

    template <String T>
    struct copy_t<T> {
        static void apply(T&& val, buffer* buf, int32_t& offset) {
            std::memcpy(buf->data + offset, val.data(), val.size());
            offset += static_cast<int32_t>(val.size() + 1);
        }
    };

    template <Copyable T>
    void copy(T&& val, buffer* buf, int32_t& offset) {
        return copy_t<T>::apply(std::forward<T>(val), buf, offset);
    }

    template <Copyable T>
    struct get_t;

    template <Integer T>
    struct get_t<T> {
        static T apply(const buffer* buf, int32_t& offset) {
            T val{};

            std::memcpy(&val, buf->data + offset, sizeof(val));
            offset += sizeof(val);

            return val;
        }
    };

    template <String T>
    struct get_t<T> {
        static T apply(const buffer* buf, int32_t& offset) {
            const char* start = buf->data + offset;
            const char* end = start + 1;

            for (; *end != '\0'; end++) {
            }

            int32_t size = static_cast<int32_t>(end - start);

            auto val = T(start, size);
            offset += size + 1;

            return val;
        }
    };

    template <Copyable T>
    T get(const buffer* buf, int32_t& offset) {
        return get_t<T>::apply(buf, offset);
    }

    template <Copyable T>
    struct easy_get_t;

    template <Integer T>
    struct easy_get_t<T> {
        static T apply(const buffer* buf, int32_t& offset) {
            return to_little_endian(get<T>(buf, offset));
        }
    };

    template <String T>
    struct easy_get_t<T> {
        static T apply(const buffer* buf, int32_t& offset) {
            return get<T>(buf, offset);
        }
    };

    template <Copyable T>
    T easy_get(const buffer* buf, int32_t& offset) {
        return easy_get_t<T>::apply(buf, offset);
    }

}  // namespace ippf::core