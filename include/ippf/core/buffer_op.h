#pragma once

#include <ippf/core/concepts.h>
#include <ippf/core/to_x_endian.h>

#include <cstdint>
#include <utility>

namespace ippf::core {
    template <Copyable T, Buffer B>
    struct copy_t;

    template <Integer T, Buffer B>
    struct copy_t<T, B> {
        static void apply(T&& val, B* buf, int32_t& offset) {
            std::memcpy(buf->data + offset, &val, sizeof(val));
            offset += sizeof(val);
        }
    };

    template <String T, Buffer B>
    struct copy_t<T, B> {
        static void apply(T&& val, B* buf, int32_t& offset) {
            std::memcpy(buf->data + offset, val.data(), val.size());
            offset += static_cast<int32_t>(val.size() + 1);
        }
    };

    template <Copyable T, Buffer B>
    void copy(T&& val, B* buf, int32_t& offset) {
        return copy_t<T, B>::apply(std::forward<T>(val), buf, offset);
    }

    template <Copyable T, Buffer B>
    struct get_t;

    template <Integer T, Buffer B>
    struct get_t<T, B> {
        static T apply(const B* buf, int32_t& offset) {
            T val{};

            std::memcpy(&val, buf->data + offset, sizeof(val));
            offset += sizeof(val);

            return val;
        }
    };

    template <String T, Buffer B>
    struct get_t<T, B> {
        static T apply(const B* buf, int32_t& offset) {
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

    template <Copyable T, Buffer B>
    T get(const B* buf, int32_t& offset) {
        return get_t<T, B>::apply(buf, offset);
    }

    template <Copyable T, Buffer B>
    struct easy_get_t;

    template <Integer T, Buffer B>
    struct easy_get_t<T, B> {
        static T apply(const B* buf, int32_t& offset) {
            return to_little_endian(get<T, B>(buf, offset));
        }
    };

    template <String T, Buffer B>
    struct easy_get_t<T, B> {
        static T apply(const B* buf, int32_t& offset) {
            return get<T, B>(buf, offset);
        }
    };

    template <Copyable T, Buffer B>
    T easy_get(const B* buf, int32_t& offset) {
        return easy_get_t<T, B>::apply(buf, offset);
    }

}  // namespace ippf::core