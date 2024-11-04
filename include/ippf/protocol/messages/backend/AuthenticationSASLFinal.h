#pragma once

#include <ippf/core/buffer.h>
#include <ippf/core/buffer_op.h>

#include <cstdint>
#include <memory>
#include <string_view>

namespace ippf::protocol::messages::backend {
    class AuthenticationSASLFinal {
    public:
        AuthenticationSASLFinal(core::buffer&& buf) : buf_(std::move(buf)) {}

        AuthenticationSASLFinal(const AuthenticationSASLFinal& other) = delete;
        AuthenticationSASLFinal(AuthenticationSASLFinal&&) = default;

        AuthenticationSASLFinal operator==(
            const AuthenticationSASLFinal& other) = delete;
        AuthenticationSASLFinal& operator=(AuthenticationSASLFinal&&) = default;

        core::bytes get_sasl_data() {
            constexpr int32_t identifier_size = 1;

            int32_t offset = identifier_size;
            int32_t msg_size = core::easy_get<int32_t>(buf_, offset);

            constexpr int32_t header_size = 8;
            int32_t sasl_data_size = msg_size - header_size;

            offset = identifier_size + header_size;

            return core::get<core::bytes>(buf_, sasl_data_size, offset);
        }

        const core::buffer* data() const { return &buf_; }

    private:
        core::buffer buf_;
    };
}  // namespace ippf::protocol::messages::backend
