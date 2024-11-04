#pragma once

#include <ippf/core/buffer.h>
#include <ippf/core/buffer_op.h>

#include <cstdint>
#include <memory>
#include <string_view>

namespace ippf::protocol::messages::backend {
    class AuthenticationSASLContinue {
    public:
        AuthenticationSASLContinue(core::buffer&& buf) : buf_(std::move(buf)) {}

        AuthenticationSASLContinue(const AuthenticationSASLContinue& other) =
            delete;
        AuthenticationSASLContinue(AuthenticationSASLContinue&&) = default;

        AuthenticationSASLContinue operator==(
            const AuthenticationSASLContinue& other) = delete;
        AuthenticationSASLContinue& operator=(AuthenticationSASLContinue&&) =
            default;

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
