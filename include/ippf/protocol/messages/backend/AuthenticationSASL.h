#pragma once

#include <ippf/core/buffer.h>
#include <ippf/core/buffer_op.h>
#include <ippf/core/to_x_endian.h>

#include <cstdint>
#include <string_view>

namespace ippf::protocol::messages::backend {
    class AuthenticationSASL {
    public:
        AuthenticationSASL(core::buffer&& buf) : buf_(std::move(buf)) {}

        AuthenticationSASL(const AuthenticationSASL& other) = delete;
        AuthenticationSASL operator==(const AuthenticationSASL& other) = delete;
        AuthenticationSASL operator==(AuthenticationSASL&& other) = delete;

        const core::buffer* data() const { return &buf_; }

    private:
        core::buffer buf_;
    };
}  // namespace ippf::protocol::messages::backend
