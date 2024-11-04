#pragma once

#include <ippf/core/buffer.h>
#include <ippf/core/buffer_op.h>
#include <ippf/core/to_x_endian.h>

#include <cstdint>
#include <memory>

namespace ippf::protocol::messages::backend {
    class AuthenticationOk {
    public:
        AuthenticationOk(core::buffer&& buf) : buf_(std::move(buf)) {}

        AuthenticationOk(const AuthenticationOk& other) = delete;
        AuthenticationOk(AuthenticationOk&&) = default;

        AuthenticationOk operator==(const AuthenticationOk& other) = delete;
        AuthenticationOk& operator=(AuthenticationOk&&) = default;

        const core::buffer* data() const { return &buf_; }

    private:
        core::buffer buf_;
    };
}  // namespace ippf::protocol::messages::backend