#pragma once

#include <ippf/core/buffer.h>
#include <ippf/core/buffer_op.h>
#include <ippf/core/to_x_endian.h>

#include <cstdint>
#include <memory>

namespace ippf::protocol::messages::backend {
    class BackendKeyData {
    public:
        BackendKeyData(core::buffer&& buf) : buf_(std::move(buf)) {}

        BackendKeyData(const BackendKeyData& other) = delete;
        BackendKeyData(BackendKeyData&&) = default;

        BackendKeyData operator==(const BackendKeyData& other) = delete;
        BackendKeyData& operator=(BackendKeyData&&) = default;

        const core::buffer* data() const { return &buf_; }

    private:
        core::buffer buf_;
    };
}  // namespace ippf::protocol::messages::backend