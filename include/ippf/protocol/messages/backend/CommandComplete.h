#pragma once

#include <ippf/core/buffer.h>
#include <ippf/core/buffer_op.h>
#include <ippf/core/to_x_endian.h>

#include <cstdint>
#include <memory>

namespace ippf::protocol::messages::backend {
    class CommandComplete {
    public:
        CommandComplete(core::buffer&& buf) : buf_(std::move(buf)) {}

        CommandComplete(const CommandComplete& other) = delete;
        CommandComplete(CommandComplete&&) = default;

        CommandComplete operator==(const CommandComplete& other) = delete;
        CommandComplete& operator=(CommandComplete&&) = default;

        const core::buffer* data() const { return &buf_; }

    private:
        core::buffer buf_;
    };
}  // namespace ippf::protocol::messages::backend