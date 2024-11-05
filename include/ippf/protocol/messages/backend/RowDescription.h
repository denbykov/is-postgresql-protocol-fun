#pragma once

#include <ippf/core/buffer.h>
#include <ippf/core/buffer_op.h>
#include <ippf/core/to_x_endian.h>

#include <cstdint>
#include <memory>

namespace ippf::protocol::messages::backend {
    class RowDescription {
    public:
        RowDescription(core::buffer&& buf) : buf_(std::move(buf)) {}

        RowDescription(const RowDescription& other) = delete;
        RowDescription(RowDescription&&) = default;

        RowDescription operator==(const RowDescription& other) = delete;
        RowDescription& operator=(RowDescription&&) = default;

        const core::buffer* data() const { return &buf_; }

    private:
        core::buffer buf_;
    };
}  // namespace ippf::protocol::messages::backend