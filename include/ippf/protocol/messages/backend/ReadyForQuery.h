#pragma once

#include <ippf/core/buffer.h>
#include <ippf/core/buffer_op.h>
#include <ippf/core/to_x_endian.h>

#include <cstdint>
#include <memory>

namespace ippf::protocol::messages::backend {
    class ReadyForQuery {
    public:
        ReadyForQuery(core::buffer&& buf) : buf_(std::move(buf)) {}

        ReadyForQuery(const ReadyForQuery& other) = delete;
        ReadyForQuery(ReadyForQuery&&) = default;

        ReadyForQuery operator==(const ReadyForQuery& other) = delete;
        ReadyForQuery& operator=(ReadyForQuery&&) = default;

        const core::buffer* data() const { return &buf_; }

    private:
        core::buffer buf_;
    };
}  // namespace ippf::protocol::messages::backend