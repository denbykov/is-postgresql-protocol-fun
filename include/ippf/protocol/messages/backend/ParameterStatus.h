#pragma once

#include <ippf/core/buffer.h>
#include <ippf/core/buffer_op.h>
#include <ippf/core/to_x_endian.h>

#include <cstdint>
#include <memory>

namespace ippf::protocol::messages::backend {
    class ParameterStatus {
    public:
        ParameterStatus(core::buffer&& buf) : buf_(std::move(buf)) {}

        ParameterStatus(const ParameterStatus& other) = delete;
        ParameterStatus(ParameterStatus&&) = default;

        ParameterStatus operator==(const ParameterStatus& other) = delete;
        ParameterStatus& operator=(ParameterStatus&&) = default;

        const core::buffer* data() const { return &buf_; }

    private:
        core::buffer buf_;
    };
}  // namespace ippf::protocol::messages::backend