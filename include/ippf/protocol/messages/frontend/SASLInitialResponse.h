#pragma once

#include <ippf/core/buffer.h>
#include <ippf/core/buffer_op.h>
#include <ippf/core/to_x_endian.h>

#include <cstdint>
#include <memory>
#include <string_view>
#include <vector>

namespace ippf::protocol::messages::frontend {
    class SASLInitialResponse {
    public:
        SASLInitialResponse(const std::string_view mechanism,
                            const std::string_view initial_response) {
            int32_t size{};
            int32_t ir_size{static_cast<int32_t>(initial_response.size() + 1)};

            size += sizeof(identifier);
            size += sizeof(size);
            size += static_cast<int32_t>(mechanism.size() + 1);
            size += sizeof(ir_size);
            size += ir_size;

            buf_ = std::make_shared<core::buffer>(size, 0);

            int32_t offset{0};

            core::copy(core::to_big_endian(identifier), *buf_.get(), offset);
            core::copy(core::to_big_endian(size), *buf_.get(), offset);
            core::copy(mechanism, *buf_.get(), offset);
            core::copy(core::to_big_endian(ir_size), *buf_.get(), offset);
            core::copy(initial_response, *buf_.get(), offset);
        }

        SASLInitialResponse(const SASLInitialResponse& other) = delete;
        SASLInitialResponse operator==(const SASLInitialResponse& other) =
            delete;
        SASLInitialResponse operator==(SASLInitialResponse&& other) = delete;

        std::shared_ptr<core::buffer> data() const { return buf_; }

    private:
        const char identifier{'p'};
        std::shared_ptr<core::buffer> buf_;
    };
}  // namespace ippf::protocol::messages::frontend
