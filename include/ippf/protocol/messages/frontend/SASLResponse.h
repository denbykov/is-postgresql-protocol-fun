#pragma once

#include <ippf/core/buffer.h>
#include <ippf/core/buffer_op.h>
#include <ippf/core/to_x_endian.h>

#include <cstdint>
#include <memory>
#include <vector>

namespace ippf::protocol::messages::frontend {
    class SASLResponse {
    public:
        SASLResponse(const core::bytes data) {
            int32_t packet_size{};

            int32_t size{};
            int32_t data_size{core::get_size(data)};

            packet_size += core::get_size(identifier);
            size += core::get_size(size);
            size += data_size;

            packet_size += size;
            buf_ = std::make_shared<core::buffer>(packet_size, 0);

            int32_t offset{0};

            core::copy(core::to_big_endian(identifier), *buf_.get(), offset);
            core::copy(core::to_big_endian(size), *buf_.get(), offset);
            core::copy(data, *buf_.get(), offset);
        }

        SASLResponse(const SASLResponse& other) = delete;
        SASLResponse operator==(const SASLResponse& other) = delete;
        SASLResponse operator==(SASLResponse&& other) = delete;

        std::shared_ptr<core::buffer> data() const { return buf_; }

    private:
        const char identifier{'p'};
        std::shared_ptr<core::buffer> buf_;
    };
}  // namespace ippf::protocol::messages::frontend
