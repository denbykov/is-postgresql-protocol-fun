#pragma once

#include <ippf/core/buffer.h>
#include <ippf/core/buffer_op.h>
#include <ippf/core/to_x_endian.h>

#include <cstdint>
#include <memory>
#include <vector>

namespace ippf::protocol::messages::frontend {
    class Query {
    public:
        Query(const std::string_view query) {
            int32_t packet_size{};

            int32_t size{};
            int32_t query_size{core::get_size(query)};

            packet_size += core::get_size(identifier);
            size += core::get_size(size);
            size += query_size;

            packet_size += size;
            buf_ = std::make_shared<core::buffer>(packet_size, 0);

            int32_t offset{0};

            core::copy(core::to_big_endian(identifier), *buf_.get(), offset);
            core::copy(core::to_big_endian(size), *buf_.get(), offset);
            core::copy(query, *buf_.get(), offset);
        }

        Query(const Query& other) = delete;
        Query operator==(const Query& other) = delete;
        Query operator==(Query&& other) = delete;

        std::shared_ptr<core::buffer> data() const { return buf_; }

    private:
        const char identifier{'Q'};
        std::shared_ptr<core::buffer> buf_;
    };
}  // namespace ippf::protocol::messages::frontend
