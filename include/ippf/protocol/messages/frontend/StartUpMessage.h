#pragma once

#include <ippf/core/buffer.h>
#include <ippf/core/buffer_op.h>
#include <ippf/core/to_x_endian.h>

#include <cstdint>
#include <memory>
#include <string_view>
#include <vector>

namespace ippf::protocol::messages::frontend {
    class StartUpMessage {
    public:
        using parameter = std::pair<std::string_view, std::string_view>;
        using parameters = std::vector<parameter>;

        enum class version : int32_t {
            v3 = 196608,
        };

    public:
        StartUpMessage(version ver, const parameters& parameters) {
            int32_t size{};

            auto version = static_cast<int32_t>(ver);

            size += core::get_size(size);
            size += core::get_size(version);

            for (const auto& param : parameters) {
                size += core::get_size(param.first);
                size += core::get_size(param.second);
            }

            size += 1;  // terminator;

            buf_ = std::make_shared<core::buffer>(size, 0);

            int32_t offset{0};

            core::copy(core::to_big_endian(size), *buf_.get(), offset);
            core::copy(core::to_big_endian(version), *buf_.get(), offset);

            for (const auto& param : parameters) {
                core::copy(param.first, *buf_.get(), offset);
                core::copy(param.second, *buf_.get(), offset);
            }
        }

        StartUpMessage(const StartUpMessage& other) = delete;
        StartUpMessage operator==(const StartUpMessage& other) = delete;
        StartUpMessage operator==(StartUpMessage&& other) = delete;

        std::shared_ptr<core::buffer> data() const { return buf_; }

    private:
        std::shared_ptr<core::buffer> buf_;
    };
}  // namespace ippf::protocol::messages::frontend
