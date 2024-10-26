#pragma once

#include <ippf/core/buffer.h>
#include <ippf/core/to_x_endian.h>

#include <cstdint>
#include <string_view>

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
            size += sizeof(size);
            size += sizeof(ver);

            for (const auto& param : parameters) {
                size += static_cast<int32_t>(param.first.size()) + 1;
                size += static_cast<int32_t>(param.second.size()) + 1;
            }

            size += 1;  // terminator;

            buf_.data = static_cast<char*>(calloc(sizeof(char), size));
            buf_.size = size;

            int32_t offset{0};

            core::copy(core::to_big_endian(size), &buf_, offset);
            core::copy(core::to_big_endian(static_cast<int32_t>(ver)), &buf_,
                       offset);

            for (const auto& param : parameters) {
                core::copy(param.first, &buf_, offset);
                core::copy(param.second, &buf_, offset);
            }
        }

        StartUpMessage(const StartUpMessage& other) = delete;
        StartUpMessage operator==(const StartUpMessage& other) = delete;
        StartUpMessage operator==(StartUpMessage&& other) = delete;

        ~StartUpMessage() { delete buf_.data; }

        const core::buffer* data() const { return &buf_; }

    private:
        core::buffer buf_;
    };
}  // namespace ippf::protocol::messages::frontend
