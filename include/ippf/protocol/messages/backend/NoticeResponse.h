#pragma once

#include <ippf/core/buffer.h>
#include <ippf/core/buffer_op.h>
#include <ippf/protocol/messages/backend/message_types.h>

#include <cstdint>
#include <map>
#include <memory>
#include <string_view>

namespace ippf::protocol::messages::backend {
    class NoticeResponse {
    public:
        NoticeResponse(core::buffer&& buf) : buf_(std::move(buf)) {}

        NoticeResponse(const NoticeResponse& other) = delete;
        NoticeResponse(NoticeResponse&&) = default;

        NoticeResponse operator==(const NoticeResponse& other) = delete;
        NoticeResponse& operator=(NoticeResponse&&) = default;

        std::map<message_id_token, std::string_view> get_fields() const {
            std::map<message_id_token, std::string_view> fields;

            int32_t offset{1};

            const auto size = core::easy_get<int32_t>(buf_, offset);
            auto identifier = core::easy_get<char>(buf_, offset);

            while (identifier != '\0') {
                auto token = static_cast<message_id_token>(identifier);
                auto payload = core::easy_get<std::string_view>(buf_, offset);

                auto insertion_took_place =
                    fields.insert({token, payload}).second;

                assert(insertion_took_place &&
                       "Whoopsie daisy, looks like token duplication is a real "
                       "thing");

                identifier = core::easy_get<char>(buf_, offset);
            }

            return fields;
        }

        const core::buffer* data() const { return &buf_; }

    private:
        core::buffer buf_;
    };
}  // namespace ippf::protocol::messages::backend
