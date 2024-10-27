#pragma once

#include <ippf/protocol/messages/backend/AuthenticationSASL.h>
#include <ippf/protocol/messages/backend/message_types.h>

#include <any>
#include <cassert>
#include <utility>

namespace ippf::protocol {
    using namespace ippf::protocol::messages::backend;

    struct message_parser {
        message_parser(core::buffer&& buf) : buf_(std::move(buf)) {}

        type_n_message parse() {
            auto category = static_cast<message_category>(
                core::easy_get<char>(buf_, offset_));

            offset_ += 4;  // skip size field

            switch (category) {
                case message_category::auth:
                    return parse_auth_message();

                default:
                    assert(false && "Unaccounted message category received");
                    break;
            }
        }

    private:
        type_n_message parse_auth_message() {
            auto type = static_cast<auth::message_type>(
                core::easy_get<int32_t>(buf_, offset_));

            switch (type) {
                case auth::message_type::AuthenticationOk:
                    assert(false && "Wow you did it!");

                case auth::message_type::AuthenticationSASL: {
                    std::any val =
                        std::make_shared<AuthenticationSASL>(std::move(buf_));

                    return std::make_pair(
                        internal_message_type::AuthenticationSASL, val);
                }

                default:
                    assert(false && "Unaccounted auth message received");
                    break;
            }
        }

    private:
        int32_t offset_{};
        core::buffer buf_;
    };
}  // namespace ippf::protocol