#pragma once

#include <ippf/protocol/messages/backend/AuthenticationOk.h>
#include <ippf/protocol/messages/backend/AuthenticationSASL.h>
#include <ippf/protocol/messages/backend/AuthenticationSASLContinue.h>
#include <ippf/protocol/messages/backend/AuthenticationSASLFinal.h>
#include <ippf/protocol/messages/backend/BackendKeyData.h>
#include <ippf/protocol/messages/backend/ErrorResponse.h>
#include <ippf/protocol/messages/backend/NoticeResponse.h>
#include <ippf/protocol/messages/backend/ParameterStatus.h>
#include <ippf/protocol/messages/backend/ReadyForQuery.h>
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

                case message_category::error: {
                    std::any val =
                        std::make_shared<ErrorResponse>(std::move(buf_));

                    return std::make_pair(internal_message_type::ErrorResponse,
                                          val);
                }

                case message_category::notice: {
                    std::any val =
                        std::make_shared<NoticeResponse>(std::move(buf_));

                    return std::make_pair(internal_message_type::NoticeResponse,
                                          val);
                }

                case message_category::key_data: {
                    std::any val =
                        std::make_shared<BackendKeyData>(std::move(buf_));

                    return std::make_pair(internal_message_type::BackendKeyData,
                                          val);
                }

                case message_category::parameter_status: {
                    std::any val =
                        std::make_shared<ParameterStatus>(std::move(buf_));

                    return std::make_pair(
                        internal_message_type::ParameterStatus, val);
                }

                case message_category::ready_for_query: {
                    std::any val =
                        std::make_shared<ReadyForQuery>(std::move(buf_));

                    return std::make_pair(internal_message_type::ReadyForQuery,
                                          val);
                }

                default:
                    assert(false && "Unaccounted message category received");
                    break;
            }

            throw std::runtime_error(
                "Pasring is failed - should never happen error");
        }

    private:
        type_n_message parse_auth_message() {
            auto type = static_cast<auth::message_type>(
                core::easy_get<int32_t>(buf_, offset_));

            switch (type) {
                case auth::message_type::AuthenticationSASL: {
                    std::any val =
                        std::make_shared<AuthenticationSASL>(std::move(buf_));

                    return std::make_pair(
                        internal_message_type::AuthenticationSASL, val);
                }

                case auth::message_type::AuthenticationSASLContinue: {
                    std::any val = std::make_shared<AuthenticationSASLContinue>(
                        std::move(buf_));

                    return std::make_pair(
                        internal_message_type::AuthenticationSASLContinue, val);
                }

                case auth::message_type::AuthenticationSASLFinal: {
                    std::any val = std::make_shared<AuthenticationSASLFinal>(
                        std::move(buf_));

                    return std::make_pair(
                        internal_message_type::AuthenticationSASLFinal, val);
                }

                case auth::message_type::AuthenticationOk: {
                    std::any val =
                        std::make_shared<AuthenticationOk>(std::move(buf_));

                    return std::make_pair(
                        internal_message_type::AuthenticationOk, val);
                }

                default:
                    assert(false && "Unaccounted auth message received");
                    break;
            }

            throw std::runtime_error(
                "Pasring is failed - should never happen error");
        }

    private:
        int32_t offset_{};
        core::buffer buf_;
    };
}  // namespace ippf::protocol