#pragma once

#include <ippf/connection_data.h>
#include <ippf/core/crypto.h>
#include <ippf/io/session_context.h>
#include <ippf/protocol/message_reader.h>
#include <ippf/protocol/messages/frontend/Query.h>

#include <boost/asio.hpp>
#include <iostream>

namespace ippf::protocol::actions::simple_query {
    using namespace ippf::protocol::messages;
    using namespace ippf::protocol::messages::frontend;
    using namespace std::string_literals;

    class action : public std::enable_shared_from_this<action> {
        using tcp = boost::asio::ip::tcp;

    public:
        action(io::session_context& ctx) : ctx_{ctx} {}

        std::future<void> execute(const std::string_view query) {
            auto self = shared_from_this();
            message_reader_ =
                std::make_shared<message_reader<action>>(self, ctx_);

            auto future = promise_.get_future();

            Query msg{query};
            auto data = msg.data();

            boost::asio::async_write(ctx_.socket, boost::asio::buffer(*data),
                                     [self, data](auto ec, auto sent) mutable {
                                         self->onQuery_sent(ec);
                                     });
            return future;
        }

        void onQuery_sent(boost::system::error_code ec) {
            auto self = shared_from_this();

            if (ec) {
                ctx_.socket.close();
                promise_.set_exception(
                    std::make_exception_ptr(std::runtime_error(ec.message())));

                return;
            }

            message_reader_->read_message([self](auto ec, auto tnm) mutable {
                self->message_reader_->reset();
                self->onQuery_response(ec, tnm);
            });
        }

        void onQuery_response(boost::system::error_code ec,
                              std::optional<backend::type_n_message> tnm) {
            auto self = shared_from_this();

            if (ec) {
                ctx_.socket.close();
                promise_.set_exception(
                    std::make_exception_ptr(std::runtime_error(ec.message())));

                return;
            }

            if (tnm->first == backend::internal_message_type::RowDescription) {
                // Skip handling for now
            } else if (tnm->first == backend::internal_message_type::DataRow) {
                // Skip handling for now
            } else if (tnm->first ==
                       backend::internal_message_type::CommandComplete) {
                // Skip handling for now
            } else if (tnm->first ==
                       backend::internal_message_type::ReadyForQuery) {
                if (exception_ != nullptr) {
                    promise_.set_exception(exception_);
                } else {
                    promise_.set_value();
                }
                return;
            } else if (tnm->first ==
                       backend::internal_message_type::ErrorResponse) {
                auto message =
                    std::any_cast<std::shared_ptr<backend::ErrorResponse>>(
                        tnm->second);

                auto fields = message->get_fields();

                std::stringstream ss;

                ss << fields.at(message_id_token::serverity) << ": "
                   << fields.at(message_id_token::message);

                exception_ =
                    std::make_exception_ptr(std::runtime_error(ss.str()));
            } else if (tnm->first ==
                       backend::internal_message_type::NoticeResponse) {
                // Well, ok. Skip handling for now
            } else {
                assert(false && "Unexpected message type");
            }

            message_reader_->read_message([self](auto ec, auto tnm) mutable {
                self->message_reader_->reset();
                self->onQuery_response(ec, tnm);
            });
        };

    private:
        io::session_context& ctx_;
        std::promise<void> promise_;

        std::shared_ptr<message_reader<action>> message_reader_{nullptr};
        std::exception_ptr exception_{nullptr};
    };
}  // namespace ippf::protocol::actions::simple_query