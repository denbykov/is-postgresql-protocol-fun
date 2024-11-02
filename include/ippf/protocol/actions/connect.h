#pragma once

#include <ippf/connection_data.h>
#include <ippf/core/crypto.h>
#include <ippf/io/session_context.h>
#include <ippf/protocol/message_reader.h>
#include <ippf/protocol/messages/frontend/SASLInitialResponse.h>
#include <ippf/protocol/messages/frontend/StartUpMessage.h>

#include <boost/asio.hpp>
#include <iostream>

namespace ippf::protocol::actions::connect {
    using namespace ippf::protocol::messages;
    using namespace ippf::protocol::messages::frontend;
    using namespace std::string_literals;

    class action : public std::enable_shared_from_this<action> {
        using tcp = boost::asio::ip::tcp;

    public:
        action(io::session_context& ctx) : ctx_{ctx} {}

        std::future<void> execute(const connection_data& connection_data) {
            tcp::resolver resolver(ctx_.io_context);

            auto self = shared_from_this();
            message_reader_ =
                std::make_shared<message_reader<action>>(self, ctx_);

            cd_ = connection_data;
            auto future = promise_.get_future();

            auto endpoints = resolver.resolve(cd_.host, cd_.port);

            boost::asio::async_connect(
                ctx_.socket, endpoints,
                [self](boost::system::error_code ec, tcp::endpoint) mutable {
                    self->onConnected(ec);
                });

            return future;
        }

    private:
        void onConnected(boost::system::error_code ec) {
            auto self = shared_from_this();

            StartUpMessage msg{StartUpMessage::version::v3,
                               {
                                   {"user", cd_.username},
                                   {"database", cd_.database},
                               }};

            if (ec) {
                ctx_.socket.close();
                promise_.set_exception(
                    std::make_exception_ptr(std::runtime_error(ec.message())));
                return;
            }

            auto data = msg.data();

            boost::asio::async_write(ctx_.socket, boost::asio::buffer(*data),
                                     [self, data](auto ec, auto) mutable {
                                         self->onStartUpSent(ec);
                                     });
        }

        void onStartUpSent(boost::system::error_code ec) {
            auto self = shared_from_this();

            if (ec) {
                ctx_.socket.close();
                promise_.set_exception(
                    std::make_exception_ptr(std::runtime_error(ec.message())));

                return;
            }

            message_reader_->read_message([self](auto ec, auto tnm) mutable {
                self->message_reader_->reset();
                self->on_server_message(ec, tnm);
            });
        }

        void on_server_message(boost::system::error_code ec,
                               std::optional<backend::type_n_message> tnm) {
            auto self = shared_from_this();

            if (ec) {
                ctx_.socket.close();
                promise_.set_exception(
                    std::make_exception_ptr(std::runtime_error(ec.message())));

                return;
            }

            if (tnm->first ==
                backend::internal_message_type::AuthenticationSASL) {
                auto rsp =
                    std::any_cast<std::shared_ptr<backend::AuthenticationSASL>>(
                        tnm->second);

                std::string client_nonce = core::generate_nonce();
                std::string client_first_message =
                    "n,,n="s + "*"s + ",r="s + client_nonce;

                messages::frontend::SASLInitialResponse msg{
                    rsp->get_mechanism(), client_first_message};

                auto data = msg.data();

                boost::asio::async_write(
                    ctx_.socket, boost::asio::buffer(*data),
                    [self, data](auto ec, auto sent) mutable {
                        self->onSASLInitialResponseSent(ec);
                    });
            }
        }

        void onSASLInitialResponseSent(boost::system::error_code ec) {
            auto self = shared_from_this();

            if (ec) {
                ctx_.socket.close();
                promise_.set_exception(
                    std::make_exception_ptr(std::runtime_error(ec.message())));

                return;
            }

            message_reader_->read_message([self](auto ec, auto tnm) mutable {
                self->message_reader_->reset();
                self->on_server_message(ec, tnm);
            });

            // promise_.set_value();
        }

    private:
        io::session_context& ctx_;
        std::promise<void> promise_;
        connection_data cd_;

        std::shared_ptr<message_reader<action>> message_reader_{nullptr};
    };

}  // namespace ippf::protocol::actions::connect