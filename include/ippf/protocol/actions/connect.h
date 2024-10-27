#pragma once

#include <ippf/connection_data.h>
#include <ippf/io/session_context.h>
#include <ippf/protocol/messages/frontend/StartUpMessage.h>

#include <boost/asio.hpp>
#include <iostream>

namespace ippf::protocol::actions::connect {
    using namespace ippf::protocol::messages::frontend;

    class action : public std::enable_shared_from_this<action> {
        using tcp = boost::asio::ip::tcp;

    public:
        action(io::session_context& ctx) : ctx_{ctx} {}

        std::future<void> execute(const connection_data& connection_data) {
            tcp::resolver resolver(ctx_.io_context);
            auto self = shared_from_this();
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

            boost::asio::async_write(
                ctx_.socket,
                boost::asio::buffer(msg.data()->data, msg.data()->size),
                [self](auto ec, auto) mutable { self->onStartUpSent(ec); });
        }

        void onStartUpSent(boost::system::error_code ec) {
            auto self = shared_from_this();

            if (ec) {
                ctx_.socket.close();
                promise_.set_exception(
                    std::make_exception_ptr(std::runtime_error(ec.message())));

                return;
            }

            boost::asio::async_read(
                ctx_.socket, boost::asio::buffer(sbuf_.data, 24),
                [self](auto ec, auto) {
                    const auto* buf = &self->sbuf_;

                    int32_t offset{};

                    std::cout << core::easy_get<char>(buf, offset) << std::endl;
                    std::cout << core::easy_get<int32_t>(buf, offset)
                              << std::endl;
                    std::cout << core::easy_get<int32_t>(buf, offset)
                              << std::endl;
                    std::cout << core::easy_get<std::string_view>(buf, offset)
                              << std::endl;
                    self->onServerResponse(ec);
                });
        }

        void onServerResponse(boost::system::error_code ec) {
            auto self = shared_from_this();

            if (ec) {
                ctx_.socket.close();
                promise_.set_exception(
                    std::make_exception_ptr(std::runtime_error(ec.message())));

                return;
            }

            promise_.set_value();
        }

    private:
        io::session_context& ctx_;
        std::promise<void> promise_;
        connection_data cd_;

        core::static_buffer sbuf_;
    };

}  // namespace ippf::protocol::actions::connect