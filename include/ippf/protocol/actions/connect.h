#pragma once

#include <ippf/connection_data.h>
#include <ippf/io/session_context.h>
#include <ippf/protocol/messages/frontend/StartUpMessage.h>

#include <boost/asio.hpp>
#include <iostream>

namespace ippf::protocol::actions::connect {
    class action : public std::enable_shared_from_this<action> {
        using tcp = boost::asio::ip::tcp;

    public:
        action(io::session_context& ctx) : ctx{ctx} {}

        std::future<void> execute(const connection_data& connection_data) {
            tcp::resolver resolver(ctx.io_context);
            auto endpoints =
                resolver.resolve(connection_data.host, connection_data.port);

            auto future = _promise.get_future();

            auto self = shared_from_this();

            boost::asio::async_connect(
                ctx.socket, endpoints,
                [self](boost::system::error_code ec, tcp::endpoint) mutable {
                    self->onConnected(ec);
                });

            return future;
        }

    private:
        void onConnected(boost::system::error_code ec) {
            if (!ec) {
                std::cout << "I'm connected now!" << std::endl;
                _promise.set_value();
            } else {
                ctx.socket.close();
                _promise.set_exception(
                    std::make_exception_ptr(std::runtime_error(ec.message())));
            }
        }

    private:
        io::session_context& ctx;
        std::promise<void> _promise;
    };

}  // namespace ippf::protocol::actions::connect