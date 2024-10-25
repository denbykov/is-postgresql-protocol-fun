#pragma once

#include <ippf/connection_data.h>
#include <ippf/io/session_context.h>
#include <ippf/protocol/actions/connect.h>

#include <boost/asio.hpp>
#include <iostream>

namespace ippf {
    class session {
        using tcp = boost::asio::ip::tcp;

    public:
        session(boost::asio::io_context& io_context) : _ctx(io_context) {}

        std::future<void> connect(const connection_data& cd) {
            auto action =
                std::make_shared<protocol::actions::connect::action>(_ctx);
            return action->execute(cd);
        }

    private:
        connection_data _connection_data;
        io::session_context _ctx;
    };
}  // namespace ippf