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
        session(boost::asio::io_context& io_context) : ctx_(io_context) {}

        std::future<void> connect(const connection_data& cd) {
            auto action =
                std::make_shared<protocol::actions::connect::action>(ctx_);
            return action->execute(cd);
        }

    private:
        connection_data connection_data_;
        io::session_context ctx_;
    };
}  // namespace ippf