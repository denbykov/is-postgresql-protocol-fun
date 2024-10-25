#pragma once

#include <boost/asio.hpp>

namespace ippf::io {
    struct session_context {
        using tcp = boost::asio::ip::tcp;

        session_context(boost::asio::io_context& io_context)
            : io_context(io_context), socket(io_context) {}

        boost::asio::io_context& io_context;
        tcp::socket socket;
    };
}  // namespace ippf::io