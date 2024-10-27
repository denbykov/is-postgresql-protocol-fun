#pragma once

#include <sasl/sasl.h>

#include <boost/asio.hpp>
#include <memory>

namespace ippf::io {
    struct session_context {
        using tcp = boost::asio::ip::tcp;

        session_context(boost::asio::io_context& io_context)
            : io_context(io_context), socket(io_context) {}

        boost::asio::io_context& io_context;
        tcp::socket socket;

        // TODO: add connection cleaning
        sasl_conn_t* sasl_conn{nullptr};
    };
}  // namespace ippf::io