#pragma once

#include <ippf/core/buffer.h>
#include <ippf/core/buffer_op.h>
#include <ippf/io/session_context.h>

#include <boost/asio.hpp>
#include <cstdint>
// TODO clean up iostream includes
#include <functional>
#include <iostream>
#include <memory>

namespace ippf::protocol {
    template <typename Action>
    class message_reader
        : public std::enable_shared_from_this<message_reader<Action>> {
    public:
        message_reader(std::shared_ptr<Action> master, io::session_context& ctx)
            : master_(master), ctx_(ctx) {
            buf_.reserve(core::default_buffer_size);
        }

        void read_message(
            std::function<void(boost::system::error_code)> on_done) {
            auto self = this->shared_from_this();
            on_done_ = on_done;

            int32_t constexpr primal_header_size = 5;  // identifier + size

            boost::asio::async_read(
                ctx_.socket, boost::asio::buffer(buf_, primal_header_size),
                [self](auto ec, auto) {
                    if (ec) {
                        self->on_done_(ec);

                        return;
                    }

                    const auto& buf = self->buf_;

                    int32_t offset{};

                    std::cout << core::easy_get<char>(buf, offset) << std::endl;
                    std::cout << core::easy_get<int32_t>(buf, offset)
                              << std::endl;
                    self->on_done_(ec);
                });

            // boost::asio::async_read(
            //     ctx_.socket, boost::asio::buffer(sbuf_.data, 24),
            //     [self](auto ec, auto) {
            //         const auto* buf = &self->sbuf_;

            //         int32_t offset{};

            //         std::cout << core::easy_get<int32_t>(buf, offset)
            //                   << std::endl;
            //         std::cout << core::easy_get<std::string_view>(buf,
            //         offset)
            //                   << std::endl;
            //         self->on_done_(ec);
            //     });
        }

    private:
        void read_more();

    private:
        std::shared_ptr<Action> master_;
        io::session_context& ctx_;
        std::function<void(boost::system::error_code)> on_done_;

        int32_t size_{};
        int32_t bytes_read_{};

        core::buffer buf_{};
    };
}  // namespace ippf::protocol