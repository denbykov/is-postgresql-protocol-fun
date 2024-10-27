#pragma once

#include <ippf/core/buffer.h>
#include <ippf/core/buffer_op.h>
#include <ippf/io/session_context.h>
#include <ippf/protocol/message_parser.h>

#include <boost/asio.hpp>
#include <cstdint>
// TODO clean up iostream includes

#include <functional>
#include <iostream>
#include <memory>
#include <optional>

namespace ippf::protocol {
    template <typename Action>
    class message_reader
        : public std::enable_shared_from_this<message_reader<Action>> {
    public:
        using on_done_t = std::function<void(
            boost::system::error_code,
            std::optional<messages::backend::type_n_message>)>;

    public:
        message_reader(std::shared_ptr<Action> master, io::session_context& ctx)
            : master_(master), ctx_(ctx) {}

        void read_message(on_done_t on_done) {
            auto self = this->shared_from_this();
            on_done_ = on_done;

            int32_t constexpr primal_header_size = 5;  // identifier + size

            boost::asio::async_read(
                ctx_.socket,
                boost::asio::buffer(sbuf_.data(), primal_header_size),
                [self](auto ec, auto length) {
                    self->bytes_read_ += static_cast<int32_t>(length);
                    self->sbuf_offset_ += static_cast<int32_t>(length);

                    if (ec) {
                        self->on_done_(ec, std::nullopt);

                        return;
                    }

                    const auto& buf = self->sbuf_;

                    int32_t offset{1};
                    self->size_ = core::easy_get<int32_t>(buf, offset) + 1;

                    self->read_more();
                });
        }

    private:
        void read_more() {
            auto self = this->shared_from_this();

            int32_t bytes_left = size_ - bytes_read_ - 1;
            int32_t capacity_left =
                static_cast<int32_t>(sbuf_.size()) - sbuf_offset_;

            assert(bytes_left < capacity_left &&
                   "More bytes requested that available in static buffer");

            boost::asio::async_read(
                ctx_.socket,
                boost::asio::buffer(sbuf_.data() + sbuf_offset_, bytes_left),
                [self](auto ec, auto length) {
                    self->bytes_read_ += static_cast<int32_t>(length);
                    self->sbuf_offset_ += static_cast<int32_t>(length);

                    const auto& sbuf = self->sbuf_;
                    auto& buf = self->buf_;

                    if (self->bytes_read_ == self->size_ - 1) {
                        buf.reserve(self->size_);

                        std::copy(sbuf.begin(), sbuf.end(),
                                  std::back_inserter(buf));

                        auto tnm = message_parser(std::move(buf)).parse();
                        return self->on_done_(ec, tnm);
                    }

                    assert(false && "Reached end of read without any action");
                });
        }

    private:
        std::shared_ptr<Action> master_;
        io::session_context& ctx_;
        on_done_t on_done_;

        core::static_buffer sbuf_{};
        int32_t sbuf_offset_{};

        int32_t size_{};
        int32_t bytes_read_{};

        core::buffer buf_;
    };
}  // namespace ippf::protocol