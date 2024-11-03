#pragma once

#include <ippf/connection_data.h>
#include <ippf/core/crypto.h>
#include <ippf/io/session_context.h>
#include <ippf/protocol/message_reader.h>
#include <ippf/protocol/messages/frontend/SASLInitialResponse.h>
#include <ippf/protocol/messages/frontend/SASLResponse.h>
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
        struct authentication_context {
            std::string client_nonce;
            std::string client_first_message_bare;
            std::string server_nonce;
            std::vector<uint8_t> salt;
            int32_t iterations;
        };

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
                self->onStartUp_response(ec, tnm);
            });
        }

        void onStartUp_response(boost::system::error_code ec,
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
                auto response =
                    std::any_cast<std::shared_ptr<backend::AuthenticationSASL>>(
                        tnm->second);

                self->auth_ctx_.client_nonce = core::generate_nonce();

                std::string client_first_message_bare =
                    "n="s + "*"s + ",r="s + self->auth_ctx_.client_nonce;

                self->auth_ctx_.client_first_message_bare =
                    client_first_message_bare;

                std::string client_first_message =
                    "n,,"s + client_first_message_bare;

                messages::frontend::SASLInitialResponse msg{
                    response->get_mechanism(), client_first_message};

                auto data = msg.data();

                boost::asio::async_write(
                    ctx_.socket, boost::asio::buffer(*data),
                    [self, data](auto ec, auto sent) mutable {
                        self->onSASLInitialResponse_sent(ec);
                    });
            } else {
                assert(false && "Unexpected message type");
            }
        }

        void onSASLInitialResponse_sent(boost::system::error_code ec) {
            auto self = shared_from_this();

            if (ec) {
                ctx_.socket.close();
                promise_.set_exception(
                    std::make_exception_ptr(std::runtime_error(ec.message())));

                return;
            }

            message_reader_->read_message([self](auto ec, auto tnm) mutable {
                self->message_reader_->reset();
                self->onSASLInitialResponse_response(ec, tnm);
            });
        }

        void parse_server_first_message(std::string_view data) {
            // Message example:
            // "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+"
            // "Q6sek8bf92,i=4096"

            constexpr std::string_view nonce_prefix("r=");
            constexpr std::string_view salt_prefix(",s=");
            constexpr std::string_view it_prefix(",i=");

            auto salt_pos = data.find(salt_prefix);
            auto it_pos = data.find(it_prefix);

            const int32_t client_nonce_size =
                static_cast<int32_t>(auth_ctx_.client_nonce.size());
            constexpr int32_t nonce_prefix_size =
                static_cast<int32_t>(nonce_prefix.size());

            const auto server_nonce_pos = nonce_prefix_size + client_nonce_size;
            auth_ctx_.server_nonce =
                data.substr(server_nonce_pos, salt_pos - server_nonce_pos);

            const auto salt_data_pos = salt_pos + salt_prefix.size();
            auto salt =
                std::string(data.substr(salt_data_pos, it_pos - salt_data_pos));
            auth_ctx_.salt = core::from_base64(salt);

            const auto it_data_pos = it_pos + it_prefix.size();
            const auto it_data =
                data.substr(it_data_pos, data.size() - it_data_pos);
            auth_ctx_.iterations = std::stoi(it_data.data());
        }

        std::string build_client_final_message(
            std::string_view server_first_message) {
            // Combine the client nonce and server nonce
            std::string combined_nonce =
                auth_ctx_.client_nonce + auth_ctx_.server_nonce;

            // Create the client-final-message-without-proof
            std::string client_final_message_without_proof =
                "c=biws,r=" + combined_nonce;

            // Compute the SaltedPassword using PBKDF2
            auto salted_password = core::derive_salted_password(
                cd_.password, auth_ctx_.salt, auth_ctx_.iterations);

            // Build the auth_message
            std::string auth_message = auth_ctx_.client_first_message_bare +
                                       "," + std::string(server_first_message) +
                                       "," + client_final_message_without_proof;

            // Compute the client proof
            auto client_key = core::hmac_sha256(salted_password, "Client Key");
            auto stored_key = core::sha256(client_key);
            auto client_signature = core::hmac_sha256(stored_key, auth_message);
            auto client_proof = core::xor_arrays(client_key, client_signature);
            std::string client_proof_base64 =
                core::to_base64(client_proof.data(), client_proof.size());

            // Build the final client message
            return client_final_message_without_proof +
                   ",p=" + client_proof_base64;
        }

        void onSASLInitialResponse_response(
            boost::system::error_code ec,
            std::optional<backend::type_n_message> tnm) {
            auto self = shared_from_this();

            if (ec) {
                ctx_.socket.close();
                promise_.set_exception(
                    std::make_exception_ptr(std::runtime_error(ec.message())));

                return;
            }

            if (tnm->first ==
                backend::internal_message_type::AuthenticationSASLContinue) {
                auto response = std::any_cast<
                    std::shared_ptr<backend::AuthenticationSASLContinue>>(
                    tnm->second);

                auto sasl_data = response->get_sasl_data();
                auto sasl_data_str =
                    std::string_view(sasl_data.data(), sasl_data.size());

                parse_server_first_message(sasl_data_str);
                auto client_final_message =
                    build_client_final_message(sasl_data_str);

                messages::frontend::SASLResponse msg{client_final_message};
                auto data = msg.data();

                boost::asio::async_write(
                    ctx_.socket, boost::asio::buffer(*data),
                    [self, data](auto ec, auto sent) mutable {
                        self->onSASLResponse_sent(ec);
                    });
            } else {
                assert(false && "Unexpected message type");
            }
        }

        void onSASLResponse_sent(boost::system::error_code ec) {
            auto self = shared_from_this();

            if (ec) {
                ctx_.socket.close();
                promise_.set_exception(
                    std::make_exception_ptr(std::runtime_error(ec.message())));

                return;
            }

            self->promise_.set_value();

            // message_reader_->read_message([self](auto ec, auto tnm) mutable {
            //     self->message_reader_->reset();
            //     self->onSASLInitialResponse_response(ec, tnm);
            // });
        }

    private:
        io::session_context& ctx_;
        std::promise<void> promise_;
        connection_data cd_;

        std::shared_ptr<message_reader<action>> message_reader_{nullptr};
        authentication_context auth_ctx_;
    };

}  // namespace ippf::protocol::actions::connect