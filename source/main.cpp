#include <SDKDDKVer.h>
#include <ippf/session.h>
#include <tests/messages/all.h>

#include <boost/asio.hpp>
#include <iostream>

int main() {
    // tests
    ippf::tests::messages::test_all();

    // custom test
    boost::asio::io_context io_context;
    auto work_guard = boost::asio::make_work_guard(io_context);

    std::thread io_thread([&io_context]() { io_context.run(); });
    ippf::session session(io_context);

    try {
        ippf::connection_data cd;
        cd.host = "127.0.0.1";
        cd.port = "5432";
        cd.username = "admin";
        cd.database = "postgres";
        auto future = session.connect(cd);
        future.get();

    } catch (const std::exception& ex) {
        std::cout << ex.what() << std::endl;
    }

    io_context.stop();
    io_thread.join();

    return 0;
}

// #include <boost/asio.hpp>
// #include <iostream>
// #include <memory>
// #include <any>
// #include <stdexcept>
// #include <string>
// #include <vector>
// #include <openssl/evp.h>
// #include <openssl/hmac.h>
// #include <openssl/sha.h>
// #include <openssl/rand.h>
// #include <openssl/evp.h>
// #include <openssl/buffer.h>

// namespace backend {
//     enum class internal_message_type {
//         AuthenticationSASL
//     };

//     class AuthenticationSASL {
//     public:
//         std::string get_mechanism() const {
//             return "SCRAM-SHA-256";  // Replace with actual mechanism
//         }

//         std::string get_server_nonce() const {
//             return "serverNonce";  // Replace with actual server nonce
//         }

//         std::string get_salt() const {
//             return "c2VydmVyU2FsdA==";  // Replace with actual base64-encoded
//             salt
//         }

//         int get_iterations() const {
//             return 4096;  // Replace with actual iteration count
//         }
//     };

//     using type_n_message = std::pair<internal_message_type, std::any>;
// }

// class ConnectAction : public std::enable_shared_from_this<ConnectAction> {
// public:
//     void on_server_message(boost::system::error_code ec,
//                            std::optional<backend::type_n_message> tnm) {
//         auto self = shared_from_this();

//         if (ec) {
//             ctx_.socket.close();
//             promise_.set_exception(
//                 std::make_exception_ptr(std::runtime_error(ec.message())));
//             return;
//         }

//         if (tnm->first == backend::internal_message_type::AuthenticationSASL)
//         {
//             auto msg =
//                 std::any_cast<std::shared_ptr<backend::AuthenticationSASL>>(
//                     tnm->second);

//             // Extract information from the server message
//             std::string mechanism = msg->get_mechanism();
//             std::string clientNonce = generate_nonce();
//             std::string clientFirstMessage = "n=" + mechanism + ",r=" +
//             clientNonce;

//             // Construct the SASLInitialResponse message
//             std::string saslInitialResponse =
//             construct_sasl_initial_response(mechanism, clientFirstMessage);

//             // Send the SASLInitialResponse message to the server
//             send_message_to_server(saslInitialResponse);
//         }

//         promise_.set_value();
//     }

// private:
//     struct Context {
//         boost::asio::ip::tcp::socket socket;
//         sasl_conn_t* sasl_conn;
//     } ctx_;

//     std::promise<void> promise_;
//     std::pair<backend::internal_message_type, std::any>* tnm;

//     // Helper functions for SCRAM-SHA-256
//     std::string generate_nonce(size_t length = 24) {
//         static const char charset[] =
//             "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
//         std::random_device rd;
//         std::mt19937 gen(rd());
//         std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);
//         std::string nonce;
//         nonce.reserve(length);
//         for (size_t i = 0; i < length; ++i) nonce += charset[dist(gen)];
//         return nonce;
//     }

//     std::string to_base64(const unsigned char* data, size_t length) {
//         BIO* b64 = BIO_new(BIO_f_base64());
//         BIO* bio = BIO_new(BIO_s_mem());
//         b64 = BIO_push(b64, bio);
//         BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
//         BIO_write(b64, data, length);
//         BIO_flush(b64);
//         BUF_MEM* bufferPtr;
//         BIO_get_mem_ptr(b64, &bufferPtr);
//         std::string base64Str(bufferPtr->data, bufferPtr->length);
//         BIO_free_all(b64);
//         return base64Str;
//     }

//     std::vector<unsigned char> from_base64(const std::string& base64Str) {
//         BIO* b64 = BIO_new(BIO_f_base64());
//         BIO* bio = BIO_new_mem_buf(base64Str.data(), base64Str.size());
//         b64 = BIO_push(b64, bio);
//         BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
//         std::vector<unsigned char> buffer(base64Str.size());
//         int length = BIO_read(b64, buffer.data(), buffer.size());
//         buffer.resize(length);
//         BIO_free_all(b64);
//         return buffer;
//     }

//     std::string hmac_sha256(const std::string& key, const std::string& data)
//     {
//         unsigned char result[EVP_MAX_MD_SIZE];
//         unsigned int result_len;
//         HMAC(EVP_sha256(), key.data(), key.size(), (unsigned
//         char*)data.data(),
//              data.size(), result, &result_len);
//         return std::string((char*)result, result_len);
//     }

//     std::string pbkdf2_hmac_sha256(const std::string& password, const
//     std::string& salt, int iterations, int dklen) {
//         std::vector<unsigned char> derived_key(dklen);
//         PKCS5_PBKDF2_HMAC(password.c_str(), password.size(),
//                           (unsigned char*)salt.data(), salt.size(),
//                           iterations, EVP_sha256(),
//                           dklen, derived_key.data());
//         return std::string((char*)derived_key.data(), derived_key.size());
//     }

//     std::string sha256(const std::string& data) {
//         unsigned char hash[SHA256_DIGEST_LENGTH];
//         SHA256((unsigned char*)data.data(), data.size(), hash);
//         return std::string((char*)hash, SHA256_DIGEST_LENGTH);
//     }

//     std::string xor_strings(const std::string& str1, const std::string& str2)
//     {
//         std::string result;
//         result.reserve(str1.size());
//         for (size_t i = 0; i < str1.size(); ++i) {
//             result.push_back(str1[i] ^ str2[i]);
//         }
//         return result;
//     }

//     std::string construct_sasl_initial_response(const std::string& mechanism,
//     const std::string& clientFirstMessage) {
//         std::string message = "p=" + mechanism + "\0" + clientFirstMessage;
//         return message;
//     }

//     void send_message_to_server(const std::string& message) {
//         boost::asio::async_write(ctx_.socket, boost::asio::buffer(message),
//             [self = shared_from_this()](boost::system::error_code ec,
//             std::size_t /*length*/) {
//                 if (ec) {
//                     self->ctx_.socket.close();
//                     self->promise_.set_exception(
//                         std::make_exception_ptr(std::runtime_error(ec.message())));
//                 }
//             });
//     }
// };