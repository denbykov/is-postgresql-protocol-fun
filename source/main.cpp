#include <SDKDDKVer.h>
#include <ippf/core/crypto.h>
#include <ippf/session.h>
#include <tests/messages/all.h>

#include <boost/asio.hpp>
#include <iostream>

using namespace ippf;

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
        cd.password = "admin";
        cd.database = "postgres";
        auto future = session.connect(cd);
        future.get();

    } catch (const std::exception& ex) {
        std::cout << ex.what() << std::endl;
    }

    io_context.stop();
    io_thread.join();

    // std::string salt_base64 = "AY90OXgAgGBmpFHHDK2Uhg==";
    // auto salt = core::from_base64(salt_base64);
    // int iterations = 4096;

    // std::cout << "Salt: " << core::to_hex_string(salt) << std::endl;

    // std::string password = "admin";

    // auto salted_password =
    //     core::derive_salted_password(password, salt, iterations);

    // std::cout << "Salted password: " << core::to_hex_string(salted_password)
    //           << std::endl;

    return 0;
}