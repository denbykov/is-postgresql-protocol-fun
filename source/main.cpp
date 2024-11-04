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

    return 0;
}