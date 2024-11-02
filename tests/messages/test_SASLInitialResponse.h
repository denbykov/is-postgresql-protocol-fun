#pragma once

#include <ippf/protocol/messages/frontend/SASLInitialResponse.h>

#include <cassert>

namespace ippf::tests::messages::SASLInitialResponse {
    using message = protocol::messages::frontend::SASLInitialResponse;

    inline void test_serialization() {
        const std::string mechanism = "SCRAM-SHA256";
        const std::string client_initial_response =
            "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL";

        message msg{mechanism, client_initial_response};

        auto buf_ptr = msg.data();
        const auto& buf = *buf_ptr.get();

        assert(buf.size() == 60 && "Data size is not equal to expected");

        int32_t offset{};
        assert(core::easy_get<char>(buf, offset) == 'p');
        assert(core::easy_get<uint32_t>(buf, offset) == 60);
        assert(core::easy_get<std::string_view>(buf, offset) == mechanism);
        assert(core::easy_get<uint32_t>(buf, offset) ==
               client_initial_response.size() + 1);
        assert(core::easy_get<std::string_view>(buf, offset) ==
               client_initial_response);
        assert(core::easy_get<char>(buf, offset) == '\0');
        assert(offset == 60);
    }
}  // namespace ippf::tests::messages::SASLInitialResponse