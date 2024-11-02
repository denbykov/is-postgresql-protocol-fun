#pragma once

#include <ippf/protocol/messages/frontend/SASLInitialResponse.h>

#include <cassert>

namespace ippf::tests::messages::SASLInitialResponse {
    using message = protocol::messages::frontend::SASLInitialResponse;

    inline void test_serialization() {
        std::string mechanism = "SCRAM-SHA256";
        std::string client_initial_response =
            "n,,n=*,r=fyko+d2lbbFgONRv9qkxdawL";

        core::bytes ir{client_initial_response};
        message msg{mechanism, ir};

        auto buf_ptr = msg.data();
        const auto& buf = *buf_ptr.get();

        int32_t expected_message_size{};
        int32_t expected_packet_size{};
        expected_packet_size += 1;   // identifier
        expected_message_size += 4;  // size
        expected_message_size +=
            core::get_size(std::string_view(mechanism));  // 13 bytes
        expected_message_size += 4;                       // ir size
        expected_message_size += core::get_size(ir);      // 33 bytes

        expected_packet_size += expected_message_size;

        assert(expected_message_size == 54 && "Your expected size is wrong");
        assert(buf.size() == expected_packet_size &&
               "Data size is not equal to expected");

        int32_t offset{};

        assert(core::easy_get<char>(buf, offset) == 'p');

        auto msg_size = core::easy_get<uint32_t>(buf, offset);
        assert(msg_size == expected_message_size);

        assert(core::easy_get<std::string_view>(buf, offset) == mechanism);

        auto msg_ir_size = core::easy_get<uint32_t>(buf, offset);
        assert(msg_ir_size == core::get_size(ir));

        auto msg_ir = core::get<core::bytes>(buf, msg_ir_size, offset);
        assert(std::equal(msg_ir.begin(), msg_ir.end(), ir.begin()));

        assert(offset == expected_packet_size);
    }
}  // namespace ippf::tests::messages::SASLInitialResponse