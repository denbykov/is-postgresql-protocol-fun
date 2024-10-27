#pragma once

#include <ippf/protocol/messages/frontend/StartUpMessage.h>

#include <cassert>

namespace ippf::tests::messages::StartUpMessage {
    using message = protocol::messages::frontend::StartUpMessage;

    inline void test_serialization() {
        auto ver = message::version::v3;

        // parameters size is 5 + 6 + 9 + 9 = 29
        message::parameters parameters = {{"user", "admin"},
                                          {"database", "postgres"}};

        message msg{ver, parameters};

        auto buf_ptr = msg.data();
        const auto& buf = *buf_ptr.get();

        assert(buf.size() == 38 && "Data size is not equal to expected");

        int32_t offset{};
        assert(core::easy_get<uint32_t>(buf, offset) == 38);
        assert(core::easy_get<uint32_t>(buf, offset) ==
               static_cast<int32_t>(message::version::v3));
        assert(core::easy_get<std::string_view>(buf, offset) == "user");
        assert(core::easy_get<std::string_view>(buf, offset) == "admin");
        assert(core::easy_get<std::string_view>(buf, offset) == "database");
        assert(core::easy_get<std::string_view>(buf, offset) == "postgres");

        assert(offset == 37);
    }
}  // namespace ippf::tests::messages::StartUpMessage