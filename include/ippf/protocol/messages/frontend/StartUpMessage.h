#pragma once

#include <cstdint>

namespace ippf::protocol::messages::frontend {
    struct StartUpMessage {
        enum class Version : int32_t {
            v3 = 196608,
        };

        int32_t length{};
        Version protocolVersion{Version::v3};
        char** parameters{nullptr};
    };
}  // namespace ippf::protocol::messages::frontend
