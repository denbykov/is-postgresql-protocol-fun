#pragma once

#include <cstdint>
#include <any>

namespace ippf::protocol::messages::backend {
    enum class message_category : char {
        auth = 'R',
    };

    namespace auth {
        enum class message_type : int32_t {
            AuthenticationOk = 0,
            AuthenticationSASL = 10,
        };
    }

    enum class internal_message_type : int32_t {
        AuthenticationOk,
        AuthenticationSASL,
    };

    using type_n_message = std::pair<internal_message_type, std::any>;
};  // namespace ippf::protocol::messages::backend