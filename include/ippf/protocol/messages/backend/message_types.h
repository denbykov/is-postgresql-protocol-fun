#pragma once

#include <any>
#include <cstdint>

namespace ippf::protocol::messages::backend {
    enum class message_category : char {
        auth = 'R',
        error = 'E',
        notice = 'N',
        key_data = 'K',
        parameter_status = 'S',
        ready_for_query = 'Z',
    };

    // Applicable for Error and Notice messages
    enum class message_id_token : char {
        serverity_localized = 'S',
        serverity = 'V',
        sqlstate_code = 'C',
        message = 'M',
        detail = 'D',
        hint = 'H',
        position = 'P',
        internal_position = 'p',
        internal_qurey = 'q',
        where = 'W',
        schema_name = 's',
        table_name = 't',
        column_name = 'c',
        data_type_name = 'd',
        constraint_name = 'n',
        file = 'F',
        line = 'L',
        routine = 'R',
    };

    namespace auth {
        enum class message_type : int32_t {
            AuthenticationOk = 0,
            AuthenticationSASL = 10,
            AuthenticationSASLContinue = 11,
            AuthenticationSASLFinal = 12,
        };
    }

    enum class internal_message_type : int32_t {
        AuthenticationOk,
        AuthenticationSASL,
        AuthenticationSASLContinue,
        AuthenticationSASLFinal,

        ErrorResponse,
        NoticeResponse,

        BackendKeyData,
        ParameterStatus,
        ReadyForQuery,
    };

    using type_n_message = std::pair<internal_message_type, std::any>;
};  // namespace ippf::protocol::messages::backend