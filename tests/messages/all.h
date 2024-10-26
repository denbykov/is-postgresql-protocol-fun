#pragma once

#include "test_StartUpMessage.h"

namespace ippf::tests::messages {
    inline void test_all() { StartUpMessage::test_serialization(); }
}  // namespace ippf::tests::messages