cmake_minimum_required(VERSION 3.5.0)

set(CMAKE_CXX_STANDARD 20)

project(ippf-lib VERSION 0.1.0 LANGUAGES C CXX)

find_package(Boost 1.85 REQUIRED)
find_library(SASL libsasl REQUIRED)
# find_package(libsasl2 REQUIRED)

set(HEADERS
    include/ippf/core/concepts.h

    include/ippf/core/to_x_endian.h
    include/ippf/core/buffer.h
    include/ippf/core/buffer_op.h

    include/ippf/io/session_context.h

    include/ippf/protocol/messages/frontend/StartUpMessage.h
    include/ippf/protocol/messages/backend/AuthenticationSASL.h
    include/ippf/protocol/actions/connect.h
    include/ippf/protocol/message_reader.h
    include/ippf/protocol/message_parser.h

    include/ippf/session.h
    include/ippf/connection_data.h
)

set(SOURCES
    source/main.cpp
)

set(TEST_HEADERS
    tests/messages/test_StartUpMessage.h
    tests/messages/all.h
)

add_executable(ippf-lib ${SOURCES} ${HEADERS} ${TEST_HEADERS})

target_link_libraries(ippf-lib PRIVATE 
    Boost::boost
    ${SASL}
)

target_include_directories(ippf-lib PRIVATE include ${CMAKE_CURRENT_SOURCE_DIR})