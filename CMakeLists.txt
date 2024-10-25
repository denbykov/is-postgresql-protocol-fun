cmake_minimum_required(VERSION 3.5.0)

set(CMAKE_CXX_STANDARD 20)

project(postgresqlClient VERSION 0.1.0 LANGUAGES C CXX)

find_package(Boost 1.85 REQUIRED)

set(HEADERS
    include/ippf/core/concepts.h
    include/ippf/core/to_x_endian.h

    include/ippf/io/ostream.h
    include/ippf/io/istream.h
    include/ippf/io/session_context.h

    include/ippf/protocol/messages/frontend/StartUpMessage.h
    include/ippf/protocol/actions/connect.h

    include/ippf/session.h
    include/ippf/connection_data.h
)

set(SOURCES
    source/main.cpp
)

add_executable(postgresqlClient ${SOURCES} ${HEADERS})

target_link_libraries(postgresqlClient PRIVATE Boost::boost)

target_include_directories(postgresqlClient PRIVATE include)