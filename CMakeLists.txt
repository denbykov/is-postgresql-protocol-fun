cmake_minimum_required(VERSION 3.5.0)

set(CMAKE_CXX_STANDARD 20)

project(test VERSION 0.1.0 LANGUAGES C CXX)

find_package(Boost 1.85 REQUIRED)

set(SOURCES
    source/main.cpp
    # source/chat_client.cpp
    # source/chat_server.cpp
    # source/chat_message.hpp
)

add_executable(test ${SOURCES})

target_link_libraries(test PRIVATE Boost::boost)

# target_include_directories(test ${CMAKE_CURRENT_BINARY_DIR})