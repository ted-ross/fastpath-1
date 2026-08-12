cmake_minimum_required(VERSION 3.16)
project(udp-encap CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(udp-encap
    src/main.cpp
    src/config.cpp
    src/raw_socket.cpp
    src/udp_socket.cpp
    src/handlers.cpp
)

target_compile_options(udp-encap PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

target_link_libraries(udp-encap PRIVATE uring)
