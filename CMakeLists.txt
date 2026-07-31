cmake_minimum_required(VERSION 3.16)
project(dataplane CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Dependencies ──────────────────────────────────────────────────────────────
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)

# ── eBPF kernel program ───────────────────────────────────────────────────────
find_program(CLANG clang REQUIRED)

set(BPF_SRC  "${CMAKE_SOURCE_DIR}/bpf/xdp_prog.bpf.c")
set(BPF_OBJ  "${CMAKE_BINARY_DIR}/xdp_prog.bpf.o")

# Build a list of -I flags for each libbpf include directory.
set(BPF_INCLUDE_FLAGS)
foreach(dir ${LIBBPF_INCLUDE_DIRS})
    list(APPEND BPF_INCLUDE_FLAGS "-I${dir}")
endforeach()

add_custom_command(
    OUTPUT  ${BPF_OBJ}
    COMMAND ${CLANG}
            -target bpf
            -O2
            -g
            -Wall
            ${BPF_INCLUDE_FLAGS}
            -c ${BPF_SRC}
            -o ${BPF_OBJ}
    DEPENDS ${BPF_SRC}
    COMMENT "Compiling eBPF program ${BPF_SRC}"
    VERBATIM
)

add_custom_target(bpf_prog ALL DEPENDS ${BPF_OBJ})

# Pass the build-time path to the BPF object so the userspace binary can find it.
add_compile_definitions(BPF_OBJ_PATH="${BPF_OBJ}")

# ── Userspace binary ──────────────────────────────────────────────────────────
set(CPP_SOURCES
    src/main.cpp
    src/config.cpp
    src/iface_capture.cpp
    src/udp_socket.cpp
    src/xsk_socket.cpp
)

add_executable(dataplane ${CPP_SOURCES})
add_dependencies(dataplane bpf_prog)

target_include_directories(dataplane PRIVATE
    include
    ${LIBBPF_INCLUDE_DIRS}
)

target_link_libraries(dataplane PRIVATE
    ${LIBBPF_LIBRARIES}
    elf
    z
)

target_compile_options(dataplane PRIVATE
    ${LIBBPF_CFLAGS_OTHER}
    -Wall
    -Wextra
    -Wpedantic
)

# ── Install ───────────────────────────────────────────────────────────────────
install(TARGETS dataplane RUNTIME DESTINATION bin)
install(FILES ${BPF_OBJ} DESTINATION share/dataplane)
