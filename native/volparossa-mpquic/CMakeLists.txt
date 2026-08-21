# SPDX-License-Identifier: GPL-3.0-only

cmake_minimum_required(VERSION 3.25)
project(volparossa_mpquic VERSION 0.1.0 LANGUAGES C)

include(CTest)

option(VMP_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(VMP_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(VMP_BUILD_FUZZER "Build the libFuzzer parser target (Clang only)" OFF)
option(VMP_BUILD_DAEMON "Build the pinned mqvpn/xquic process" OFF)

set(VMP_DAEMON_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/build"
    CACHE PATH "Directory for the volparossa-mpquic executable")

add_library(volparossa_mpquic_protocol STATIC src/protocol.c)
target_include_directories(volparossa_mpquic_protocol
    PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>")
target_compile_features(volparossa_mpquic_protocol PUBLIC c_std_11)
set_target_properties(volparossa_mpquic_protocol PROPERTIES
    C_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON)

add_library(volparossa_mpquic_server STATIC src/server.c)
target_include_directories(volparossa_mpquic_server
    PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>")
target_compile_features(volparossa_mpquic_server PUBLIC c_std_11)
target_link_libraries(volparossa_mpquic_server
    PUBLIC volparossa_mpquic_protocol)
set_target_properties(volparossa_mpquic_server PROPERTIES
    C_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON)

add_library(volparossa_mpquic_runtime STATIC src/runtime.c)
target_include_directories(volparossa_mpquic_runtime
    PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>")
target_compile_features(volparossa_mpquic_runtime PUBLIC c_std_11)
target_link_libraries(volparossa_mpquic_runtime
    PUBLIC volparossa_mpquic_server)
set_target_properties(volparossa_mpquic_runtime PROPERTIES
    C_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON)

add_library(volparossa_mpquic_daemon_socket STATIC src/daemon_socket.c)
target_include_directories(volparossa_mpquic_daemon_socket
    PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>")
target_compile_features(volparossa_mpquic_daemon_socket PUBLIC c_std_11)
set_target_properties(volparossa_mpquic_daemon_socket PROPERTIES
    C_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(volparossa_mpquic_protocol PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wstrict-prototypes
        -Werror)
    target_compile_options(volparossa_mpquic_server PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wstrict-prototypes
        -Werror)
    target_compile_options(volparossa_mpquic_runtime PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wstrict-prototypes
        -Werror)
    target_compile_options(volparossa_mpquic_daemon_socket PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wstrict-prototypes
        -Werror)
endif()

if(VMP_ENABLE_ASAN)
    target_compile_options(volparossa_mpquic_protocol PUBLIC
        -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(volparossa_mpquic_protocol PUBLIC -fsanitize=address)
    target_compile_options(volparossa_mpquic_server PUBLIC
        -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(volparossa_mpquic_server PUBLIC -fsanitize=address)
    target_compile_options(volparossa_mpquic_runtime PUBLIC
        -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(volparossa_mpquic_runtime PUBLIC -fsanitize=address)
    target_compile_options(volparossa_mpquic_daemon_socket PUBLIC
        -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(volparossa_mpquic_daemon_socket PUBLIC -fsanitize=address)
endif()

if(VMP_ENABLE_UBSAN)
    target_compile_options(volparossa_mpquic_protocol PUBLIC
        -fsanitize=undefined -fno-omit-frame-pointer)
    target_link_options(volparossa_mpquic_protocol PUBLIC -fsanitize=undefined)
    target_compile_options(volparossa_mpquic_server PUBLIC
        -fsanitize=undefined -fno-omit-frame-pointer)
    target_link_options(volparossa_mpquic_server PUBLIC -fsanitize=undefined)
    target_compile_options(volparossa_mpquic_runtime PUBLIC
        -fsanitize=undefined -fno-omit-frame-pointer)
    target_link_options(volparossa_mpquic_runtime PUBLIC -fsanitize=undefined)
    target_compile_options(volparossa_mpquic_daemon_socket PUBLIC
        -fsanitize=undefined -fno-omit-frame-pointer)
    target_link_options(volparossa_mpquic_daemon_socket PUBLIC -fsanitize=undefined)
endif()

if(VMP_BUILD_DAEMON)
    set(VMP_MQVPN_SOURCE_DIR
        "${CMAKE_CURRENT_SOURCE_DIR}/build/upstream/source/mqvpn"
        CACHE PATH "Patched exported mqvpn source")
    set(VMP_MQVPN_LIBRARY
        "${CMAKE_CURRENT_SOURCE_DIR}/build/upstream/mqvpn/libmqvpn.a"
        CACHE FILEPATH "Pinned static mqvpn library")
    set(VMP_LWIP_LIBRARY
        "${CMAKE_CURRENT_SOURCE_DIR}/build/upstream/mqvpn/liblwip_core.a"
        CACHE FILEPATH "Pinned static lwIP library")
    set(VMP_XQUIC_LIBRARY
        "${CMAKE_CURRENT_SOURCE_DIR}/build/upstream/xquic/libxquic-static.a"
        CACHE FILEPATH "Pinned static xquic library")
    set(VMP_BORINGSSL_SSL_LIBRARY
        "${CMAKE_CURRENT_SOURCE_DIR}/build/upstream/boringssl/libssl.a"
        CACHE FILEPATH "Pinned static BoringSSL SSL library")
    set(VMP_BORINGSSL_CRYPTO_LIBRARY
        "${CMAKE_CURRENT_SOURCE_DIR}/build/upstream/boringssl/libcrypto.a"
        CACHE FILEPATH "Pinned static BoringSSL crypto library")
    set(VMP_BORINGSSL_INCLUDE_DIR
        "${CMAKE_CURRENT_SOURCE_DIR}/build/upstream/source/boringssl/include"
        CACHE PATH "Pinned BoringSSL headers")
    foreach(required_path
            "${VMP_MQVPN_SOURCE_DIR}/include/libmqvpn.h"
            "${VMP_BORINGSSL_INCLUDE_DIR}/openssl/sha.h"
            "${VMP_MQVPN_LIBRARY}"
            "${VMP_LWIP_LIBRARY}"
            "${VMP_XQUIC_LIBRARY}"
            "${VMP_BORINGSSL_SSL_LIBRARY}"
            "${VMP_BORINGSSL_CRYPTO_LIBRARY}")
        if(NOT EXISTS "${required_path}")
            message(FATAL_ERROR "Pinned native input is absent: ${required_path}")
        endif()
    endforeach()

    find_package(Threads REQUIRED)
    add_library(volparossa_mpquic_request_binding STATIC
        src/request_binding.c)
    target_include_directories(volparossa_mpquic_request_binding
        PUBLIC
            "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>"
            "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
        PRIVATE "${VMP_BORINGSSL_INCLUDE_DIR}")
    target_compile_features(volparossa_mpquic_request_binding PUBLIC c_std_11)
    target_link_libraries(volparossa_mpquic_request_binding
        PUBLIC "${VMP_BORINGSSL_CRYPTO_LIBRARY}" stdc++)
    set_target_properties(volparossa_mpquic_request_binding PROPERTIES
        C_EXTENSIONS OFF
        POSITION_INDEPENDENT_CODE ON)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(volparossa_mpquic_request_binding PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow
            -Wstrict-prototypes -Werror)
    endif()
    if(VMP_ENABLE_ASAN)
        target_compile_options(volparossa_mpquic_request_binding PUBLIC
            -fsanitize=address -fno-omit-frame-pointer)
        target_link_options(volparossa_mpquic_request_binding PUBLIC
            -fsanitize=address)
    endif()
    if(VMP_ENABLE_UBSAN)
        target_compile_options(volparossa_mpquic_request_binding PUBLIC
            -fsanitize=undefined -fno-omit-frame-pointer)
        target_link_options(volparossa_mpquic_request_binding PUBLIC
            -fsanitize=undefined)
    endif()

    add_executable(volparossa_mpquic_daemon
        src/main.c
        src/mqvpn_backend.c)
    target_include_directories(volparossa_mpquic_daemon PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
        "${VMP_MQVPN_SOURCE_DIR}/include")
    target_compile_features(volparossa_mpquic_daemon PRIVATE c_std_11)
    target_link_libraries(volparossa_mpquic_daemon PRIVATE
        volparossa_mpquic_runtime
        volparossa_mpquic_request_binding
        volparossa_mpquic_daemon_socket
        "${VMP_MQVPN_LIBRARY}"
        "${VMP_LWIP_LIBRARY}"
        "${VMP_XQUIC_LIBRARY}"
        "${VMP_BORINGSSL_SSL_LIBRARY}"
        "${VMP_BORINGSSL_CRYPTO_LIBRARY}"
        Threads::Threads
        "${CMAKE_DL_LIBS}"
        m
        stdc++)
    set_target_properties(volparossa_mpquic_daemon PROPERTIES
        OUTPUT_NAME volparossa-mpquic
        RUNTIME_OUTPUT_DIRECTORY "${VMP_DAEMON_OUTPUT_DIRECTORY}"
        C_EXTENSIONS OFF)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(volparossa_mpquic_daemon PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow
            -Wstrict-prototypes -Werror)
    endif()
    if(VMP_ENABLE_ASAN)
        target_compile_options(volparossa_mpquic_daemon PRIVATE
            -fsanitize=address -fno-omit-frame-pointer)
        target_link_options(volparossa_mpquic_daemon PRIVATE -fsanitize=address)
    endif()
    if(VMP_ENABLE_UBSAN)
        target_compile_options(volparossa_mpquic_daemon PRIVATE
            -fsanitize=undefined -fno-omit-frame-pointer)
        target_link_options(volparossa_mpquic_daemon PRIVATE -fsanitize=undefined)
    endif()
    install(TARGETS volparossa_mpquic_daemon
            RUNTIME DESTINATION libexec/volparossa)

    if(BUILD_TESTING)
        add_executable(test_volparossa_mpquic_request_binding
            tests/test_request_binding.c)
        target_link_libraries(test_volparossa_mpquic_request_binding
            PRIVATE volparossa_mpquic_request_binding)
        if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
            target_compile_options(
                test_volparossa_mpquic_request_binding PRIVATE
                -Wall -Wextra -Wpedantic -Wconversion -Wshadow
                -Wstrict-prototypes -Werror -UNDEBUG)
        endif()
        add_test(NAME volparossa_mpquic_request_binding
                 COMMAND test_volparossa_mpquic_request_binding)
    endif()
endif()

if(BUILD_TESTING)
    add_executable(test_volparossa_mpquic_protocol tests/test_protocol.c)
    target_link_libraries(test_volparossa_mpquic_protocol
        PRIVATE volparossa_mpquic_protocol)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(test_volparossa_mpquic_protocol PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wstrict-prototypes
            -Werror -UNDEBUG)
    endif()
    add_test(NAME volparossa_mpquic_protocol
             COMMAND test_volparossa_mpquic_protocol)

    add_executable(test_volparossa_mpquic_server tests/test_server.c)
    target_link_libraries(test_volparossa_mpquic_server
        PRIVATE volparossa_mpquic_server)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(test_volparossa_mpquic_server PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wstrict-prototypes
            -Werror -UNDEBUG)
        target_link_options(test_volparossa_mpquic_server PRIVATE
            "-Wl,--wrap=recvmsg")
    endif()
    add_test(NAME volparossa_mpquic_server
             COMMAND test_volparossa_mpquic_server)

    add_executable(test_volparossa_mpquic_runtime tests/test_runtime.c)
    target_link_libraries(test_volparossa_mpquic_runtime
        PRIVATE volparossa_mpquic_runtime)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(test_volparossa_mpquic_runtime PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wstrict-prototypes
            -Werror -UNDEBUG)
    endif()
    add_test(NAME volparossa_mpquic_runtime
             COMMAND test_volparossa_mpquic_runtime)

    add_executable(test_volparossa_mpquic_daemon_socket
        tests/test_daemon_socket.c)
    target_link_libraries(test_volparossa_mpquic_daemon_socket
        PRIVATE volparossa_mpquic_daemon_socket)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(test_volparossa_mpquic_daemon_socket PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wstrict-prototypes
            -Werror -UNDEBUG)
    endif()
    add_test(NAME volparossa_mpquic_daemon_socket
             COMMAND test_volparossa_mpquic_daemon_socket)
endif()

if(VMP_BUILD_FUZZER)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "VMP_BUILD_FUZZER requires Clang/libFuzzer")
    endif()
    add_executable(fuzz_volparossa_mpquic_protocol fuzz/fuzz_protocol.c)
    target_link_libraries(fuzz_volparossa_mpquic_protocol
        PRIVATE volparossa_mpquic_protocol)
    target_compile_options(fuzz_volparossa_mpquic_protocol PRIVATE
        -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
    target_link_options(fuzz_volparossa_mpquic_protocol PRIVATE
        -fsanitize=fuzzer,address,undefined)
endif()
