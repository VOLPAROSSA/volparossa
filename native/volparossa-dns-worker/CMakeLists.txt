# SPDX-License-Identifier: GPL-3.0-only
cmake_minimum_required(VERSION 3.25)
project(volparossa_dns_worker VERSION 0.1.0 LANGUAGES C)

find_path(UNBOUND_INCLUDE_DIR unbound.h REQUIRED)
find_library(UNBOUND_LIBRARY unbound REQUIRED)
add_executable(volparossa-dns-worker src/main.c)
target_include_directories(volparossa-dns-worker PRIVATE "${UNBOUND_INCLUDE_DIR}")
target_link_libraries(volparossa-dns-worker PRIVATE "${UNBOUND_LIBRARY}")
target_compile_features(volparossa-dns-worker PRIVATE c_std_11)
target_compile_options(volparossa-dns-worker PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wstrict-prototypes -Werror)
set_target_properties(volparossa-dns-worker PROPERTIES C_EXTENSIONS OFF)
install(TARGETS volparossa-dns-worker RUNTIME DESTINATION libexec)
