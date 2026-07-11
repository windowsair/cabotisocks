# SPDX-License-Identifier: GPL-2.0-or-later
cmake_minimum_required(VERSION 3.14)
project(caboti_project)

# generate compile_commands.json for clangd
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_C_COMPILER clang)
#set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_CXX_STANDARD 20)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/")
include(cmake/CPM.cmake)
include(ExternalProject)

# asio support
CPMAddPackage(
  NAME asiocmake
  GIT_REPOSITORY "https://github.com/OlivierLDff/asio.cmake"
  GIT_TAG "main"
)
# scope-exit support
CPMAddPackage(
  NAME scope-lite
  GIT_REPOSITORY "https://github.com/nonstd-lite/scope-lite"
  GIT_TAG "master"
)
# libbpf support
CPMAddPackage(
  NAME libbpf
  GITHUB_REPOSITORY libbpf/libbpf
  GIT_TAG v1.7.0
  DOWNLOAD_ONLY YES
)
# bpftool support
CPMAddPackage(
  NAME bpftool
  GITHUB_REPOSITORY libbpf/bpftool
  GIT_TAG v7.7.0
  DOWNLOAD_ONLY YES
)

ExternalProject_Add(libbpf
  PREFIX libbpf
  SOURCE_DIR ${libbpf_SOURCE_DIR}/src
  CONFIGURE_COMMAND ""
  BUILD_COMMAND make
    CC=${CMAKE_C_COMPILER}
    BUILD_STATIC_ONLY=1
    OBJDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf
    DESTDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf
    INCLUDEDIR=
    LIBDIR=
    UAPIDIR=
    install install_uapi_headers
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  STEP_TARGETS build
  BUILD_BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf.a
)

ExternalProject_Add(bpftool
  PREFIX bpftool
  SOURCE_DIR ${bpftool_SOURCE_DIR}/src
  CONFIGURE_COMMAND ""
  BUILD_COMMAND make bootstrap
    OUTPUT=${CMAKE_CURRENT_BINARY_DIR}/bpftool/
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  STEP_TARGETS build
)

# build libbpf
set(BPFOBJECT_BPFTOOL_EXE ${CMAKE_CURRENT_BINARY_DIR}/bpftool/bootstrap/bpftool)
set(LIBBPF_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/libbpf)
set(LIBBPF_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf.a)
find_package(BpfObject REQUIRED)

bpf_object(caboti bpf/caboti.bpf.c)

add_executable(cabotisocks
  src/cabotisocks.cpp
  src/main.cpp
  src/socks.cpp
  src/tcp_relay.cpp
  src/udp_relay.cpp
  src/rule.cpp)
target_include_directories(cabotisocks PRIVATE ${PROJECT_SOURCE_DIR})
target_compile_options(cabotisocks PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_link_libraries(cabotisocks caboti_skel asio::asio nonstd::scope-lite)
