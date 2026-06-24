/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2026 windowsair <dev@airkyi.com>
 */
#ifndef _SOCKS_HPP_
#define _SOCKS_HPP_

#include <cstdint>
#include <optional>
#include <type_traits>
#include "asio.hpp"
#include "asio/awaitable.hpp"

namespace caboti {
template<typename E>
constexpr auto to_underlying(E e) noexcept
{
  return static_cast<std::underlying_type_t<E>>(e);
}

enum class SocksVersion : std::uint8_t {
  SOCKS4 = 0x04,
  SOCKS5 = 0x05,
};

enum class SocksAuthMethod : std::uint8_t {
  NO_AUTH = 0x00,
  GSSAPI = 0x01,
  PASSWORD = 0x02,
  NO_ACCEPTABLE_METHODS = 0xFF,
};

enum class SocksCmd : std::uint8_t {
  CONNECT = 0x01,
  BIND = 0x02,
  UDP_ASSOCIATE = 0x03,
};

enum class SocksAddrType : std::uint8_t {
  IPV4 = 0x01,
  DOMAINNAME = 0x03,
  IPV6 = 0x04,
};

enum class SocksReply : std::uint8_t {
  SUCCEEDED = 0x00,
  GENERAL_FAILURE = 0x01,
  CONNECTION_NOT_ALLOWED = 0x02,
  NETWORK_UNREACHABLE = 0x03,
  HOST_UNREACHABLE = 0x04,
  CONNECTION_REFUSED = 0x05,
  TTL_EXPIRED = 0x06,
  COMMAND_NOT_SUPPORTED = 0x07,
  ADDR_TYPE_NOT_SUPPORTED = 0x08,
};

asio::awaitable<std::optional<asio::use_awaitable_t<>::as_default_on_t<asio::ip::tcp::socket>>>
SocksServerConnect(asio::any_io_executor ex,
                   const std::string &socks_host,
                   uint16_t socks_port,
                   const std::string &target_host,
                   uint16_t target_port);

asio::awaitable<std::optional<asio::use_awaitable_t<>::as_default_on_t<asio::ip::tcp::socket>>>
SocksServerAssociate(asio::any_io_executor ex,
                     const std::string &socks_host,
                     uint16_t socks_port,
                     asio::ip::address &udp_address,
                     uint16_t &udp_port);

} // namespace caboti
#endif
