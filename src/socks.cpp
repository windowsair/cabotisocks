// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 windowsair <dev@airkyi.com>
 */
#include <cstdint>
#include "asio/as_tuple.hpp"
#include "asio/connect.hpp"
#include "asio/read.hpp"
#include "asio/write.hpp"
#include "fmt/core.h"
#include "socks.hpp"

namespace caboti {
using asio::ip::tcp;
using tcp_acceptor = asio::use_awaitable_t<>::as_default_on_t<tcp::acceptor>;
using tcp_socket = asio::use_awaitable_t<>::as_default_on_t<tcp::socket>;

auto SocksAuthHandshake(tcp_socket &sock, const SocksServerConfig &cfg) -> asio::awaitable<int>
{
  asio::error_code ec;
  const bool has_creds = !cfg.username.empty() || !cfg.password.empty();

  std::vector<uint8_t> methods;
  methods.reserve(128);
  if (has_creds) {
    methods = {to_underlying(SocksAuthMethod::NO_AUTH), to_underlying(SocksAuthMethod::PASSWORD)};
  } else {
    methods = {to_underlying(SocksAuthMethod::NO_AUTH)};
  }

  std::vector<uint8_t> req = {to_underlying(SocksVersion::SOCKS5),
                              static_cast<uint8_t>(methods.size())};
  req.insert(req.end(), methods.begin(), methods.end());
  co_await asio::async_write(sock, asio::buffer(req), asio::use_awaitable);

  uint8_t res[2];
  co_await asio::async_read(sock, asio::buffer(res), asio::use_awaitable);
  if (res[0] != to_underlying(SocksVersion::SOCKS5)) {
    fmt::println(stderr, "SOCKS5: Invalid version");
    sock.close(ec);
    co_return -1;
  }

  auto server_method = static_cast<SocksAuthMethod>(res[1]);

  if (server_method == SocksAuthMethod::NO_AUTH) {
    co_return 0;
  } else if (server_method == SocksAuthMethod::PASSWORD) {
    if (!has_creds) {
      fmt::println(stderr, "SOCKS5: need passowrd");
      sock.close(ec);
      co_return -1;
    }

    // RFC1929 auth
    std::vector<uint8_t> auth_req = {0x01, // version
                                     static_cast<uint8_t>(cfg.username.size())};
    auth_req.insert(auth_req.end(), cfg.username.begin(), cfg.username.end());
    auth_req.push_back(static_cast<uint8_t>(cfg.password.size()));
    auth_req.insert(auth_req.end(), cfg.password.begin(), cfg.password.end());

    co_await asio::async_write(sock, asio::buffer(auth_req), asio::use_awaitable);

    uint8_t auth_res[2];
    co_await asio::async_read(sock, asio::buffer(auth_res), asio::use_awaitable);

    if (auth_res[0] != 0x01 || auth_res[1] != 0x00) {
      fmt::println(stderr, "SOCKS5: Invalid username or password");
      sock.close(ec);
      co_return -1;
    }

    co_return 0;
  }

  fmt::println(stderr, "SOCKS5: failed to auth");
  sock.close(ec);
  co_return -1;
}

auto SocksServerConnect(asio::any_io_executor ex,
                        const SocksServerConfig &cfg,
                        const std::string &target_host,
                        uint16_t target_port) -> asio::awaitable<std::optional<tcp_socket>>
{
  tcp::resolver resolver(ex);

  auto [ec, eps] = co_await resolver.async_resolve(cfg.host,
                                                   std::to_string(cfg.port),
                                                   asio::as_tuple(asio::use_awaitable));
  if (ec) {
    co_return std::nullopt;
  }

  tcp_socket sock(ex);
  tcp::no_delay option(true);
  sock.set_option(option, ec);

  auto [ec2, _] = co_await asio::async_connect(sock, eps, asio::as_tuple(asio::use_awaitable));
  if (ec2) {
    sock.close(ec2);
    co_return std::nullopt;
  }

  if (co_await SocksAuthHandshake(sock, cfg)) {
    co_return std::nullopt;
  }
  // connect
  {
    std::vector<uint8_t> req = {to_underlying(SocksVersion::SOCKS5),
                                to_underlying(SocksCmd::CONNECT),
                                0x00};
    auto addr = asio::ip::make_address(target_host, ec);
    if (!ec) {
      // target is ip address
      if (addr.is_v4()) {
        req.push_back(to_underlying(SocksAddrType::IPV4));
        auto bytes = addr.to_v4().to_bytes();
        req.insert(req.end(), bytes.begin(), bytes.end());
      } else {
        req.push_back(to_underlying(SocksAddrType::IPV6));
        auto bytes = addr.to_v6().to_bytes();
        req.insert(req.end(), bytes.begin(), bytes.end());
      }
    } else {
      // target is domain name
      req.push_back(to_underlying(SocksAddrType::DOMAINNAME));
      req.push_back(static_cast<uint8_t>(target_host.size()));
      req.insert(req.end(), target_host.begin(), target_host.end());
    }

    req.push_back(static_cast<uint8_t>(target_port >> 8));
    req.push_back(static_cast<uint8_t>(target_port & 0xff));
    co_await asio::async_write(sock, asio::buffer(req), asio::use_awaitable);

    uint8_t header[4];
    co_await asio::async_read(sock, asio::buffer(header), asio::use_awaitable);
    if (header[0] != to_underlying(SocksVersion::SOCKS5)) {
      fmt::println(stderr, "Invalid socks version in reply");
      sock.close(ec);
      co_return std::nullopt;
    }

    if (header[1] != to_underlying(SocksReply::SUCCEEDED)) {
      fmt::println(stderr, "SOCKS5 connect failed: {}", static_cast<int>(header[1]));
      sock.close(ec);
      co_return std::nullopt;
    }

    uint8_t addr_len = 0;
    switch (header[3]) {
      case to_underlying(SocksAddrType::IPV4):
        addr_len = 4;
        break;
      case to_underlying(SocksAddrType::IPV6):
        addr_len = 16;
        break;
      case to_underlying(SocksAddrType::DOMAINNAME):
        co_await asio::async_read(sock, asio::buffer(&addr_len, 1), asio::use_awaitable);
        break;
      default:
        fmt::println(stderr, "Unknown socks addr type");
        sock.close(ec);
        co_return std::nullopt;
    }

    if (addr_len > 253) {
      fmt::println(stderr, "Domain address length too long: {}", static_cast<int>(addr_len));
      sock.close(ec);
      co_return std::nullopt;
    }

    std::vector<uint8_t> discard(addr_len + 2);
    co_await asio::async_read(sock, asio::buffer(discard), asio::use_awaitable);
  }

  fmt::println("Connection established to {}:{}", target_host, target_port);
  co_return std::move(sock);
}

auto SocksServerAssociate(asio::any_io_executor ex,
                          const SocksServerConfig &cfg,
                          asio::ip::address &udp_address,
                          uint16_t &udp_port) -> asio::awaitable<std::optional<tcp_socket>>
{
  tcp::resolver resolver(ex);

  auto [ec, eps] = co_await resolver.async_resolve(cfg.host,
                                                   std::to_string(cfg.port),
                                                   asio::as_tuple(asio::use_awaitable));
  if (ec) {
    co_return std::nullopt;
  }

  tcp_socket sock(ex);
  tcp::no_delay option(true);
  sock.set_option(option, ec);
  asio::socket_base::keep_alive keepalive_option(true);
  sock.set_option(keepalive_option, ec);

  auto [ec2, _] = co_await asio::async_connect(sock, eps, asio::as_tuple(asio::use_awaitable));
  if (ec2) {
    sock.close(ec2);
    co_return std::nullopt;
  }

  if (co_await SocksAuthHandshake(sock, cfg)) {
    co_return std::nullopt;
  }
  // associate
  {
    std::vector<uint8_t> req = {to_underlying(SocksVersion::SOCKS5),
                                to_underlying(SocksCmd::UDP_ASSOCIATE),
                                0x00};
    // TODO: ipv6 support
    auto addr = asio::ip::make_address("0.0.0.0", ec);
    if (!ec) {
      // target is ip address
      if (addr.is_v4()) {
        req.push_back(to_underlying(SocksAddrType::IPV4));
        auto bytes = addr.to_v4().to_bytes();
        req.insert(req.end(), bytes.begin(), bytes.end());
      } else {
        req.push_back(to_underlying(SocksAddrType::IPV6));
        auto bytes = addr.to_v6().to_bytes();
        req.insert(req.end(), bytes.begin(), bytes.end());
      }
    }

    // zero port
    req.push_back(0);
    req.push_back(0);
    // TODO: noexcept process
    co_await asio::async_write(sock, asio::buffer(req), asio::use_awaitable);

    uint8_t header[4];
    co_await asio::async_read(sock, asio::buffer(header), asio::use_awaitable);
    if (header[0] != to_underlying(SocksVersion::SOCKS5)) {
      fmt::println(stderr, "Invalid socks version in reply");
      sock.close(ec);
      co_return std::nullopt;
    }

    if (header[1] != to_underlying(SocksReply::SUCCEEDED)) {
      fmt::println(stderr, "SOCKS5 associate failed: {}", static_cast<int>(header[1]));
      sock.close(ec);
      co_return std::nullopt;
    }

    uint8_t addr_len = 0;
    switch (header[3]) {
      case to_underlying(SocksAddrType::IPV4):
        addr_len = 4;
        break;
      case to_underlying(SocksAddrType::IPV6):
        addr_len = 16;
        break;
      case to_underlying(SocksAddrType::DOMAINNAME):
        co_await asio::async_read(sock, asio::buffer(&addr_len, 1), asio::use_awaitable);
        break;
      default:
        fmt::println(stderr, "Unknown socks addr type");
        sock.close(ec);
        co_return std::nullopt;
    }

    if (addr_len > 253) {
      fmt::println(stderr, "Domain address length too long: {}", static_cast<int>(addr_len));
      sock.close(ec);
      co_return std::nullopt;
    }

    std::vector<uint8_t> addr_info(addr_len + 2);
    co_await asio::async_read(sock, asio::buffer(addr_info), asio::use_awaitable);

    udp_port = (addr_info[addr_info.size() - 2] << 8) | addr_info[addr_info.size() - 1];
    switch (header[3]) {
      case to_underlying(SocksAddrType::IPV4): {
        asio::ip::address_v4::bytes_type arr;
        std::memcpy(arr.data(), addr_info.data(), 4);
        asio::ip::address_v4 v4{arr};
        udp_address = asio::ip::address{v4};
        break;
      }
      case to_underlying(SocksAddrType::IPV6): {
        asio::ip::address_v6::bytes_type arr;
        std::memcpy(arr.data(), addr_info.data(), 16);
        asio::ip::address_v6 v6{arr};
        udp_address = asio::ip::address{v6};
        break;
      }
      case to_underlying(SocksAddrType::DOMAINNAME):
      default:
        fmt::println(stderr, "SOCKS associate type not support");
        sock.close(ec);
        co_return std::nullopt;
    }
  }

  co_return std::move(sock);
}

}; // namespace caboti
