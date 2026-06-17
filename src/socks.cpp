// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 windowsair <dev@airkyi.com>
 */
#include <iostream>
#include "socks.hpp"

namespace caboti {
using asio::ip::tcp;
using tcp_acceptor = asio::use_awaitable_t<>::as_default_on_t<tcp::acceptor>;
using tcp_socket = asio::use_awaitable_t<>::as_default_on_t<tcp::socket>;

auto SocksServerConnect(asio::any_io_executor ex,
                        const std::string &socks_host,
                        uint16_t socks_port,
                        const std::string &target_host,
                        uint16_t target_port) -> asio::awaitable<std::optional<tcp_socket>>
{
  tcp::resolver resolver(ex);

  auto [ec, eps] = co_await resolver.async_resolve(socks_host,
                                                   std::to_string(socks_port),
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

  {
    const uint8_t req[] = {to_underlying(SocksVersion::SOCKS5),
                           0x01,
                           to_underlying(SocksAuthMethod::NO_AUTH)};
    uint8_t res[2];

    co_await asio::async_write(sock, asio::buffer(req), asio::use_awaitable);
    co_await asio::async_read(sock, asio::buffer(res), asio::use_awaitable);
    if (res[0] != req[0] || res[1] != req[2]) {
      sock.close(ec);
      co_return std::nullopt;
    }
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
      std::cerr << "invalid socks version in reply\n";
      sock.close(ec);
      co_return std::nullopt;
    }

    if (header[1] != to_underlying(SocksReply::SUCCEEDED)) {
      std::cerr << "SOCKS5 connect failed: " << static_cast<int>(header[1]) << "\n";
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
        std::cerr << "unknown socks addr type\n";
        sock.close(ec);
        co_return std::nullopt;
    }

    if (addr_len > 253) {
      std::cerr << "domain address length too long: " << static_cast<int>(addr_len) << "\n";
      sock.close(ec);
      co_return std::nullopt;
    }

    std::vector<uint8_t> discard(addr_len + 2);
    co_await asio::async_read(sock, asio::buffer(discard), asio::use_awaitable);
  }

  std::cout << "SOCKS5 connection established to " << target_host << ":" << target_port << "\n";
  co_return std::move(sock);
}
}; // namespace caboti
