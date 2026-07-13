// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 windowsair <dev@airkyi.com>
 */
#include <cstdint>
#include <optional>
#include "asio.hpp"
#include "asio/as_tuple.hpp"
#include "asio/awaitable.hpp"
#include "asio/experimental/awaitable_operators.hpp"
#include "fmt/core.h"
#include "cabotisocks.hpp"
#include "socks.hpp"
#include "tcp_relay.hpp"

namespace caboti {
using asio::ip::tcp;
using tcp_acceptor = asio::use_awaitable_t<>::as_default_on_t<tcp::acceptor>;
using tcp_socket = asio::use_awaitable_t<>::as_default_on_t<tcp::socket>;

auto relay(tcp_socket &src, tcp_socket &dst) -> asio::awaitable<void>
{
  std::array<char, 2048> buf;

  auto cleanup = [&dst](const asio::system_error &e) -> bool {
    asio::error_code ec;
    if (e.code() == asio::error::eof) {
      // FIN propagation
      dst.shutdown(tcp::socket::shutdown_send, ec);
      return true;
    } else if (e.code().value()) {
      // RST
      dst.close(ec);
      return true;
    }

    return false;
  };

  for (;;) {
    auto [ec, nread] = co_await src.async_read_some(asio::buffer(buf),
                                                    asio::as_tuple(asio::use_awaitable));
    if (cleanup(ec)) {
      co_return;
    }
    auto [ec2, nwrite] = co_await asio::async_write(dst,
                                                    asio::buffer(buf.data(), nread),
                                                    asio::as_tuple(asio::use_awaitable));
    if (cleanup(ec2)) {
      co_return;
    }
  }
}

auto tcp_session(CabotiSocks &ctx,
                 tcp_socket local,
                 const std::string &socks_host,
                 uint16_t socks_port) -> asio::awaitable<void>
{
  using namespace asio::experimental::awaitable_operators;

  int ret;
  int app_fd = local.native_handle();
  auto origin_dest = ctx.GetOriginalDest(local.remote_endpoint().port());
  if (!origin_dest.has_value()) {
    local.close();
    co_return;
  }

  auto target_ip = asio::ip::address_v4(origin_dest->ip);
  auto target_addr = target_ip.to_string();
  auto target_port = origin_dest->port;

  // connect to remote socks server
  auto ex = co_await asio::this_coro::executor;
  auto connect_res =
      co_await SocksServerConnect(ex, socks_host, socks_port, target_addr, target_port);
  if (!connect_res.has_value()) {
    fmt::println(stderr, "SOCKS5 connect failed");
    local.close();
    co_return;
  }
  auto remote = std::move(connect_res.value());

  // Try to use sockmap !
  int up_fd = remote.native_handle();
  ret = ctx.AddConnect(local.native_handle(), remote.native_handle());
  if (ret) {
    fmt::println(stderr, "Failed to use sockmap {}", local.native_handle());
  }

  // If sockmap is unavailable, fall back to simple relay.
  co_await (relay(local, remote) && relay(remote, local));

  // Must delete BPF map entries BEFORE closing sockets:
  // the kernel auto-removes closed sockets from sock_map.
  ctx.DelConnect(app_fd, up_fd);

  asio::error_code ec;
  local.close(ec);
  remote.close(ec);

  co_return;
}

auto tcp_listener(CabotiSocks &ctx,
                  uint16_t listen_port,
                  const std::string &socks_host,
                  uint16_t socks_port) -> asio::awaitable<void>
{
  auto executor = co_await asio::this_coro::executor;
  tcp_acceptor acceptor(executor, {tcp::v4(), listen_port});
  for (;;) {
    auto socket = co_await acceptor.async_accept();

    asio::error_code ec;
    asio::ip::tcp::no_delay option(true);
    socket.set_option(option, ec);
    if (ec) {
      fmt::println(stderr, "Failed to set_option:{}", ec.message());
    }

    asio::co_spawn(executor,
                   tcp_session(ctx, std::move(socket), socks_host, socks_port),
                   asio::detached);
  }
}
} // namespace caboti
