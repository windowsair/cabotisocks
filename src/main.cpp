// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 windowsair <dev@airkyi.com>
 */
#include <cstdint>
#include <string>
#include "asio/co_spawn.hpp"
#include "asio/detached.hpp"
#include "asio/io_context.hpp"
#include "asio/signal_set.hpp"
#include "fmt/core.h"
#include "bpf/caboti.bpf.h"
#include "cabotisocks.hpp"
#include "rule.hpp"
#include "tcp_relay.hpp"
#include "udp_relay.hpp"

auto main() -> int
{
  constexpr uint16_t listen_port = CABOTISOCKS_TCP_REDIR_PORT;
  constexpr uint16_t udp_listen_port = CABOTISOCKS_UDP_REDIR_PORT;
  const std::string socks_host = "127.0.0.1";
  constexpr uint16_t socks_port = 10808;
  caboti::SocksServerConfig server_cfg{};
  server_cfg.host = socks_host;
  server_cfg.port = socks_port;
  fmt::println("Cabotisocks started");

  caboti::CabotiSocks caboti_handle;
  caboti::CabotiSocksConfig cfg;

  if (cfg.Init()) {
    return -1;
  }

  if (caboti_handle.Init(cfg)) {
    return -1;
  }

  try {
    asio::io_context io_context(1);

    asio::signal_set signals(io_context, SIGINT, SIGTERM);
    signals.async_wait([&](auto, auto) {
      fmt::println("Shutting down...");
      io_context.stop();
    });

    co_spawn(io_context,
             caboti::tcp_listener(caboti_handle, listen_port, server_cfg),
             asio::detached);

    co_spawn(io_context,
             caboti::udp_listener(caboti_handle, udp_listen_port, server_cfg),
             asio::detached);

    io_context.run();
  } catch (std::exception &e) {
    fmt::println(stderr, "Exception: {}", e.what());
  }

  return 0;
}
