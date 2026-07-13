// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 windowsair <dev@airkyi.com>
 */
#include <cstdint>
#include <string>
#include "asio.hpp"
#include "fmt/core.h"
#include "bpf/caboti.bpf.h"
#include "cabotisocks.hpp"
#include "rule.hpp"
#include "tcp_relay.hpp"
#include "udp_relay.hpp"

int main()
{
  constexpr uint16_t listen_port = CABOTISOCKS_TCP_REDIR_PORT;
  constexpr uint16_t udp_listen_port = CABOTISOCKS_UDP_REDIR_PORT;
  const std::string socks_host = "127.0.0.1";
  constexpr uint16_t socks_port = 10808;
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
             caboti::tcp_listener(caboti_handle, listen_port, socks_host, socks_port),
             asio::detached);

    co_spawn(io_context,
             caboti::udp_listener(caboti_handle, udp_listen_port, socks_host, socks_port),
             asio::detached);

    io_context.run();
  } catch (std::exception &e) {
    fmt::println(stderr, "Exception: {}", e.what());
  }

  return 0;
}
