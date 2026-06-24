// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 windowsair <dev@airkyi.com>
 */
#include <cstdint>
#include <iostream>
#include <string>
#include "asio.hpp"
#include "cabotisocks.hpp"
#include "udp_relay.hpp"
#include "tcp_relay.hpp"

int main()
{
  constexpr uint16_t listen_port = 1081;
  constexpr uint16_t udp_listen_port = 5353;
  const std::string socks_host = "127.0.0.1";
  constexpr uint16_t socks_port = 10808;
  std::cout << "Cabotisocks started\n";
  caboti::CabotiSocks caboti_handle;
  if (caboti_handle.Init()) {
    return -1;
  }

  try {
    asio::io_context io_context(1);

    asio::signal_set signals(io_context, SIGINT, SIGTERM);
    signals.async_wait([&](auto, auto) {
      std::cout << "Shutting down..." << std::endl;
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
    std::cerr << "Exception:" << e.what() << std::endl;
  }

  return 0;
}
