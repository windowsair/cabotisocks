/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2026 windowsair <dev@airkyi.com>
 */
#ifndef _TCP_RELAY_HPP_
#define _TCP_RELAY_HPP_

#include "asio/awaitable.hpp"
#include "cabotisocks.hpp"

namespace caboti {
asio::awaitable<void> tcp_listener(CabotiSocks &ctx,
                                   uint16_t listen_port,
                                   const std::string &socks_host,
                                   uint16_t socks_port);
}; // namespace caboti

#endif
