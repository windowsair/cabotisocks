/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2026 windowsair <dev@airkyi.com>
 */
#ifndef _UDP_RELAY_HPP_
#define _UDP_RELAY_HPP_

#include "asio/awaitable.hpp"
#include "cabotisocks.hpp"
#include "rule.hpp"

namespace caboti {
asio::awaitable<void> udp_listener(CabotiSocks &ctx,
                                   uint16_t listen_port,
                                   const std::string &socks_host,
                                   uint16_t socks_port);
}; // namespace caboti

#endif
