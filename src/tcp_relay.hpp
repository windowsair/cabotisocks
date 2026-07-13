/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2026 windowsair <dev@airkyi.com>
 */
#ifndef _TCP_RELAY_HPP_
#define _TCP_RELAY_HPP_

#include "asio/awaitable.hpp"
#include "cabotisocks.hpp"
#include "rule.hpp"

namespace caboti {
auto tcp_listener(CabotiSocks &ctx, uint16_t listen_port, const SocksServerConfig &cfg)
    -> asio::awaitable<void>;
}; // namespace caboti

#endif
