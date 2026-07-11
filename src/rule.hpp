/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2026 windowsair <dev@airkyi.com>
 */
#ifndef _RULE_HPP_
#define _RULE_HPP_

#include <cstdint>
#include <vector>
#include <string>
#include "bpf/caboti.bpf.h"

namespace caboti {
enum class OutBoundTag : std::uint8_t {
  DIRECT = CABOTISOCKS_DIRECT,
  PROXY = CABOTISOCKS_PROXY,
  BLOCK = CABOTISOCKS_BLOCK,
};

struct CabotiSocksRule {
  std::string comm;
  std::vector<struct ipv4_lpm_key> ip;
  std::uint16_t port;
  OutBoundTag op;

  CabotiSocksRule() = default;
};

auto UpdateRules(std::vector<CabotiSocksRule> &rules) -> void;

} // namespace caboti

#endif
