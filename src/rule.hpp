/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2026 windowsair <dev@airkyi.com>
 */
#ifndef _RULE_HPP_
#define _RULE_HPP_

#include <cstdint>
#include <vector>
#include <string>

namespace caboti {
enum class OutBoundTag : std::uint8_t;

struct SocksServerConfig {
  std::string username;
  std::string password;
  std::string host;
  uint16_t port;
};

struct CabotiSocksRule {
  std::string comm;
  std::vector<struct ipv4_lpm_key> ip;
  std::uint16_t port;
  OutBoundTag action;

  CabotiSocksRule() = default;
};

class CabotiSocksConfig {
public:
  CabotiSocksConfig() = default;

  auto IsUdpEnabled() const -> bool
  {
    return enable_udp_;
  }

  auto GetRules() const -> const std::vector<CabotiSocksRule> &
  {
    return rules_;
  }

  auto GetIncludeCgPath() const -> const std::string &
  {
    return include_cg_path_;
  }

  auto GetExcludeCgPath() const -> const std::string &
  {
    return exclude_cg_path_;
  }

  auto Init() -> int;

private:
  auto UpdateRules() -> void;

private:
  std::string include_cg_path_;
  std::string exclude_cg_path_;
  std::vector<CabotiSocksRule> rules_;
  bool enable_udp_;
};
} // namespace caboti

#endif
