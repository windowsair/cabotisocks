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

  auto GetIncludeCgPaths() const -> const std::vector<std::string> &
  {
    return include_cg_paths_;
  }

  auto GetExcludeCgPath() const -> const std::string &
  {
    return exclude_cg_path_;
  }

  auto GetServer() const -> const SocksServerConfig &
  {
    return server_;
  }

  auto Init(const std::string &path) -> int;

private:
  auto ParseConfig(const std::string &path) -> int;
  auto UpdateRules(CabotiSocksRule &rule, const std::vector<std::string> &host_list) -> void;

private:
  std::vector<std::string> include_cg_paths_;
  std::string exclude_cg_path_;
  std::vector<CabotiSocksRule> rules_;
  SocksServerConfig server_;
  bool enable_udp_;
};
} // namespace caboti

#endif
