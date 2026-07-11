// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 windowsair <dev@airkyi.com>
 */
#include <iostream>
#include <string>
#include <string_view>
#include "asio.hpp"
#include "rule.hpp"

namespace caboti {
auto StringToLpmKey(const std::string &str) -> struct ipv4_lpm_key {
  std::string_view s{str};
  std::string ip_str;
  asio::error_code ec;
  struct ipv4_lpm_key ret = {
      .prefix_len = UINT32_MAX,
      .data = 0,
  };

  auto pos = s.find("/");
  if (pos == s.npos) {
    ip_str = s;
    ret.prefix_len = 32;
  } else {
    ip_str = s.substr(0, pos);
    auto prefix_str = s.substr(pos + 1);
    int result;
    auto [ptr,
          err] = std::from_chars(prefix_str.data(), prefix_str.data() + prefix_str.size(), result);

    if (err != std::errc()) {
      return ret;
    }

    if (result < 0 || result > 32) {
      std::cerr << "Invalid CIDR prefix length:" << str << std::endl;
      return ret;
    }

    ret.prefix_len = result;
  }

  auto addr = asio::ip::make_address(ip_str, ec);
  if (ec) {
    std::cerr << "Invalid IP address:" << str << std::endl;
    ret.prefix_len = UINT32_MAX;
    return ret;
  }
  if (addr.is_v6()) {
    // TODO: IPv6
    std::cerr << "IPv6 not support:" << str << std::endl;
    ret.prefix_len = UINT32_MAX;
    return ret;
  }

  ret.data = htonl(addr.to_v4().to_uint());
  return ret;

}

auto UpdateRules(std::vector<CabotiSocksRule> &rules) -> void
{
  CabotiSocksRule rule;
  CabotiSocksRule default_rule;

  std::vector<std::string> ip_list = {
      "0.0.0.0/8",
      "10.0.0.0/8",
      "100.64.0.0/10",
      "127.0.0.0/8",
      "169.254.0.0/16",
      "172.16.0.0/12",
      "192.0.0.0/24",
      "192.0.2.0/24",
      "192.88.99.0/24",
      "192.168.0.0/16",
      "198.18.0.0/15",
      "198.51.100.0/24",
      "203.0.113.0/24",
      "224.0.0.0/3",
  };

  for (auto &str : ip_list) {
    auto lpm_key = StringToLpmKey(str);
    if (lpm_key.prefix_len == UINT32_MAX) {
      continue;
    }
    rule.ip.emplace_back(std::move(lpm_key));
  }

  rule.port = htons(0);
  default_rule.port = htons(0);
  rule.op = OutBoundTag::DIRECT;
  default_rule.op = OutBoundTag::PROXY;

  rules.emplace_back(std::move(rule));
  rules.emplace_back(std::move(default_rule));
}

} // namespace caboti
