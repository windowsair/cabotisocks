/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2026 windowsair <dev@airkyi.com>
 */
#ifndef _CABOTISOCKS_HPP_
#define _CABOTISOCKS_HPP_

#include <cstdint>
#include <memory>
#include <map>
#include <optional>
#include "rule.hpp"

namespace caboti {
// host order
struct Ipv4Endpoint {
  uint32_t addr;
  uint32_t port;

  auto operator<=>(const Ipv4Endpoint &) const = default;
};

struct OriginalDestInfo {
  uint32_t ip;
  uint32_t tgid;
  uint16_t port;
};

struct ConnectTable {
  // app for local, up for remote
  int app_fd;
  int up_fd;
  uint32_t app_key;
  uint32_t up_key;
  uint64_t app_cookie;
  uint64_t up_cookie;
};

class CabotiSocks {
public:
  CabotiSocks();
  ~CabotiSocks();
  // no copy
  CabotiSocks(const CabotiSocks &) = delete;
  CabotiSocks &operator=(const CabotiSocks &) = delete;
  // move only
  CabotiSocks(CabotiSocks &&) noexcept = default;
  CabotiSocks &operator=(CabotiSocks &&) noexcept = default;

public:
  int Init(const std::vector<CabotiSocksRule> &rules);
  // TCP
  std::optional<OriginalDestInfo> GetOriginalDest(uint16_t src_port);
  int AddConnect(int app_fd, int up_fd);
  int DelConnect(int app_fd, int up_fd);
  // UDP
  auto GetUdpOriginalDest(const Ipv4Endpoint &src) -> std::optional<Ipv4Endpoint>;

private:
  using AppFd = int;
  std::map<AppFd, ConnectTable> conn_;
  struct CabotiBpfImpl;
  std::unique_ptr<CabotiBpfImpl> bpf_impl_;
  struct KeyPool;
  std::unique_ptr<KeyPool> key_pool_;
};
} // namespace caboti

#endif
