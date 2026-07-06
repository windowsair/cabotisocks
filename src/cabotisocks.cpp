// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 windowsair <dev@airkyi.com>
 */
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <netinet/in.h>
#include <optional>
#include <unistd.h>
#include "asio.hpp"
#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "bpf/caboti.bpf.h"
#include "caboti.skel.h"
#include "cabotisocks.hpp"
#include "nonstd/scope.hpp"

namespace caboti {
using namespace nonstd;

inline uint64_t getSocketCookie(int fd)
{
  uint64_t cookie = 0;
  socklen_t clen = sizeof(cookie);

  getsockopt(fd, SOL_SOCKET, SO_COOKIE, &cookie, &clen);
  return cookie;
}

constexpr auto exclude_cg_path = "/sys/fs/cgroup/system.slice/myapp.service";
constexpr auto cg_path = "/sys/fs/cgroup/cabotisocks";
//constexpr auto cg_path = "/sys/fs/cgroup/cabotisocks";
//constexpr auto cg_path = "/sys/fs/cgroup/system.slice";

class cgroup {
public:
  uint64_t inode; // cgroup id
  int fd;

  explicit cgroup(const char *path)
      : inode(0)
      , fd(-1)
  {
    if (mkdir(path, 0755) < 0 && errno != EEXIST) {
      std::cerr << "mkdir cgroup\n";
      return;
    }

    fd = open(path, O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
      std::cerr << "open cgroup (is cgroup v2 at /sys/fs/cgroup?)\n";
    }

    struct stat st;
    if (stat(path, &st) < 0) {
      std::cerr << "Failed to get cgroup inode\n";
      return;
    }
    inode = st.st_ino;
  }

  ~cgroup()
  {
    if (fd >= 0) {
      close(fd);
    }
  }
};

struct CabotiSocks::KeyPool {
public:
  explicit KeyPool(uint32_t n)
  {
    free_key.reserve(n);
    for (uint32_t i = 0; i < n; i++) {
      free_key.push_back(n - 1 - i);
    }
  }

  uint32_t Get()
  {
    int key;

    if (free_key.empty()) {
      return UINT32_MAX;
    }
    key = free_key.back();
    free_key.pop_back();
    return key;
  }

  void Put(uint32_t key)
  {
    if (key == UINT32_MAX) {
      return;
    }
    free_key.push_back(key);
  }

private:
  std::vector<uint32_t> free_key;
};

struct CabotiSocks::CabotiBpfImpl {

  caboti_bpf *ctx;
  // maps
  int sockmap_fd;
  int peermap_fd;
  int v4_connect_fd;
  int v4_udp_dest_fd;
  // program
  int parser_fd;
  int verdict_fd;
  struct bpf_link *ipv4_datagram_connect_link;
  struct bpf_link *sendmsg4_link;
  struct bpf_link *recvmsg4_link;
  struct bpf_link *connect_v4_link;
  struct bpf_link *socksop_link;

  CabotiBpfImpl()
      : ctx(nullptr)
      , sockmap_fd(-1)
      , peermap_fd(-1)
      , v4_connect_fd(-1)
      , v4_udp_dest_fd(-1)
      , parser_fd(-1)
      , verdict_fd(-1)
      , ipv4_datagram_connect_link(nullptr)
      , sendmsg4_link(nullptr)
      , recvmsg4_link(nullptr)
      , connect_v4_link(nullptr)
      , socksop_link(nullptr)
  {
  }

  ~CabotiBpfImpl()
  {
    Destroy();
  }

  int Init();
  void Destroy();
};

auto CabotiSocks::CabotiBpfImpl::Init() -> int
{
  auto perror = [&](auto &arg) {
    std::cerr << arg << std::endl;
  };

  if (getuid() != 0) {
    perror("Cabotisocks must be run as root.");
    return -1;
  }

  ctx = caboti_bpf::open_and_load();
  if (!ctx) {
    perror("Failed to load BPF program");
    return -1;
  }
  auto step_ctx = make_scope_exit([&] {
    caboti_bpf::destroy(ctx);
    ctx = nullptr;
  });

  // bypass cabotisocks self
  ctx->bss->caboti_tgid = getpid();
  cgroup exclude_handle{exclude_cg_path};
  if (exclude_handle.fd < 0) {
    perror("Failed to get exclude id\n");
  } else {
    ctx->bss->caboti_exclude_cgroup_id = exclude_handle.inode;
  }

  // load all maps fd.
  sockmap_fd = bpf_map__fd(ctx->maps.sock_map);
  peermap_fd = bpf_map__fd(ctx->maps.peer_map);
  v4_connect_fd = bpf_map__fd(ctx->maps.v4_connect);
  v4_udp_dest_fd = bpf_map__fd(ctx->maps.v4_udp_dest);
  if (sockmap_fd == -EINVAL || peermap_fd == -EINVAL || v4_connect_fd == -EINVAL ||
      v4_udp_dest_fd == -EINVAL) {
    perror("Failed to load BPF fd");
    return -1;
  }

  // attach program
  parser_fd = bpf_program__fd(ctx->progs._stream_parser);
  verdict_fd = bpf_program__fd(ctx->progs.verdict);
  if (bpf_prog_attach(parser_fd, sockmap_fd, BPF_SK_SKB_STREAM_PARSER, 0) < 0) {
    perror("BPF attach parser failed!");
    return -1;
  }
  auto step_parser_attch = make_scope_exit([&] {
    bpf_prog_detach(sockmap_fd, BPF_SK_SKB_STREAM_PARSER);
  });

  if (bpf_prog_attach(verdict_fd, sockmap_fd, BPF_SK_SKB_STREAM_VERDICT, 0) < 0) {
    perror("BPF attach verdict failed");
    return -1;
  }
  auto step_veridct_attch = make_scope_exit([&] {
    bpf_prog_detach(sockmap_fd, BPF_SK_SKB_STREAM_VERDICT);
  });

  // UDP
  ipv4_datagram_connect_link = bpf_program__attach(ctx->progs.ipv4_datagram_connect);
  if (ipv4_datagram_connect_link == NULL) {
    perror("BPF attach ipv4 datagram connect failed");
    return -1;
  }
  auto step_ipv4_datagram_connect_link = make_scope_exit([&] {
    bpf_link__destroy(ipv4_datagram_connect_link);
  });

  // TODO: set cgroup path
  if (cg_path) {
    cgroup cg_handle{cg_path};
    if (cg_handle.fd < 0) {
      perror("BPF invalid cgroup path");
      return -1;
    }

    sendmsg4_link = bpf_program__attach_cgroup(ctx->progs.sendmsg4_redirect, cg_handle.fd);
    recvmsg4_link = bpf_program__attach_cgroup(ctx->progs.recvmsg4_redirect, cg_handle.fd);
    connect_v4_link = bpf_program__attach_cgroup(ctx->progs.connect4_redirect, cg_handle.fd);
    socksop_link = bpf_program__attach_cgroup(ctx->progs.sock_ops_handler, cg_handle.fd);
    auto step_attach_group = make_scope_exit([&] {
      bpf_link__destroy(sendmsg4_link);
      bpf_link__destroy(recvmsg4_link);
      bpf_link__destroy(connect_v4_link);
      bpf_link__destroy(socksop_link);
      sendmsg4_link = nullptr;
      recvmsg4_link = nullptr;
      connect_v4_link = nullptr;
      socksop_link = nullptr;
    });
    if (!connect_v4_link || !socksop_link) {
      perror("BPF failed to attach cgroup");
      return -1;
    }

    // step success
    step_attach_group.release();
  }

  // all step success
  step_ctx.release();
  step_parser_attch.release();
  step_veridct_attch.release();
  step_ipv4_datagram_connect_link.release();
  return 0;
}

auto CabotiSocks::CabotiBpfImpl::Destroy() -> void
{
  if (socksop_link) {
    bpf_link__destroy(socksop_link);
  }

  if (connect_v4_link) {
    bpf_link__destroy(connect_v4_link);
  }

  if (recvmsg4_link) {
    bpf_link__destroy(recvmsg4_link);
  }

  if (sendmsg4_link) {
    bpf_link__destroy(sendmsg4_link);
  }

  if (ipv4_datagram_connect_link) {
    bpf_link__destroy(ipv4_datagram_connect_link);
  }

  if (ctx) {
    // destory will close fd?
    caboti_bpf::destroy(ctx);
  }
}

CabotiSocks::CabotiSocks()
    : bpf_impl_(std::make_unique<CabotiBpfImpl>())
    , key_pool_(std::make_unique<KeyPool>(CABOTI_BPF_MAX_SOCKMAP_ENTRY))
{
}

CabotiSocks::~CabotiSocks() = default;

auto CabotiSocks::Init() -> int
{
  return bpf_impl_->Init();
}

auto CabotiSocks::GetOriginalDest(uint16_t src_port) -> std::optional<OriginalDestInfo>
{
  struct orig_dest_val val;
  // Note that bpf "local_port" use host order
  uint32_t key = static_cast<uint32_t>(src_port);

  int ret = bpf_map_lookup_and_delete_elem(bpf_impl_->v4_connect_fd, &key, &val);
  if (ret < 0) {
    std::cerr << "Failed to lookup original destination for port: " << key << "\n";
    return std::nullopt;
  }

  OriginalDestInfo dest = {
      .ip = ntohl(val.daddr),
      .tgid = val.tgid,
      .port = ntohs(val.dport),
  };

  return dest;
}

auto CabotiSocks::AddConnect(int app_fd, int up_fd) -> int
{
  auto app_cookie = getSocketCookie(app_fd);
  auto up_cookie = getSocketCookie(up_fd);
  auto peer_fd = bpf_impl_->peermap_fd;
  auto sockmap_fd = bpf_impl_->sockmap_fd;
  uint32_t up_key, app_key;
  int ret;

  up_key = key_pool_->Get();
  if (up_key == UINT32_MAX) {
    return -1;
  }
  auto step_up_key = make_scope_exit([&]() {
    key_pool_->Put(up_key);
  });

  app_key = key_pool_->Get();
  if (app_key == UINT32_MAX) {
    return -1;
  }
  auto step_app_key = make_scope_exit([&]() {
    key_pool_->Put(app_key);
  });

  auto UpdateMapAtomic = [&](int fd, const void *key, const void *value, __u64 flags) {
    ret = bpf_map_update_elem(fd, key, value, flags);
    if (ret) {
      std::cerr << "Failed to update map, ret:" << ret << std::endl;
    }
    bool need_delete = ret == 0;
    return make_scope_exit([fd, key, need_delete]() {
      if (need_delete) {
        bpf_map_delete_elem(fd, key);
      }
    });
  };

  auto step1 = UpdateMapAtomic(peer_fd, &app_cookie, &up_key, BPF_ANY);
  if (ret) {
    return ret;
  }
  auto step2 = UpdateMapAtomic(peer_fd, &up_cookie, &app_key, BPF_ANY);
  if (ret) {
    return ret;
  }
  auto step3 = UpdateMapAtomic(sockmap_fd, &app_key, &app_fd, BPF_ANY);
  if (ret) {
    return ret;
  }
  auto step4 = UpdateMapAtomic(sockmap_fd, &up_key, &up_fd, BPF_ANY);
  if (ret) {
    return ret;
  }

  // all step success
  step4.release();
  step3.release();
  step2.release();
  step1.release();
  step_app_key.release();
  step_up_key.release();

  ConnectTable item = {.app_fd = app_fd,
                       .up_fd = up_fd,
                       .app_key = app_key,
                       .up_key = up_key,
                       .app_cookie = app_cookie,
                       .up_cookie = up_cookie};

  conn_[app_fd] = item;
  return 0;
}

auto CabotiSocks::DelConnect(int app_fd, int up_fd) -> int
{
  (void)up_fd;

  auto iter = conn_.find(app_fd);
  if (iter == conn_.end()) {
    std::cerr << "Failed to find connect table item\n";
    return -1;
  }

  auto &item = iter->second;
  auto peer_fd = bpf_impl_->peermap_fd;
  auto sockmap_fd = bpf_impl_->sockmap_fd;

  bpf_map_delete_elem(peer_fd, &item.app_cookie);
  bpf_map_delete_elem(peer_fd, &item.up_cookie);
  bpf_map_delete_elem(sockmap_fd, &item.app_key);
  bpf_map_delete_elem(sockmap_fd, &item.up_key);

  key_pool_->Put(item.app_key);
  key_pool_->Put(item.up_key);

  conn_.erase(iter);

  return 0;
}

auto CabotiSocks::GetUdpOriginalDest(const Ipv4Endpoint &src) -> std::optional<Ipv4Endpoint>
{
  struct orig_ipv4_udp_src src_key = {
      .saddr = htonl(src.addr),
      .sport = src.port,
  };

  struct orig_dest_val val;

  auto res = bpf_map_lookup_elem(bpf_impl_->v4_udp_dest_fd, &src_key, &val);
  if (res) {
    return std::nullopt;
  }

  Ipv4Endpoint ret;
  ret.addr = ntohl(val.daddr);
  ret.port = static_cast<uint32_t>(ntohs(static_cast<uint16_t>(val.dport)));

  return ret;
}

} // namespace caboti
