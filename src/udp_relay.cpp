
// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 windowsair <dev@airkyi.com>
 */
#include <chrono>
#include <cstdint>
#include <cstring>
#include <list>
#include <map>
#include <netinet/in.h>
#include <optional>
#include <system_error>
#include "asio/as_tuple.hpp"
#include "asio/co_spawn.hpp"
#include "asio/detached.hpp"
#include "asio/ip/tcp.hpp"
#include "asio/ip/udp.hpp"
#include "fmt/core.h"
#include "udp_relay.hpp"
#include "socks.hpp"

namespace caboti {
constexpr int UDP_RECV_BUFFER_SIZE = 2048;

uint64_t GetCurrentTimeMs()
{
  using namespace std::chrono;

  return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

struct Ipv4ConnectionTuple {
  Ipv4Endpoint src;
  Ipv4Endpoint dst;

  auto operator<=>(const Ipv4ConnectionTuple &) const = default;
};

struct Ipv4TunnelManager;

struct Ipv4ConnectionInfo {
  asio::ip::udp::endpoint src;
  uint64_t active_time;
  Ipv4TunnelManager *parent;
};

using RelayEndpoint = Ipv4Endpoint;
using DstEndpoint = Ipv4Endpoint;
using TunnelItemMap = std::map<DstEndpoint, Ipv4ConnectionInfo>;

struct Ipv4TunnelManager {
  asio::ip::tcp::socket tcp_socket;
  asio::ip::udp::socket udp_socket;
  TunnelItemMap tunnel_item_map;

  explicit Ipv4TunnelManager(asio::ip::tcp::socket &&tcp_sk, asio::ip::udp::socket &&udp_sk)
      : tcp_socket(std::move(tcp_sk))
      , udp_socket(std::move(udp_sk))
  {
  }
};

inline auto Ipv4EndpointToUdpEndpoint(const Ipv4Endpoint &ep) -> asio::ip::udp::endpoint
{
  uint32_t addr = htonl(ep.addr);
  asio::ip::address_v4::bytes_type arr;
  std::memcpy(arr.data(), &addr, 4);
  asio::ip::address_v4 v4_addr{arr};
  asio::ip::udp::endpoint endpoint{v4_addr, static_cast<uint16_t>(ep.port)};
  return endpoint;
}

inline auto UdpEndpointToIpv4Endpoint(const asio::ip::udp::endpoint &endpoint) -> Ipv4Endpoint
{
  Ipv4Endpoint ep = {.addr = endpoint.address().to_v4().to_uint(), .port = endpoint.port()};
  return ep;
}

class UdpSession {
public:
  explicit UdpSession(CabotiSocks &ctx,
                      asio::ip::udp::socket &socket,
                      const std::string &socks_host,
                      uint16_t socks_port)
      : ctx_(ctx)
      , udp_socket_(socket)
      , socks_host_(socks_host)
      , socks_port_(socks_port)
  {
  }

  auto GetUdpConnection(const Ipv4ConnectionTuple &tuple) -> asio::awaitable<Ipv4ConnectionInfo *>;

private:
  auto AddSocksConnection(void)
      -> asio::awaitable<std::optional<Ipv4TunnelManager>>;
  auto RemoveSocksConnection(Ipv4TunnelManager *manager) -> void;
  auto SocksServerDataRecv(asio::any_io_executor executor, Ipv4TunnelManager *manager) -> void;

private:
  CabotiSocks &ctx_;
  asio::ip::udp::socket &udp_socket_;
  std::string socks_host_;
  uint16_t socks_port_;
  std::map<Ipv4ConnectionTuple, Ipv4ConnectionInfo *> connect_map_;
  std::map<RelayEndpoint, std::list<Ipv4TunnelManager>> tunnel_map_;
};

auto UdpSession::AddSocksConnection(void)
    -> asio::awaitable<std::optional<Ipv4TunnelManager>>
{
  auto executor = co_await asio::this_coro::executor;
  asio::ip::address udp_address;
  uint16_t udp_port;

  auto res =
      co_await SocksServerAssociate(executor, socks_host_, socks_port_, udp_address, udp_port);
  if (!res.has_value()) {
    co_return std::nullopt;
  }

  asio::ip::udp::socket udp_socket(executor);
  asio::ip::udp::endpoint ep(udp_address, udp_port);
  asio::error_code ec;
  udp_socket.connect(ep, ec);
  if (ec) {
    co_return std::nullopt;
  }

  Ipv4TunnelManager manager{std::move(res.value()), std::move(udp_socket)};
  co_return manager;
}

auto UdpSession::RemoveSocksConnection(Ipv4TunnelManager *manager) -> void
{
  Ipv4ConnectionTuple tuple;
  for (auto &item : manager->tunnel_item_map) {
    // dst(key) -> src
    tuple.dst = item.first;
    tuple.src = UdpEndpointToIpv4Endpoint(item.second.src);

    auto iter = connect_map_.find(tuple);
    if (iter != connect_map_.end()) {
      connect_map_.erase(iter);
    }
  }

  for (auto it = tunnel_map_.begin(); it != tunnel_map_.end();) {
    // inner list
    auto &list = it->second;
    for (auto list_it = list.begin(); list_it != list.end();) {
      if (&(*list_it) == manager) {
        list_it = list.erase(list_it);
      } else {
        ++list_it;
      }
    }

    if (list.empty()) {
      it = tunnel_map_.erase(it);
    } else {
      ++it;
    }
  }
}

auto UdpSession::GetUdpConnection(const Ipv4ConnectionTuple &tuple)
    -> asio::awaitable<Ipv4ConnectionInfo *>
{
  auto iter = connect_map_.find(tuple);
  if (iter != connect_map_.end()) {
    co_return iter->second;
  }

  auto TunnelItemMapAdd = [this](const Ipv4ConnectionTuple &tuple,
                                 const Ipv4TunnelManager *manager) -> Ipv4ConnectionInfo * {
    Ipv4ConnectionInfo info = {.src = Ipv4EndpointToUdpEndpoint(tuple.src),
                               .active_time = GetCurrentTimeMs(),
                               .parent = const_cast<Ipv4TunnelManager *>(manager)};

    auto &tunnel = const_cast<TunnelItemMap &>(manager->tunnel_item_map);
    auto [iter, success] = tunnel.emplace(tuple.dst, std::move(info));
    if (!success) {
      return nullptr;
    }

    auto ret = &iter->second;
    if (!this->connect_map_.emplace(tuple, ret).second) {
      // failed to add global connection table
      tunnel.erase(iter);
      return nullptr;
    }

    return ret;
  };

  // try to insert new connect
  Ipv4ConnectionInfo *ret = nullptr;
  for (auto &list_pair : tunnel_map_) {
    auto &tunnel_list = list_pair.second;
    bool found = false;
    for (auto &item : tunnel_list) {
      auto &tunnel = item.tunnel_item_map;
      if (tunnel.find(tuple.dst) != tunnel.end()) {
        continue;
      }
      ret = TunnelItemMapAdd(tuple, &item);
      if (!ret) {
        co_return nullptr;
      }
      found = true;
      break;
    }
    if (found) {
      break;
    }
  }
  // find available connect info
  if (ret) {
    co_return ret;
  }
  // not found, then try to add new connection
  auto res = co_await AddSocksConnection();
  if (!res.has_value()) {
    co_return nullptr;
  }
  auto &new_tunnel = res.value();

  std::error_code ec;
  auto remote_ep = new_tunnel.udp_socket.remote_endpoint(ec);
  if (ec) {
    co_return nullptr;
  }
  DstEndpoint socks_ep = {.addr = remote_ep.address().to_v4().to_uint(), .port = remote_ep.port()};

  Ipv4TunnelManager *new_manager = &tunnel_map_[socks_ep].emplace_back(std::move(new_tunnel));
  if (!TunnelItemMapAdd(tuple, new_manager)) {
    RemoveSocksConnection(new_manager);
    co_return nullptr;
  }

  auto executor = co_await asio::this_coro::executor;
  SocksServerDataRecv(executor, new_manager);
  // get first item in the map
  ret = &new_manager->tunnel_item_map.begin()->second;
  ret->active_time = GetCurrentTimeMs();
  co_return ret;
}

auto UdpSession::SocksServerDataRecv(asio::any_io_executor executor, Ipv4TunnelManager *manager)
    -> void
{
  // 1. recv udp data
  asio::co_spawn(
      executor,
      [this, manager]() -> asio::awaitable<void> {
        std::array<uint8_t, UDP_RECV_BUFFER_SIZE> buf;
        auto *udp_socket = &manager->udp_socket;
        for (;;) {
          auto [ec, len] = co_await udp_socket->async_receive(asio::buffer(buf),
                                                              asio::as_tuple(asio::use_awaitable));
          if (ec) {
            co_return;
          }
          // TODO: ipv6
          // Ipv4 only
          constexpr int header_len = 2 + 1 + 1 + 4 + 2;
          if (len <= header_len) {
            continue;
          }
          constexpr int port_offset = 2 + 1 + 1 + 4;
          constexpr int addr_offset = 2 + 1 + 1;
          uint16_t port = (buf[port_offset] << 8) | buf[port_offset + 1];

          // get originial endpoint
          uint32_t addr;
          std::memcpy(&addr, buf.data() + addr_offset, 4);
          addr = ntohl(addr);
          Ipv4Endpoint dst_ep{addr, port};
          auto iter = manager->tunnel_item_map.find(dst_ep);
          if (iter == manager->tunnel_item_map.end()) {
            continue;
          }

          auto [ec2, len2] = co_await this->udp_socket_.async_send_to(
              asio::buffer(buf.data() + header_len, len - header_len),
              iter->second.src,
              asio::as_tuple(asio::use_awaitable));
          if (ec2) {
            continue;
          }
        }
      },
      asio::detached);

  // 2. monitor tcp
  asio::co_spawn(
      executor,
      [this, manager]() -> asio::awaitable<void> {
        std::array<uint8_t, 1> unused;
        auto *tcp_socket = &manager->tcp_socket;
        for (;;) {
          auto [err,
                len] = co_await tcp_socket->async_read_some(asio::buffer(unused),
                                                            asio::as_tuple(asio::use_awaitable));
          if (err) {
            RemoveSocksConnection(manager);
            co_return;
          }
        }
      },
      asio::detached);
}

auto udp_listener(CabotiSocks &ctx,
                  uint16_t listen_port,
                  const std::string &socks_host,
                  uint16_t socks_port) -> asio::awaitable<void>
{
  auto executor = co_await asio::this_coro::executor;

  asio::ip::udp::socket udp_server(executor, {asio::ip::udp::v4(), listen_port});
  UdpSession udp_session{ctx, udp_server, socks_host, socks_port};

  std::array<uint8_t, UDP_RECV_BUFFER_SIZE> buf;
  asio::ip::udp::endpoint endpoint;

  constexpr int header_len = 2 + 1 + 1 + 4 + 2;
  std::memset(buf.data(), 0, header_len);
  buf[3] = to_underlying(SocksAddrType::IPV4);
  for (;;) {
    auto [err, len] = co_await udp_server.async_receive_from(asio::buffer(buf.data() + header_len,
                                                                          buf.size() - header_len),
                                                             endpoint,
                                                             asio::as_tuple(asio::use_awaitable));
    if (err) {
      continue;
    }

    auto src_endpoint = UdpEndpointToIpv4Endpoint(endpoint);
    auto origin_dst_info = ctx.GetUdpOriginalDest(src_endpoint);
    if (!origin_dst_info.has_value()) {
      continue;
    }

    // TODO: get real dst Ipv4Tuple
    Ipv4ConnectionTuple tuple{.src = src_endpoint, .dst = origin_dst_info.value()};
    auto conn_info = co_await udp_session.GetUdpConnection(tuple);
    if (!conn_info) {
      continue;
    }
    // fill dst address and port info
    auto &udp_socket = conn_info->parent->udp_socket;
    uint32_t ipv4_addr = htonl(tuple.dst.addr);
    std::memcpy(&buf[4], &ipv4_addr, 4);
    buf[8] = tuple.dst.port >> 8;
    buf[9] = tuple.dst.port & 0xff;
    auto [err2, len2] = co_await udp_socket.async_send(asio::buffer(buf.data(), header_len + len),
                                                       asio::as_tuple(asio::use_awaitable));
    if (err2) {
      fmt::println(stderr, "UDP send failed {}", err2.message());
    }
  }
}

} // namespace caboti
