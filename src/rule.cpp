// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 windowsair <dev@airkyi.com>
 */
#include <charconv>
#include <fstream>
#include <string>
#include <string_view>
#include "asio/error_code.hpp"
#include "asio/ip/address.hpp"
#include "fmt/core.h"
#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "rapidjson/istreamwrapper.h"
#include "rapidjson/schema.h"
#include "rapidjson/stringbuffer.h"
#include "bpf/caboti.bpf.h"
#include "rule.hpp"

namespace caboti {
enum class OutBoundTag : std::uint8_t {
  DIRECT = CABOTISOCKS_DIRECT,
  PROXY = CABOTISOCKS_PROXY,
  BLOCK = CABOTISOCKS_BLOCK,
};

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
      fmt::println(stderr, "Invalid CIDR prefix length: {}", str);
      return ret;
    }

    ret.prefix_len = result;
  }

  auto addr = asio::ip::make_address(ip_str, ec);
  if (ec) {
    fmt::println(stderr, "Invalid IP address: {}", str);
    ret.prefix_len = UINT32_MAX;
    return ret;
  }
  if (addr.is_v6()) {
    // TODO: IPv6
    fmt::println(stderr, "IPv6 not support: {}", str);
    ret.prefix_len = UINT32_MAX;
    return ret;
  }

  ret.data = htonl(addr.to_v4().to_uint());
  return ret;

}

#if defined(HAS_EMBED_SUPPORT)
#if __has_embed("../config/config.schema.json" suffix(, 0) if_empty(0)) == __STDC_EMBED_FOUND__
static constexpr char kSchemaJson[] = {
#embed "../config/config.schema.json" suffix(, 0) if_empty(0)
};
#else
#error "Failed to embed confg.schema.json!"
#endif
#else // !defined(HAS_EMBED_SUPPORT)
#include "kSchemaJson.hpp"
#endif

auto CabotiSocksConfig::Init(const std::string &path) -> int
{
  return ParseConfig(path);
}

auto CabotiSocksConfig::UpdateRules(CabotiSocksRule &rule,
                                    const std::vector<std::string> &host_list) -> void
{
  for (auto &str : host_list) {
    auto lpm_key = StringToLpmKey(str);
    if (lpm_key.prefix_len == UINT32_MAX) {
      continue;
    }
    rule.ip.emplace_back(std::move(lpm_key));
  }

  rule.port = htons(rule.port);
  rules_.emplace_back(std::move(rule));
}

auto ValidateConfig(const rapidjson::Document &doc) -> int
{
  rapidjson::Document schema_doc;
  if (schema_doc.Parse(kSchemaJson).HasParseError()) {
    fmt::println(stderr,
                 "Internal error: failed to parse schema (offset {}): {}",
                 static_cast<unsigned>(schema_doc.GetErrorOffset()),
                 rapidjson::GetParseError_En(schema_doc.GetParseError()));
    return -1;
  }

  rapidjson::SchemaDocument schema(schema_doc);
  rapidjson::SchemaValidator validator(schema);

  if (!doc.Accept(validator)) {
    rapidjson::StringBuffer sb;
    validator.GetInvalidSchemaPointer().StringifyUriFragment(sb);
    fmt::println(stderr, "Config validation failed at '{}'", sb.GetString());

    sb.Clear();
    validator.GetInvalidDocumentPointer().StringifyUriFragment(sb);
    fmt::println(stderr, "  Invalid keyword: '{}'", validator.GetInvalidSchemaKeyword());
    fmt::println(stderr, "  Document path : '{}'", sb.GetString());
    return -1;
  }

  return 0;
}

auto CabotiSocksConfig::ParseConfig(const std::string &path) -> int
{
  std::ifstream ifs(path);
  if (!ifs.is_open()) {
    fmt::println(stderr, "Failed to open config file: {}", path);
    return -1;
  }

  rapidjson::IStreamWrapper isw(ifs);
  rapidjson::Document doc;
  if (doc.ParseStream(isw).HasParseError()) {
    fmt::println(stderr,
                 "JSON parse error (offset {}): {}",
                 static_cast<unsigned>(doc.GetErrorOffset()),
                 rapidjson::GetParseError_En(doc.GetParseError()));
    return -1;
  }

  if (ValidateConfig(doc)) {
    return -1;
  }

  const auto &srv = doc["server"];
  server_.host = srv["host"].GetString();
  server_.port = srv["port"].GetUint();

  if (srv.HasMember("username")) {
    server_.username = srv["username"].GetString();
  }
  if (srv.HasMember("password")) {
    server_.password = srv["password"].GetString();
  }

  /*
   * cgroup v2 path.
   * For example:
   * - /sys/fs/cgroup/system.slice/myapp.service
   * - /sys/fs/cgroup/cabotisocks
   */
  const auto &cg = doc["cgroup"];
  auto prefix = "/sys/fs/cgroup/";
  include_cg_path_ = cg["include_path"].GetString();
  include_cg_path_ = prefix + include_cg_path_;
  if (cg.HasMember("exclude_path")) {
    exclude_cg_path_ = cg["exclude_path"].GetString();
    exclude_cg_path_ = prefix + exclude_cg_path_;
  }

  // misc
  const auto &misc = doc["misc"];
  if (misc.HasMember("enable_udp")) {
    enable_udp_ = misc["enable_udp"].GetBool();
  } else {
    enable_udp_ = false;
  }

  // rule
  const auto &rules = doc["rules"];
  std::vector<std::string> host_str;
  host_str.reserve(1024);
  for (auto &item : rules.GetArray()) {
    CabotiSocksRule rule;
    host_str.clear();

    std::string action = item["action"].GetString();
    if (action == "direct") {
      rule.action = OutBoundTag::DIRECT;
    } else if (action == "block") {
      rule.action = OutBoundTag::BLOCK;
    } else {
      rule.action = OutBoundTag::PROXY;
    }

    if (item.HasMember("process")) {
      rule.comm = item["process"].GetString();
    }

    if (item.HasMember("port")) {
      rule.port = item["port"].GetUint();
    } else {
      rule.port = 0;
    }

    if (item.HasMember("host")) {
      const auto &host_list = item["host"];
      for (auto &host : host_list.GetArray()) {
        host_str.emplace_back(host.GetString());
      }
    }

    UpdateRules(rule, host_str);
  }

  return 0;
}

} // namespace caboti
