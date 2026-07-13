// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 windowsair <dev@airkyi.com>
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "caboti.bpf.h"

#define AF_INET				2
#define SOCK_STREAM			1
#define SOCK_DGRAM			2
#define SK_DROP				0
#define SK_PASS				1

int caboti_tgid = 0;
int caboti_exclude_cgroup_id = 0;

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, CABOTI_BPF_MAX_SOCKMAP_ENTRY);
	__type(key, int);
	__type(value, int);
} sock_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CABOTI_BPF_MAX_SOCKMAP_ENTRY);
	__type(key, __u64);
	__type(value, __u32);
} peer_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, __u64); /* cookie */
	__type(value, struct orig_dest_val);
} internal_pending_v4_cookie SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32); /* src port */
	__type(value, struct orig_dest_val);
} v4_connect SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 2048);
	__type(key, struct orig_ipv4_udp_src);
	__type(value, struct orig_dest_val);
	__uint(map_flags, BPF_F_NO_COMMON_LRU);
} v4_udp_dest SEC(".maps");

struct ipv4_lpm_map {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct ipv4_lpm_key);
	__type(value, __u32); /* dummy? */
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 4096);
} _ipv4_lpm_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, CABOTISOCKS_RULES_MAX_ENTRY);
	__type(key, __u32);
	__array(values, struct ipv4_lpm_map);
} ipv4_lpm_array SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct cabotisocks_rules);
	__uint(max_entries, CABOTISOCKS_RULES_MAX_ENTRY);
} rules_array SEC(".maps");

static __always_inline bool starts_with(const char comm[16],
					const char prefix[16])
{
#pragma unroll
	for (int i = 0; i < 16; i++) {
		if (prefix[i] == '\0')
			return true;

		if (comm[i] != prefix[i])
			return false;

		if (comm[i] == '\0')
			return false;
	}

	return true;
}

struct rule_check_ctx {
	struct bpf_sock_addr *ctx;
	int result;
};

static long rule_check_cb(struct bpf_map *map, const void *key,
			  void *value, void *data)
{
	struct cabotisocks_rules *rule = value;
	struct rule_check_ctx *cb = data;
	struct bpf_sock_addr *ctx = cb->ctx;
	char comm[16];

	if (rule->port != 0 && rule->port != ctx->user_port)
		return 0;

	if (rule->comm[0] != '\0' && !bpf_get_current_comm(comm, sizeof(comm))) {
		if (!starts_with(comm, rule->comm))
			return 0;
	}

	if (rule->index != CABOTISOCKS_INVALID_INDEX) {
		struct ipv4_lpm_map *lpm_map_v4 =
			bpf_map_lookup_elem(&ipv4_lpm_array, &rule->index);
		if (!lpm_map_v4)
			return 0;

		struct ipv4_lpm_key lpm_key = {
			.prefix_len = 32,
			.data = ctx->user_ip4,
		};
		if (!bpf_map_lookup_elem(lpm_map_v4, &lpm_key))
			return 0;
	}

	cb->result = rule->action;
	return 1;
}

static int rule_check(struct bpf_sock_addr *ctx)
{
	struct rule_check_ctx cb = {
		.ctx = ctx,
		.result = CABOTISOCKS_PROXY,
	};

	bpf_for_each_map_elem(&rules_array, rule_check_cb, &cb, 0);
	return cb.result;
}

SEC("fexit/__ip4_datagram_connect")
int BPF_PROG(ipv4_datagram_connect, struct sock *sk,
			 struct sockaddr_unsized *uaddr, int addr_len, int ret)
{
	if (sk->__sk_common.skc_family != AF_INET)
		return 0;

	/* Invalid connect */
	if (sk->__sk_common.skc_dport == 0)
		return 0;

	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (tgid == caboti_tgid)
		return 0;

	__u64 cid = bpf_get_current_cgroup_id();
	if (cid == caboti_exclude_cgroup_id)
		return 0;

	__u64 cookie = bpf_get_socket_cookie(sk);
	struct orig_dest_val *val = bpf_map_lookup_elem(&internal_pending_v4_cookie, &cookie);
	if (!val)
		return 0;

	struct orig_ipv4_udp_src src_key = {
		.saddr = sk->__sk_common.skc_rcv_saddr,
		.sport = sk->__sk_common.skc_num
	};

	bpf_map_update_elem(&v4_udp_dest, &src_key, val, BPF_ANY);
	bpf_map_delete_elem(&internal_pending_v4_cookie, &cookie);

	return 0;
}

SEC("cgroup/sendmsg4")
int sendmsg4_redirect(struct bpf_sock_addr *ctx)
{
	if (ctx->family != AF_INET)
		return SK_PASS;

	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (tgid == caboti_tgid)
		return SK_PASS;

	__u64 cid = bpf_get_current_cgroup_id();
	if (cid == caboti_exclude_cgroup_id)
		return SK_PASS;

	int action = rule_check(ctx);
	if (action == CABOTISOCKS_DIRECT)
		return SK_PASS;
	else if (action == CABOTISOCKS_BLOCK)
		return SK_DROP;

	struct bpf_sock *sk = ctx->sk;
	__u32 saddr = sk->src_ip4;

	/*
	 * When the source address is set to 0.0.0.0 (INADDR_ANY),
	 * traffic destined for the is routed through the loopback interface,
	 * causing userspace applications to observe packets with 127.0.0.1
	 * as the source address rather than 0.0.0.0.
	 */
	if (saddr == 0)
		saddr = bpf_htonl(0x7f000001);

	struct orig_ipv4_udp_src src_key = {
		.saddr = saddr,
		.sport = sk->src_port,
	};

	struct orig_dest_val val = {
		.daddr = ctx->user_ip4,
		.dport = (__u16)ctx->user_port,
		.tgid = tgid,
	};

	if (bpf_map_update_elem(&v4_udp_dest, &src_key, &val, BPF_ANY))
		return SK_PASS;

	ctx->user_ip4 = bpf_htonl(0x7f000001);
	ctx->user_port = bpf_htons(CABOTISOCKS_UDP_REDIR_PORT);

	return SK_PASS;
}

SEC("cgroup/recvmsg4")
int recvmsg4_redirect(struct bpf_sock_addr *ctx)
{
	if (ctx->family != AF_INET)
		return SK_PASS;

	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (tgid == caboti_tgid)
		return SK_PASS;

	__u64 cid = bpf_get_current_cgroup_id();
	if (cid == caboti_exclude_cgroup_id)
		return SK_PASS;

	struct bpf_sock *sk = ctx->sk;
	__u32 saddr = sk->src_ip4;
	if (saddr == 0)
		saddr = bpf_htonl(0x7f000001);

	struct orig_ipv4_udp_src src_key = {
		.saddr = saddr,
		.sport = sk->src_port,
	};

	/*
	 * When the source address is set to 0.0.0.0 (INADDR_ANY),
	 * traffic destined for the is routed through the loopback interface,
	 * causing userspace applications to observe packets with 127.0.0.1
	 * as the source address rather than 0.0.0.0.
	 */
	struct orig_dest_val *val = bpf_map_lookup_elem(&v4_udp_dest, &src_key);
	if (!val)
		return SK_PASS;

	ctx->user_ip4 = val->daddr;
	ctx->user_port = val->dport;

	return SK_PASS;
}

SEC("cgroup/connect4")
int connect4_redirect(struct bpf_sock_addr *ctx)
{
	if (ctx->family != AF_INET)
		return SK_PASS;

	/* TODO: config bypass UDP */
	if (ctx->type != SOCK_STREAM && ctx->type != SOCK_DGRAM)
		return SK_PASS;

	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (tgid == caboti_tgid)
		return SK_PASS;

	__u64 cid = bpf_get_current_cgroup_id();
	if (cid == caboti_exclude_cgroup_id)
		return SK_PASS;

	int action = rule_check(ctx);
	if (action == CABOTISOCKS_DIRECT)
		return SK_PASS;
	else if (action == CABOTISOCKS_BLOCK)
		return SK_DROP;

	/* Then start to proxy */

	struct orig_dest_val val = {
		.daddr = ctx->user_ip4,
		.dport = (__u16)ctx->user_port,
		.tgid = tgid,
	};

	__u64 cookie = bpf_get_socket_cookie(ctx);
	bpf_map_update_elem(&internal_pending_v4_cookie, &cookie, &val, BPF_ANY);

	ctx->user_ip4 = bpf_htonl(0x7f000001);
	if (ctx->type == SOCK_STREAM)
		ctx->user_port = bpf_htons(CABOTISOCKS_TCP_REDIR_PORT);
	else if (ctx->type == SOCK_DGRAM)
		ctx->user_port = bpf_htons(CABOTISOCKS_UDP_REDIR_PORT);

	return SK_PASS;
}

SEC("sockops")
int sock_ops_handler(struct bpf_sock_ops *ctx)
{
	if (ctx->family != AF_INET)
		return 0;
	if (ctx->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB)
		return 0;

	__u64 cookie = bpf_get_socket_cookie(ctx);

	struct orig_dest_val *val = bpf_map_lookup_elem(&internal_pending_v4_cookie, &cookie);
	if (!val)
		return 0;

	__u32 key = ctx->local_port;

	bpf_map_update_elem(&v4_connect, &key, val, BPF_ANY);
	bpf_map_delete_elem(&internal_pending_v4_cookie, &cookie);

	return 0;
}

SEC("sk_skb/stream_parser")
int _stream_parser(struct __sk_buff *skb)
{
	return skb->len;
}

SEC("sk_skb/verdict")
int verdict(struct __sk_buff *skb)
{
	__u64 cookie = bpf_get_socket_cookie(skb);
	__u32 *peer_key = bpf_map_lookup_elem(&peer_map, &cookie);

	if (!peer_key)
		return SK_PASS;

	return bpf_sk_redirect_map(skb, &sock_map, *peer_key, 0);
}

char _license[] SEC("license") = "GPL";
