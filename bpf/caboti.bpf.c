// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 windowsair <dev@airkyi.com>
 */
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "caboti.bpf.h"

#define AF_INET				2
#define SOCK_STREAM			1
#define SK_PASS				1
#define CABOTISOCKS_TCP_REDIR_PORT	1081

int caboti_tgid = 0;

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

SEC("cgroup/connect4")
int connect4_redirect(struct bpf_sock_addr *ctx)
{
	if (ctx->family != AF_INET)
		return 1;

	if (ctx->type != SOCK_STREAM)
		return 1;

	if ((ctx->user_ip4 & bpf_htonl(0xff000000)) == bpf_htonl(0x7f000000))
		return 1;

	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (tgid == caboti_tgid)
		return 1;

	struct orig_dest_val val = {
		.daddr = ctx->user_ip4,
		.dport = (__u16)ctx->user_port,
		.tgid   = tgid,
	};
	__u64 cookie = bpf_get_socket_cookie(ctx);
	bpf_map_update_elem(&internal_pending_v4_cookie, &cookie, &val, BPF_ANY);

	ctx->user_ip4  = bpf_htonl(0x7f000001);
	ctx->user_port = bpf_htons(CABOTISOCKS_TCP_REDIR_PORT);

	return 1;
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
	__u64 cookie    = bpf_get_socket_cookie(skb);
	__u32 *peer_key = bpf_map_lookup_elem(&peer_map, &cookie);

	if (!peer_key)
		return SK_PASS;

	return bpf_sk_redirect_map(skb, &sock_map, *peer_key, 0);
}

char _license[] SEC("license") = "GPL";
