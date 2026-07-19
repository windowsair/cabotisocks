/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2026 windowsair <dev@airkyi.com>
 */
#ifndef _CABOTI_BPF_H_
#define _CABOTI_BPF_H_

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define CABOTI_BPF_MAX_SOCKMAP_ENTRY	1024
#define CABOTISOCKS_RULES_MAX_ENTRY	32

#define CABOTISOCKS_TCP_REDIR_PORT	41081
#define CABOTISOCKS_UDP_REDIR_PORT	41082

#define CABOTISOCKS_INVALID_INDEX	0xFFFFFFFFU

enum cabotisocks_op {
	CABOTISOCKS_DIRECT = 0,
	CABOTISOCKS_PROXY = 1,
	CABOTISOCKS_BLOCK = 2,
};

struct orig_ipv4_udp_src {
	__u32 saddr; /* network order */
	__u32 sport; /* network order */
};

struct orig_dest_val {
	__u32 daddr;
	__u16 dport;
	__u16 pad;
	__u32 tgid;
};

struct ipv4_lpm_key {
	__u32 prefix_len;
	__u32 data;
};

struct cabotisocks_rules {
	__u32 index; /* ip address map */
	char comm[16];
	__u16 port; /* network order */
	__u8 action;
	__u8 pad;
};

#endif
