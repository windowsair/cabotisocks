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

#define CABOTISOCKS_TCP_REDIR_PORT	1081
#define CABOTISOCKS_UDP_REDIR_PORT	1082

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

#endif
