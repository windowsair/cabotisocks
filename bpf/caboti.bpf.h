/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2026 windowsair <dev@airkyi.com>
 */
#ifndef _CABOTI_BPF_H_
#define _CABOTI_BPF_H_

#include <linux/types.h>

#define CABOTI_BPF_MAX_SOCKMAP_ENTRY	1024

struct orig_dest_val {
	__u32 daddr;
	__u16 dport;
	__u16 pad;
	__u32 tgid;
};

#endif
