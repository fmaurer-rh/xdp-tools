/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause) */

#ifndef COMMON_KERN_USER_H
#define COMMON_KERN_USER_H

#include <linux/types.h>

#define XDP_FILTER_DISPATCHER_RETVAL 31

#ifndef MAX_FILTER_ACTIONS
#define MAX_FILTER_ACTIONS 10
#endif

struct xdp_filter_dispatcher_config {
	__u8 num_filters_enabled;
	__u32 chain_call_actions[MAX_FILTER_ACTIONS];
	__u32 run_prios[MAX_FILTER_ACTIONS];
};

#endif
