/* SPDX-License-Identifier: GPL-2.0 */

#undef FILT_MODE_ETHERNET
#define FILT_MODE_IPV4
#define FILT_MODE_IPV6
#undef FILT_MODE_UDP
#undef FILT_MODE_TCP
#define FUNCNAME xdp_filt_ip
#include "xdp_filt_prog.h"
