// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2016 John Fastabend <john.r.fastabend@intel.com>
 */
static const char *__doc__ =
"XDP redirect, using bpf_redirect helper\n"
"Usage: xdp-redirect basic <IFINDEX|IFNAME>_IN <IFINDEX|IFNAME>_OUT\n";

#include <errno.h>
#include <stdio.h>
#include <assert.h>
#include <getopt.h>
#include <libgen.h>
#include <net/if.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <stdbool.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <linux/if_link.h>
#include <xdp/libxdp.h>

#include "xdp_sample.h"
#include "xdp_redirect_basic.skel.h"

static int mask = SAMPLE_RX_CNT | SAMPLE_REDIRECT_ERR_CNT |
		  SAMPLE_EXCEPTION_CNT | SAMPLE_DEVMAP_XMIT_CNT_MULTI;

DEFINE_SAMPLE_INIT(xdp_redirect_basic);

static const struct option long_options[] = {
	{"help",	no_argument,		NULL, 'h' },
	{"skb-mode",	no_argument,		NULL, 'S' },
	{"stats",	no_argument,		NULL, 's' },
	{"interval",	required_argument,	NULL, 'i' },
	{"verbose",	no_argument,		NULL, 'v' },
	{}
};

int xdp_redirect_basic_main(int argc, char **argv)
{
	struct xdp_program *xdp_prog = NULL, *dummy_prog = NULL;
	enum xdp_attach_mode xdp_mode = XDP_MODE_NATIVE;
	DECLARE_LIBBPF_OPTS(xdp_program_opts, opts);
	int ifindex_in, ifindex_out, opt;
	struct xdp_redirect_basic *skel;
	char str[2 * IF_NAMESIZE + 1];
	char ifname_out[IF_NAMESIZE];
	char ifname_in[IF_NAMESIZE];
	int ret = EXIT_FAIL_OPTION;
	unsigned long interval = 2;
	bool error = true;

	while ((opt = getopt_long(argc, argv, "hSi:vs",
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 'S':
			xdp_mode = XDP_MODE_SKB;
			mask &= ~(SAMPLE_DEVMAP_XMIT_CNT |
				  SAMPLE_DEVMAP_XMIT_CNT_MULTI);
			break;
		case 'i':
			interval = strtoul(optarg, NULL, 0);
			break;
		case 'v':
			sample_switch_mode();
			break;
		case 's':
			mask |= SAMPLE_REDIRECT_CNT;
			break;
		case 'h':
			error = false;
			__attribute__((__fallthrough__));
		default:
			sample_usage(argv, long_options, __doc__, mask, error);
			return ret;
		}
	}

	if (argc <= optind + 1) {
		sample_usage(argv, long_options, __doc__, mask, true);
		return ret;
	}

	ifindex_in = if_nametoindex(argv[optind]);
	if (!ifindex_in)
		ifindex_in = strtoul(argv[optind], NULL, 0);

	ifindex_out = if_nametoindex(argv[optind + 1]);
	if (!ifindex_out)
		ifindex_out = strtoul(argv[optind + 1], NULL, 0);

	if (!ifindex_in || !ifindex_out) {
		fprintf(stderr, "Bad interface index or name\n");
		sample_usage(argv, long_options, __doc__, mask, true);
		goto end;
	}

	skel = xdp_redirect_basic__open();
	if (!skel) {
		fprintf(stderr, "Failed to xdp_redirect_basic__open: %s\n", strerror(errno));
		ret = EXIT_FAIL_BPF;
		goto end;
	}

	ret = sample_init_pre_load(skel);
	if (ret < 0) {
		fprintf(stderr, "Failed to sample_init_pre_load: %s\n", strerror(-ret));
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

	skel->rodata->from_match[0] = ifindex_in;
	skel->rodata->to_match[0] = ifindex_out;
	skel->rodata->ifindex_out = ifindex_out;

	opts.obj = skel->obj;
	opts.prog_name = bpf_program__name(skel->progs.xdp_redirect_basic_prog);
	xdp_prog = xdp_program__create(&opts);
	if (!xdp_prog) {
		ret = -errno;
		fprintf(stderr, "Couldn't open XDP program: %s\n",
			strerror(-ret));
		goto end_destroy;
	}

	ret = xdp_program__attach(xdp_prog, ifindex_in, xdp_mode, 0);
	if (ret < 0) {
		fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(-ret));
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

	ret = sample_init(skel, mask, ifindex_in, ifindex_out);
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize sample: %s\n", strerror(-ret));
		ret = EXIT_FAIL;
		goto end_detach;
	}

	opts.obj = NULL;
	opts.prog_name = "xdp_pass";
	opts.find_filename = "xdp-dispatcher.o";
	dummy_prog = xdp_program__create(&opts);
	if (!dummy_prog) {
		fprintf(stderr, "Failed to load dummy program: %s\n", strerror(errno));
		ret = EXIT_FAIL_BPF;
		goto end_detach;
	}

	ret = xdp_program__attach(dummy_prog, ifindex_out, xdp_mode, 0);
	if (ret < 0) {
		fprintf(stderr, "Failed to attach dummy program: %s\n", strerror(-ret));
		ret = EXIT_FAIL_BPF;
		goto end_detach;
	}

	ret = EXIT_FAIL;
	if (!if_indextoname(ifindex_in, ifname_in)) {
		fprintf(stderr, "Failed to if_indextoname for %d: %s\n", ifindex_in,
			strerror(errno));
		goto end_detach;
	}

	if (!if_indextoname(ifindex_out, ifname_out)) {
		fprintf(stderr, "Failed to if_indextoname for %d: %s\n", ifindex_out,
			strerror(errno));
		goto end_detach;
	}

	safe_strncpy(str, get_driver_name(ifindex_in), sizeof(str));
	printf("Redirecting from %s (ifindex %d; driver %s) to %s (ifindex %d; driver %s)\n",
	       ifname_in, ifindex_in, str, ifname_out, ifindex_out, get_driver_name(ifindex_out));
	snprintf(str, sizeof(str), "%s->%s", ifname_in, ifname_out);

	ret = sample_run(interval, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "Failed during sample run: %s\n", strerror(-ret));
		ret = EXIT_FAIL;
		goto end_detach;
	}
	ret = EXIT_OK;
end_detach:
	if (dummy_prog)
		xdp_program__detach(dummy_prog, ifindex_out, xdp_mode, 0);
	xdp_program__detach(xdp_prog, ifindex_in, xdp_mode, 0);
end_destroy:
	xdp_redirect_basic__destroy(skel);
end:
	sample_exit(ret);
	return 0;
}
