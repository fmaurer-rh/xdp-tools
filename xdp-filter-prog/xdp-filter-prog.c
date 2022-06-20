/* SPDX-License-Identifier: GPL-2.0 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <libgen.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#include "params.h"
#include "logging.h"
#include "util.h"

#include "common_kern_user.h"

#define PROG_NAME "xdp-filter-prog"
#define NUM_FILTERS 1

static int find_prog_btf_id(const char *name, __u32 attach_prog_fd)
{
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	struct btf *btf;
	int err;

	err = bpf_obj_get_info_by_fd(attach_prog_fd, &info, &info_len);
	if (err) {
		pr_warn("failed bpf_obj_get_info_by_fd for FD %d: %d\n",
			attach_prog_fd, err);
		return err;
	}

	err = -EINVAL;
	if (!info.btf_id) {
		pr_warn("The target program doesn't have BTF\n");
		goto out;
	}
	btf = btf__load_from_kernel_by_id(info.btf_id);
	err = libbpf_get_error(btf);
	if (err) {
		pr_warn("Failed to get BTF %d of the program: %d\n", info.btf_id, err);
		goto out;
	}
	err = btf__find_by_name_kind(btf, name, BTF_KIND_FUNC);
	btf__free(btf);
	if (err <= 0) {
		pr_warn("%s is not found in prog's BTF\n", name);
		goto out;
	}
out:
	return err;
}

static int attach_dispatcher_program(struct bpf_program *prog, const struct iface *iface,
		   const char *pin_root_path)
{
	char pin_path[PATH_MAX], errmsg[STRERR_BUFSIZE];
	int err = 0;
	struct bpf_link *link;

	if (!prog || !pin_root_path)
		return -EINVAL;

	err = make_dir_subdir(pin_root_path, "filters");
	if (err) {
		pr_warn("Unable to create parent pin directory: %s\n", strerror(-err));
		return err;
	}

	err = try_snprintf(pin_path, sizeof(pin_path), "%s/filters", pin_root_path);
	if (err)
		return err;

	err = make_dir_subdir(pin_path, iface->ifname);
	if (err) {
		pr_warn("Unable to create interface pin directory: %s\n", strerror(-err));
		return err;
	}

	link = bpf_program__attach_xdp(prog, iface->ifindex);
	if (!link) {
		err = errno;
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		if (pin_root_path && err != -EEXIST)
			unlink(pin_path);
		return err;
	}

	pr_debug("Program '%s' loaded on interface '%s'\n", bpf_program__name(prog),
		 iface->ifname);


	err = try_snprintf(pin_path, sizeof(pin_path), "%s/%s-prog",
			   pin_root_path, iface->ifname);
	if (err)
		return err;
	err = bpf_program__pin(prog, pin_path);
	if (err) {
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Unable to pin BPF program at %s: %s (%d)\n", pin_path,
			errmsg, err);
		goto unload;
	}
	pr_debug("dispatcher program pinned at %s\n", pin_path);

	err = try_snprintf(pin_path, sizeof(pin_path), "%s/%s-link",
			   pin_root_path, iface->ifname);
	if (err)
		return err;
	err = bpf_link__pin(link, pin_path);
	if (err) {
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Unable to pin BPF link at %s: %s (%d)\n", pin_path,
			errmsg, err);
		goto unload;
	}

	pr_debug("dispatcher link pinned at %s\n", pin_path);
	return err;

unload:
	bpf_link__detach(link);
	return err;
}

#define CHUNK_SIZE 10240
int read_raw_bpf(const char *filename, struct bpf_insn **insns, size_t *insn_cnt)
{
	int err = 0, fsize = 0;
	FILE *f;
	void *data = NULL;

	f = fopen(filename, "rb");
	if (!f) {
		err = errno;
		goto out;
	}

	while (true) {
		data = realloc(data, ((fsize / CHUNK_SIZE) + 1) * CHUNK_SIZE);
		if (!data) {
			err = errno;
			goto out;
		}

		fsize += fread(data + fsize, 1, CHUNK_SIZE, f);

		if (ferror(f)) {
			err = 1;
			goto out;
		}
		if (feof(f))
			break;
	}

	if (fsize % sizeof(struct bpf_insn)) {
		pr_warn("File size is not a multipe of sizeof(struct bpf_insn). Are you sure the file contains raw bpf instructions?");
		err = 1;
		goto out;
	}

	data = realloc(data, fsize);
	if (!data) {
		err = errno;
		goto out;
	}

	*insns = data;
	*insn_cnt = fsize / sizeof(struct bpf_insn);

	return err;
out:
	if (data)
		free(data);
	return err;
}

/**
 * Populates the load opts with the necessary BTF data to allow loading of the
 * bare instructions. The structure of the BTF information is the same as from
 * a plain XDP program, i.e., similar to the following (with different order):
 *
 * [1] PTR '(anon)' type_id=2
 * [2] STRUCT 'xdp_md' size=24 vlen=6
 *         'data' type_id=3 bits_offset=0
 *         'data_end' type_id=3 bits_offset=32
 *         'data_meta' type_id=3 bits_offset=64
 *         'ingress_ifindex' type_id=3 bits_offset=96
 *         'rx_queue_index' type_id=3 bits_offset=128
 *         'egress_ifindex' type_id=3 bits_offset=160
 * [3] TYPEDEF '__u32' type_id=4
 * [4] INT 'unsigned int' size=4 bits_offset=0 nr_bits=32 encoding=(none)
 * [5] FUNC_PROTO '(anon)' ret_type_id=6 vlen=1
 *         'ctx' type_id=1
 * [6] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED
 * [7] FUNC 'xdp_pass' type_id=5 linkage=global
 */
int populate_filter_load_opt_btf(struct bpf_prog_load_opts *opts) {
	char errmsg[STRERR_BUFSIZE];
	int err = 0, fd;
	struct btf *btf;
	struct bpf_func_info *func_info;

	btf = btf__new_empty();
	if (!btf) {
		err = errno;
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Could not create btf structure: %s (%d)\n", errmsg, err);
		goto out;
	}

	int unsig_int_id = btf__add_int(btf, "unsigned int", 4, 0);
	if (unsig_int_id < 0) {
		err = unsig_int_id;
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Could not create 'unsigned int' btf: %s (%d)\n", errmsg, err);
		goto out;
	}

	int u32_id = btf__add_typedef(btf, "__u32", unsig_int_id);
	if (u32_id < 0) {
		err = u32_id;
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Could not create '__u32' btf: %s (%d)\n", errmsg, err);
		goto out;
	}

	int xdp_md_id = btf__add_struct(btf, "xdp_md", 24);
	if (xdp_md_id < 0) {
		err = xdp_md_id;
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Could not create 'xdp_md' btf: %s (%d)\n", errmsg, err);
		goto out;
	}

	err = btf__add_field(btf, "data", u32_id, 0, 32);
	if (err < 0) {
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Could not create 'xdp_md' field 'data' btf: %s (%d)\n", errmsg, err);
		goto out;
	}

	err = btf__add_field(btf, "data_end", u32_id, 32, 32);
	if (err < 0) {
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Could not create 'xdp_md' field 'data_end' btf: %s (%d)\n", errmsg, err);
		goto out;
	}

	err = btf__add_field(btf, "data_meta", u32_id, 64, 32);
	if (err < 0) {
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Could not create 'xdp_md' field 'data_meta' btf: %s (%d)\n", errmsg, err);
		goto out;
	}

	err = btf__add_field(btf, "ingress_ifindex", u32_id, 96, 32);
	if (err < 0) {
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Could not create 'xdp_md' field 'ingress_ifindex' btf: %s (%d)\n", errmsg, err);
		goto out;
	}

	err = btf__add_field(btf, "rx_queue_index", u32_id, 128, 32);
	if (err < 0) {
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Could not create 'xdp_md' field 'rx_queue_index' btf: %s (%d)\n", errmsg, err);
		goto out;
	}

	err = btf__add_field(btf, "egress_ifindex", u32_id, 160, 32);
	if (err < 0) {
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Could not create 'xdp_md' field 'egress_ifindex' btf: %s (%d)\n", errmsg, err);
		goto out;
	}

	int ptr_xdp_md_id = btf__add_ptr(btf, xdp_md_id);
	if (ptr_xdp_md_id < 0) {
		err = ptr_xdp_md_id;
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Could not create 'xdp_md *' btf: %s (%d)\n", errmsg, err);
		goto out;
	}

	int func_return_id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
	if (func_return_id < 0) {
		err = func_return_id;
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Could not create return int btf: %s (%d)\n", errmsg, err);
		goto out;
	}

	int func_proto_id = btf__add_func_proto(btf, func_return_id);
	if (func_proto_id < 0) {
		err = func_proto_id;
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Could not create func proto btf: %s (%d)\n", errmsg, err);
		goto out;
	}

	int ctx_param_id = btf__add_func_param(btf, "ctx", ptr_xdp_md_id);
	if (ctx_param_id < 0) {
		err = ctx_param_id;
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Could not create ctx param btf: %s (%d)\n", errmsg, err);
		goto out;
	}

	int xdp_prog_func_id = btf__add_func(btf, "filter0", BTF_FUNC_GLOBAL, func_proto_id);
	if (xdp_prog_func_id < 0) {
		err = xdp_prog_func_id;
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Could not create xdp func btf: %s (%d)\n", errmsg, err);
		goto out;
	}

	fd = btf__load_into_kernel(btf);
	if (fd < 0) {
		err = fd;
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Could not load btf into the kernel: %s (%d)\n", errmsg, err);
		goto out;
	}
	opts->prog_btf_fd = btf__fd(btf);

	func_info = malloc(sizeof(*func_info));
	if (!func_info) {
		err = errno;
		goto out;
	}

	// XDP filter function starts at insn 0
	func_info->insn_off = 0;
	func_info->type_id = xdp_prog_func_id;

	opts->func_info = func_info;
	opts->func_info_cnt = 1;
	opts->func_info_rec_size = sizeof(*func_info);

out:
	return err;
}


static const struct loadopt {
	bool help;
	struct iface iface;
} defaults_load = {
};

static struct prog_option load_options[] = {
	DEFINE_OPTION("dev", OPT_IFNAME, struct loadopt, iface,
		      .positional = true,
		      .metavar = "<ifname>",
		      .required = true,
		      .help = "Load on device <ifname>"),
	END_OPTIONS
};

int do_load(const void *cfg, const char *pin_root_path)
{
	char errmsg[STRERR_BUFSIZE];
	const struct loadopt *opt = cfg;
	struct bpf_object *obj = NULL;
	struct bpf_program *prog = NULL;
	struct bpf_map *rodata = NULL;
	struct xdp_filter_dispatcher_config config = {0};
	int err = EXIT_SUCCESS, i;

	LIBBPF_OPTS(bpf_object_open_opts, opts,
		    .pin_root_path = pin_root_path);

	obj = bpf_object__open_file("xdp-filter-dispatcher.o", &opts);
	if (!obj) {
		err = errno;
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Could not open filter dispatcher BPF program: %s (%d)\n", errmsg, err);
		goto out;
	}

	rodata = bpf_object__next_map(obj, NULL);
	if (!rodata) {
		err = errno;
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Could not find rodata map in dispatcher object file: %s (%d)\n", errmsg, err);
		goto out;
	}

	config.num_filters_enabled = NUM_FILTERS;
	for (i = 0; i < NUM_FILTERS; i++) {
		config.chain_call_actions[i] = (1U << XDP_FILTER_DISPATCHER_RETVAL |
						1U << XDP_PASS); // Call next filter on XDP_PASS
		config.run_prios[i] = i;
	}

	err = bpf_map__set_initial_value(rodata, &config, sizeof(config));
	if (err) {
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Failed to set rodata for filter dispatcher: %s (%d)'\n", errmsg, err);
		goto out;
	}

	err = bpf_object__load(obj);
	if (err) {
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Could not load dispatcher BPF program: %s (%d)\n", errmsg, err);
		goto out;
	}

	prog = bpf_object__find_program_by_name(obj, "xdp_filter_dispatcher");
	if (!prog) {
		err = errno;
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Could not find dispatcher BPF program in object file: %s (%d)\n", errmsg, err);
		goto out;
	}

	err = attach_dispatcher_program(prog, &opt->iface, pin_root_path);
	if (err) {
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Could not attach dispatcher BPF program on iface '%s': %s (%d)\n",
			opt->iface.ifname, errmsg, err);
		goto out;
	}

out:
	if (obj)
		bpf_object__close(obj);
	return err;
}

static const struct addopt {
	bool help;
	struct iface iface;
	char *filename;
} defaults_add = {
};

static struct prog_option add_options[] = {
	DEFINE_OPTION("dev", OPT_IFNAME, struct addopt, iface,
		      .positional = true,
		      .metavar = "<ifname>",
		      .required = true,
		      .help = "Load on device <ifname>"),
	DEFINE_OPTION("prog", OPT_STRING, struct addopt, filename,
		      .positional = true,
		      .metavar = "<filename>",
		      .required = true,
		      .help = "Add filter program from <filename>"),
	END_OPTIONS
};

int do_add(const void *cfg, const char *pin_root_path)
{
	char pin_path[PATH_MAX], errmsg[STRERR_BUFSIZE];
	const struct addopt *opt = cfg;
	struct bpf_insn *filter_prog = NULL;
	char *logbuf = NULL;
	char *filter_name = "filter0";
	size_t filter_len = 0;
	int dispatch_fd, filter_fd, err = EXIT_SUCCESS;
	int btf_id, link_fd;

	err = try_snprintf(pin_path, sizeof(pin_path), "%s/%s-prog",
			   pin_root_path, opt->iface.ifname);
	if (err)
		return err;

	dispatch_fd = bpf_obj_get(pin_path);
	if (dispatch_fd < 0) {
		err = errno;
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Could not get bpf obj fd: %s (%d)\n", errmsg, err);
		goto out;
	}

	btf_id = find_prog_btf_id(filter_name, dispatch_fd);
	if (btf_id < 0) {
		err = btf_id;
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Could not find BTF id of target function: %s (%d)\n", errmsg, err);
		goto out;
	}

	err = read_raw_bpf(opt->filename, &filter_prog, &filter_len);
	if (err || !filter_prog) {
		pr_warn("Could not read filter program: %s (%d)\n", strerror(err), err);
		goto out;
	}

	logbuf = malloc(BPF_LOG_BUF_SIZE);
	DECLARE_LIBBPF_OPTS(bpf_prog_load_opts, load_opts,
			    .log_buf = logbuf,
			    .log_size = BPF_LOG_BUF_SIZE,
			    .log_level = 7,
			    .attach_prog_fd = dispatch_fd,
			    .attach_btf_id = btf_id,
			    );
	err = populate_filter_load_opt_btf(&load_opts);
	if (err) {
		pr_warn("Could not populate BTF information for loading (%d)\n", err);
		goto out;
	}

	filter_fd = bpf_prog_load(BPF_PROG_TYPE_EXT, basename(opt->filename), "GPL",
				  filter_prog, filter_len, &load_opts);
	if (filter_fd < 0) {
		err = filter_fd;
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		pr_info("%s\n", logbuf);
		pr_warn("Could not load filter BPF program: %s (%d)\n", errmsg, err);
		goto out;
	}

	DECLARE_LIBBPF_OPTS(bpf_link_create_opts, create_opts,
			    .target_btf_id = btf_id);
	link_fd = bpf_link_create(filter_fd, dispatch_fd, 0, &create_opts);
	if (link_fd < 0) {
		err = errno;
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Failed to attach filter: %s (%d)\n", errmsg, err);
		goto out;
	}

	err = try_snprintf(pin_path, sizeof(pin_path), "%s/filters/%s/%s-prog",
			   pin_root_path, opt->iface.ifname, filter_name);
	if (err)
		goto out;

	err = bpf_obj_pin(filter_fd, pin_path);
	if (err < 0) {
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Failed to pin filter prog: %s (%d)\n", errmsg, err);
		goto out;
	}

	err = try_snprintf(pin_path, sizeof(pin_path), "%s/filters/%s/%s-link",
			   pin_root_path, opt->iface.ifname, filter_name);
	if (err)
		goto out;

	err = bpf_obj_pin(link_fd, pin_path);
	if (err < 0) {
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Failed to pin filter link: %s (%d)\n", errmsg, err);
		goto out;
	}

out:
	if (filter_prog)
		free(filter_prog);
	if (logbuf)
		free(logbuf);
	return err;
}

int do_help(__unused const void *cfg, __unused const char *pin_root_path)
{
	fprintf(stderr,
		"Usage: xdp-filter-prog COMMAND [options]\n"
		"\n"
		"COMMAND can be one of:\n"
		"       load        - load xdp-filter on an interface\n"
		//"       unload      - unload xdp-filter from an interface\n"
		"       add         - add a new filter program to the filter list\n"
		//"       remove      - remove a filter program from the filter list\n"
		//"       status      - show current xdp-filter status\n"
		"       help        - show this help message\n"
		"\n"
		"Use 'xdp-filter-prog COMMAND --help' to see options for each command\n");
	return -1;
}

static const struct prog_command cmds[] = {
	DEFINE_COMMAND(load, "Load xdp-filter-prog on an interface"),
	//DEFINE_COMMAND(unload, "Unload xdp-filter-prog from an interface"),
	DEFINE_COMMAND(add, "Add new filter program"),
	//DEFINE_COMMAND(remove, "Remove filter program"),
	//DEFINE_COMMAND_NODEF(status, "Show xdp-filter-prog status"),
	{ .name = "help", .func = do_help, .no_cfg = true },
	END_COMMANDS
};

union all_opts {
	struct loadopt load;
	//struct unloadopt unload;
	struct addopt add;
	//struct removeopt remove;
};

int main(int argc, char **argv)
{
	libbpf_set_strict_mode(LIBBPF_STRICT_DIRECT_ERRS | LIBBPF_STRICT_CLEAN_PTRS);

	if (argc > 1)
		return dispatch_commands(argv[1], argc - 1, argv + 1, cmds,
					 sizeof(union all_opts), PROG_NAME);

	return do_help(NULL, NULL);
}
