#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "uprobe_add.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct uprobe_add_bpf *skel;
	int err;

	const char* target_program_path;
    LIBBPF_OPTS(bpf_uprobe_opts, uprobe_add_opts);

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <path-to-uprobe_add_target>\n", argv[0]);
        return 1;
    }
    target_program_path = argv[1];

    libbpf_set_print(libbpf_print_fn);

    skel = uprobe_add_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }
    uprobe_add_opts.func_name = "uprobe_add";
    uprobe_add_opts.retprobe = false;
    skel->links.uprobe_add = 
        bpf_program__attach_uprobe_opts(skel->progs.uprobe_add,
                                        -1, 
                                        target_program_path,
                                        0, 
                                        &uprobe_add_opts);
    if (!skel->links.uprobe_add) {
        err = -errno;
        fprintf(stderr, "Failed to attach uprobe: %d\n", err);
        goto cleanup;
    }

    uprobe_add_opts.func_name = "uprobe_add";
    uprobe_add_opts.retprobe = true;
    skel->links.uretprobe_add = 
        bpf_program__attach_uprobe_opts(skel->progs.uretprobe_add,
                                        -1, 
                                        target_program_path,
                                        0, 
                                        &uprobe_add_opts);
    if (!skel->links.uretprobe_add) {
        err = -errno;
        fprintf(stderr, "Failed to attach uretprobe: %d\n", err);
        goto cleanup;
    }

    printf("Successfully started! Please run the target program to trigger the uprobe.\n");
    printf("Monitoring functions 'uprobe_add' and its return value in %s\n", target_program_path);
    printf("Please run \"sudo cat /sys/kernel/debug/tracing/trace_pipe\" to see the output in another terminal.\n");
    printf("Then run the target program like this:\n");
    printf("    %s %s\n", argv[0], target_program_path);
    printf("Press Ctrl+C to exit and clean up.\n");
    while (1) {
        sleep(1);
    }

cleanup:
    uprobe_add_bpf__destroy(skel);
    return -err ;
}