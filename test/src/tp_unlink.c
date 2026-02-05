#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "tp_unlink.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct tp_unlink_bpf *skel;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	skel = tp_unlink_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	err = tp_unlink_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		tp_unlink_bpf__destroy(skel);
		return 1;
	}

	err = tp_unlink_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		tp_unlink_bpf__destroy(skel);
		return 1;
	}

	printf("Successfully started!\n");
	system("sudo cat /sys/kernel/debug/tracing/trace_pipe");

	tp_unlink_bpf__destroy(skel);

	return 0;
}