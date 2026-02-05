#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "btf.skel.h"

struct event {
    u_int32_t pid;
	u_int32_t ppid;
	u_int32_t uid;
    int ret;
    char comm[16];
    char filename[256];
};

bool running = true;

void signal_handler(int sig) {
    printf("Signal received, exiting...\n");
    running = false;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

void handle_event_callback(void *ctx, int cpu, void *data, __u32 data_sz)
{
    struct event *evt = (struct event *)data;
    printf("PID: %-7d, PPID: %-7d, UID: %-7d, RET: %-7d, COMM: %-16s, FILENAME: %s\n",
           evt->pid, evt->ppid, evt->uid, evt->ret, evt->comm, evt->filename);
}

void handle_lost_events_callback(void *ctx, int cpu, __u64 lost_cnt)
{
    fprintf(stderr, "Lost %llu events on CPU %d\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	struct btf_bpf *skel;
    struct perf_buffer *pb = NULL;
	int err;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	skel = btf_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	err = btf_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		btf_bpf__destroy(skel);
		return 1;
	}

	err = btf_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		btf_bpf__destroy(skel);
		return 1;
	}

    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 8,
                          handle_event_callback,
                          handle_lost_events_callback,
                          NULL, NULL);
    if(!pb) {
        fprintf(stderr, "Failed to create perf buffer: %d\n", err);
        perf_buffer__free(pb);
        btf_bpf__destroy(skel);
        return 1;
    }

    printf("Listening for open syscalls... Press Ctrl+C to exit.\n");
    printf("%-7s %-7s %-7s %-7s %-16s %s\n", "PID", "PPID", "UID", "RET", "COMM", "FILENAME");

    while(running) {
        err = perf_buffer__poll(pb, 100);
        if(err < 0 && err != -EINTR){
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            break;
        }
    }

    perf_buffer__free(pb);
	btf_bpf__destroy(skel);
    printf("Exiting program\n");
	return 0;
}