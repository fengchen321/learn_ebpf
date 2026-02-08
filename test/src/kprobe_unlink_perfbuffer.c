#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "kprobe_unlink_perfbuffer.skel.h"

struct event{
    int pid;
    char comm[16];
    char filename[256];
};

bool running = true;

void signal_handler(int sig)
{
    printf("Signal received, exiting...\n");
    running = false;
}

void handle_event_callback(void *ctx, int cpu, void *data, __u32 data_size)
{
    const struct event *evt = data;
    printf("%-8s %-6d %-16s %s\n", "UNLINK", evt->pid, evt->comm, evt->filename);
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
    fprintf(stderr, "Lost %llu events on CPU %d\n", lost_cnt, cpu);
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct kprobe_unlink_perfbuffer_bpf *skel;
    struct perf_buffer *pb = NULL;

	int err;
    signal(SIGINT, signal_handler);  // Handle Ctrl+C
    signal(SIGTERM, signal_handler);  // Handle termination signals

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	skel = kprobe_unlink_perfbuffer_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	err = kprobe_unlink_perfbuffer_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        kprobe_unlink_perfbuffer_bpf__destroy(skel);
		return 1;
	}

	err = kprobe_unlink_perfbuffer_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
        kprobe_unlink_perfbuffer_bpf__destroy(skel);
        return 1;
	}

    pb = perf_buffer__new(bpf_map__fd(skel->maps.events),
                            8,
                            handle_event_callback,
                            handle_lost_events, NULL, NULL);
    if(!pb){
        fprintf(stderr, "Failed to create perf buffer\n");
        kprobe_unlink_perfbuffer_bpf__destroy(skel);
        return 1;
    }

    printf("%-8s %-6s %-16s %s\n", "EVENT", "PID", "COMM", "FILENAME");

    while(running){
        err = perf_buffer__poll(pb, 100);
        if(err < 0 && err != -EINTR){
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            break;
        }
    }
    perf_buffer__free(pb);
	kprobe_unlink_perfbuffer_bpf__destroy(skel);
    printf("Exiting program\n");
	return 0;
}