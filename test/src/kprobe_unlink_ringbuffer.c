#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "kprobe_unlink_ringbuffer.skel.h"

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

void handle_event_callback(void *ctx, void *data, __u64 data_size)
{
    const struct event *evt = data;
    printf("%-8s %-6d %-16s %s\n", "UNLINK", evt->pid, evt->comm, evt->filename);
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct kprobe_unlink_ringbuffer_bpf *skel;
    struct ring_buffer *rb = NULL;

	int err;
    signal(SIGINT, signal_handler);  // Handle Ctrl+C
    signal(SIGTERM, signal_handler);  // Handle termination signals

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	skel = kprobe_unlink_ringbuffer_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	err = kprobe_unlink_ringbuffer_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        kprobe_unlink_ringbuffer_bpf__destroy(skel);
		return 1;
	}

	err = kprobe_unlink_ringbuffer_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
        kprobe_unlink_ringbuffer_bpf__destroy(skel);
        return 1;
	}

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb),
                            handle_event_callback, NULL, NULL);
    if(!rb){
        fprintf(stderr, "Failed to create ring buffer\n");
        kprobe_unlink_ringbuffer_bpf__destroy(skel);
        return 1;
    }

    printf("%-8s %-6s %-16s %s\n", "EVENT", "PID", "COMM", "FILENAME");

    while(running){
        err = ring_buffer__poll(rb, 100);
        if(err < 0 && err != -EINTR){
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            break;
        }
    }
    ring_buffer__free(rb);
	kprobe_unlink_ringbuffer_bpf__destroy(skel);
    printf("Exiting program\n");
	return 0;
}