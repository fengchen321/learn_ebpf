#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct event{
    int pid;
    char comm[16];
    char filename[256];
};
// perf event array map to send data to user space
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
    struct event evt = {};
    const char* fileNamePtr;
    evt.pid = bpf_get_current_pid_tgid() >> 32;  // pid is in the upper 32 bits, tgid in lower 32 bits
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    fileNamePtr = BPF_CORE_READ(name, name);
    bpf_probe_read_kernel_str(&evt.filename, sizeof(evt.filename), fileNamePtr);
    // ctx is the context of the kprobe
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}