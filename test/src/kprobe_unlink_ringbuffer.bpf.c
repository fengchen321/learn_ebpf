#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";
#define RINGBUF_SIZE (256 * 1024)  // 256 KB ring buffer size
struct event{
    int pid;
    char comm[16];
    char filename[256];
};
// perf event array map to send data to user space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} rb SEC(".maps");

SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
    struct event *evt;
    const char* fileNamePtr;
    __u64 avail_data = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
    if (RINGBUF_SIZE - avail_data < sizeof(*evt)) {
        bpf_printk("Not enough space in ringbuf\n");
        return 0;
    }

    evt = bpf_ringbuf_reserve(&rb, sizeof(*evt), 0);
    if (!evt) {
        bpf_printk("Failed to reserve ringbuf space\n");
        return 0;
    }

    evt->pid = bpf_get_current_pid_tgid() >> 32;  // pid is in the upper 32 bits, tgid in lower 32 bits
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    fileNamePtr = BPF_CORE_READ(name, name);
    bpf_probe_read_kernel_str(&evt->filename, sizeof(evt->filename), fileNamePtr);
    // ctx is the context of the kprobe
    bpf_ringbuf_submit(evt, 0);
    return 0;
}