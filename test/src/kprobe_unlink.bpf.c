#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlink_at, int dfd, struct filename *name)
{
    const char* fileName;
    fileName = BPF_CORE_READ(name, name);
    bpf_printk("do_unlinkat kprobe triggered, filename: %s\n", fileName);
    return 0;
}