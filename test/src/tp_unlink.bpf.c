#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// sudo cat /sys/kernel/debug/tracing/available_events | grep unlinkat
// sudo bpftrace -l 'tracepoint:*' | grep unlinkat
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_enter_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // view parameter details:
    // sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_unlinkat/format
    // sudo bpftrace -l tracepoint:syscalls:sys_enter_unlinkat -v
    // int unlinkat(int dfd, const char *pathname, int flag);
    const char *user_filename = (const char *)ctx->args[1];
    char filename[256] = {};
    bpf_probe_read_user_str(filename, sizeof(filename), user_filename);
    
    bpf_printk("tracepoint triggered, pid: %d, comm: %s, filename: %s\n", pid, comm, filename);
    return 0;
}
