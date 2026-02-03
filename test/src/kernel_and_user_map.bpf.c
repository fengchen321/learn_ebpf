#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct process_info {
    __u32 pid;
    char comm[16]; // process name
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct process_info);
} process_map SEC(".maps");

SEC("tp/sched/sched_process_exec")
int trace_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct process_info info = {};
    
    info.pid = pid;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));
    
    bpf_map_update_elem(&process_map, &pid, &info, BPF_ANY);
    
    bpf_printk("Process exec: PID=%d, COMM=%s\n", info.pid, info.comm);
    
    return 0;
}

SEC("tp/sched/sched_process_exit")
int trace_process_exit(struct trace_event_raw_sched_process_exit *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&process_map, &pid);

    return 0;
}