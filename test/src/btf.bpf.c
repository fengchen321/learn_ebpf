#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct event {
    u32 pid;
    u32 ppid;
    u32 uid;
    int ret;
    char comm[16];
    char filename[256];
};

struct args_t {
    const char *filename;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, struct args_t);
} pid_to_filename SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

const volatile bool targ_failed = false; // record failures

static __always_inline
int trace_exit(struct trace_event_raw_sys_exit* ctx)
{
    struct event evt = {};
    struct args_t *ap;
    int ret;
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    ap = bpf_map_lookup_elem(&pid_to_filename, &pid);
    if (!ap) {
        return 0;
    }

    ret = ctx->ret;
    if (targ_failed && ret >= 0) {
        bpf_map_delete_elem(&pid_to_filename, &pid);
        return 0;
    }

    evt.pid = pid;
    evt.uid = bpf_get_current_uid_gid();

    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    bpf_probe_read_user_str(&evt.filename, sizeof(evt.filename), ap->filename);
    evt.ret = ret;

    // method 1: bpf_get_current_task + BPF_CORE_READ
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    evt.ppid = BPF_CORE_READ(task, real_parent, pid);
    // error usage : event.ppid = task->real_parent->pid; 

    // method 2: bpf_get_current_task_btf + BPF_CORE_READ
    // struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    // evt.ppid = BPF_CORE_READ(task, real_parent, pid);

    // method 3: bpf_get_current_task + bpf_core_read
    // struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    // struct task_struct *parent;
    // pid_t ppid;
    // bpf_core_read(&parent, sizeof(parent), &task->real_parent);
    // bpf_core_read(&ppid, sizeof(ppid), &parent->pid);
    // evt.ppid = ppid;

    // method 4: bpf_get_current_task + bpf_probe_read
    // struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    // struct task_struct *parent;
    // bpf_probe_read(&parent, sizeof(parent), &task->real_parent);
    // bpf_probe_read(&evt.ppid, sizeof(evt.ppid), &parent->pid);


    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

    bpf_map_delete_elem(&pid_to_filename, &pid);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int trace_enter_open(struct trace_event_raw_sys_enter *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct args_t args = {};
    args.filename = (const char *)ctx->args[0];
    bpf_map_update_elem(&pid_to_filename, &pid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_open")
int trace_exit_open(struct trace_event_raw_sys_exit* ctx)
{
	return trace_exit(ctx);
}