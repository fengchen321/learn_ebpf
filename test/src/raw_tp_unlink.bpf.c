#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";


SEC("raw_tp/sys_enter")
int raw_trace_enter_unlinkat(struct bpf_raw_tracepoint_args *ctx)
{
    // grep -r "__NR_unlinkat" /usr/include/
    // cat /usr/include/asm/unistd_64.h | grep unlinkat
    #define __NR_unlinkat 263
    long syscall_id = ctx->args[1];
    if (syscall_id != __NR_unlinkat) {
        return 0;
    }

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // view parameter details:
    // int unlinkat(int dfd, const char *pathname, int flag);
    // args[0] = struct pt_regs *  args[0] 保存 struct pt_regs * 指针
    // args[1] = long syscall_id 系统调用号
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

    const char* user_filename = (const char*)PT_REGS_PARM2_CORE(regs);

    char filename[256] = {};
    // 从用户空间读取字符串参数
    bpf_probe_read_user_str(filename, sizeof(filename), user_filename);
    
    bpf_printk("tracepoint triggered, pid: %d, comm: %s, filename: %s\n", pid, comm, filename);
    return 0;
}
