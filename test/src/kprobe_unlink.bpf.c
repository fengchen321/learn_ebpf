#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";
#if 1
SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
    const char* fileName;
    fileName = BPF_CORE_READ(name, name);
    // bpf_core_read(&fileName, sizeof(fileName), &name->name);
    bpf_printk("do_unlinkat kprobe triggered, filename: %s\n", fileName);
    return 0;
}
#else
SEC("kprobe/do_unlinkat")
int trace_unlinkat(struct pt_regs *ctx)
{
    char fname[256] = {};
    struct filename *file;

    bpf_core_read(&file, sizeof(file), (void*)PT_REGS_PARM2(ctx));
    BPF_CORE_READ_STR_INTO(&fname, file, name);

    bpf_printk("do_unlinkat kprobe triggered, filename: %s\n", fname);
    return 0;
}
#endif