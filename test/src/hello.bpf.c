#include "vmlinux.h" 			// 内核数据结构定义
#include <bpf/bpf_helpers.h> 	// 辅助函数
#include <bpf/bpf_tracing.h> 	// 跟踪相关宏
#include <bpf/bpf_core_read.h> 	// CORE读取

char LICENSE[] SEC("license") = "Dual BSD/GPL"; // 许可证声明

// 定义类型别名
typedef unsigned int u32;
typedef int pid_t;
struct comm_key {
    char name[16];
};

// 创建一个数组Map，用于在用户态和内核态之间传递comm
struct {
	__uint(type, BPF_MAP_TYPE_HASH); 	// HASH类型Map
	__uint(max_entries, 8);				// 最大条目数：8
	__type(key, struct comm_key);		// key类型：comm_key
	__type(value, u32);					// value类型：1 = 启用
} comm_filter SEC(".maps");				// 定义在".maps" section

// 挂载到tracepoint：syscalls/sys_enter_write
// 当进程调用write()系统调用时触发
SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
	// 获取当前进程的命令名
	char comm[16];
	bpf_get_current_comm(&comm, sizeof(comm));
	// 从Map中查找我们设置的过滤comm
	u32 *enableed = bpf_map_lookup_elem(&comm_filter, &comm);
	if (!enableed || *enableed != 1)
		return 0;
	// 获取当前进程的PID（高32位）
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("[%s] BPF triggered from PID %d.\n", comm, pid);

	return 0;
}