#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "kprobe_unlink.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}
int main(int argc, char **argv)
{
	struct kprobe_unlink_bpf *skel;
	int err;
	pid_t pid;
	unsigned index = 0;

	//设置libbpf的严格模式
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	// 1. 设置调试输出函数，libbpf发生错误会回调libbpf_print_fn
	libbpf_set_print(libbpf_print_fn);

	// 2. 打开BPF程序
	skel = kprobe_unlink_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}
	// 3. 加载BPF字节码
	err = kprobe_unlink_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	// 4. 挂载BPF字节码到kprobe
	err = kprobe_unlink_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	//运行成功后，打印tracepoint的输出日志
	printf("Successfully started!\n");
	system("sudo cat /sys/kernel/debug/tracing/trace_pipe");

cleanup:
	//销毁BPF程序
	kprobe_unlink_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}