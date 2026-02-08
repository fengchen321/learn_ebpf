#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <signal.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include "hello.skel.h" // 生成的skeleton头文件

struct comm_key {
    char name[16];
};

// libbpf调试输出回调函数
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	const char *color = "";
	const char *reset = "\033[0m";

	switch (level) {
		case LIBBPF_WARN:
			color = "\033[31;1m";
			break;
		case LIBBPF_INFO:
			color = "\033[33;1m";
			break;
		case LIBBPF_DEBUG:
			color = "\033[36;1m";
			break;
		default:
			color = "\033[0m";
			break;
	}

	int ret = fprintf(stderr, "%s", color);
    ret += vfprintf(stderr, format, args);
    ret += fprintf(stderr, "%s", reset);
	return ret;
}

int main()
{
	struct hello_bpf *skel;
	int err;
	// 启用libbpf严格模式
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	// 设置libbpf的打印回调
	libbpf_set_print(libbpf_print_fn);

	// 1. 打开BPF程序（读取skeleton）
	skel = hello_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}
	// 2. 加载BPF字节码到内核
	err = hello_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	// 3. 更新Map，追踪进程名字
	struct comm_key key = {};
	strncpy(key.name, "hello", sizeof(key.name));
	__u32 enabled = 1;
	fprintf(stderr, "Setting filter comm to %s\n", key.name);
	err = bpf_map__update_elem(skel->maps.comm_filter, &key, sizeof(key), 
							&enabled, sizeof(enabled), BPF_ANY);
	if (err < 0) {
		fprintf(stderr, "Error updating map with comm filter: %s\n", strerror(err));
		goto cleanup;
	}

	// 4. 附加BPF程序到tracepoint
	err = hello_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Successfully started!\n");
	printf("Please run 'sudo cat /sys/kernel/debug/tracing/trace_pipe' in another terminal and then execute 'echo Hello, eBPF!' to trigger the BPF program.\n");
	printf("Press Enter to trigger write()...\n");
	getchar();
	printf("Hello eBPF!\n");

cleanup:
	//销毁BPF程序
	hello_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}