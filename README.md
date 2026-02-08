# eBPF 学习

> 系统学习eBPF（Extended Berkeley Packet Filter）技术。

---

## 第一章：环境搭建与基础概念

### 1.1 eBPF核心概念

eBPF是Linux内核中的一个革命性技术，它允许你在内核态安全地运行自定义程序，而无需修改内核源码或加载内核模块。

**eBPF的主要特点：**

1. **安全性**：eBPF程序在执行前会经过JIT编译器和验证器的检查，确保不会导致内核崩溃或安全漏洞
2. **高性能**：程序在内核态执行，减少了用户态和内核态之间的上下文切换开销
3. **灵活性**：可用于网络包处理、系统调用跟踪、性能分析等多种场景
4. **实时性**：无需重启内核即可动态加载和卸载程序

**eBPF程序的生命周期：**

```
编写C代码 → 编译为字节码 → 验证器检查 → JIT编译 → 加载到内核 → 附加到Hook点 → 执行
```

**常见的Hook类型：**

| Hook类型 | 描述 | 示例 |
|---------|------|-----|
| Tracepoint | 内核静态跟踪点 | `tracepoint/syscalls/sys_enter_write` |
| Kprobe | 内核函数动态探针 | `kprobe/do_unlinkat` |
| Uprobe | 用户态函数探针 | 用户程序函数 |
| TC | 流量控制 | 网络包处理 |
| XDP | 快速数据包处理 | 网卡入口处理 |

### 1.2 安装bcc和bpftrace（可选）

如果需要使用BCC或bpftrace工具，可以按以下步骤安装：

```shell
# Ubuntu/Debian 安装bcc和bpftrace
sudo apt-get install bpfcc-tools
# 验证安装
dpkg -L bpfcc-tools | head -20
ls /usr/sbin/*-bpfcc
python3 -c "from bcc import BPF; print('BCC OK')"
sudo apt-get install -y bpftrace
```

### 1.3 安装libbpf和bpftool

libbpf是使用C语言开发eBPF程序的主要库：

```shell
# 安装基础依赖
sudo apt install -y libelf-dev pkg-config
sudo apt install clang

# 安装libbpf
git clone https://github.com/libbpf/libbpf.git
cd libbpf/src
NO_PKG_CONFIG=1 make
mkdir build root
sudo BUILD_STATIC_ONLY=y PREFIX=/usr/local/bpf make install

# 设置bpftool
ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | head -1
sudo ln -sf $(ls /usr/lib/linux-tools/*/bpftool | head -1) /usr/local/bin/bpftool
```

### 1.4 项目结构说明

```
learn_ebpf/
├── README.md                 # 项目说明文档
├── bcc/                      # BCC示例代码
│   ├── hello_world.py        # BCC Python示例
│   └── path.bt              # bpftrace脚本
├── libbpf/                   # libbpf子模块
└── test/                     # 主要示例程序
    ├── CMakeLists.txt        # CMake构建配置
    ├── include/             # 头文件
    └── src/                 # 源代码
        ├── *.bpf.c          # eBPF内核程序
        └── *.c              # 用户空间程序
```

### 1.5 编译流程说明

**使用CMake编译：**

```shell
cd test
mkdir build && cd build
cmake ..
make
```

**ebpf程序编译流程：**

```shell
cd test/build
# 1. 生成vmlinux.h，包含内核所有数据结构定义的头文件，检查内核是否支持 BTF：ls /sys/kernel/btf/vmlinux
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 2. 编译eBPF程序为字节码
clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 \
  -I/usr/include/x86_64-linux-gnu -I/usr/local/bpf/include -I.\
  -c ../src/hello.bpf.c -o hello.bpf.o

# 3. 生成skeleton头文件
bpftool gen skeleton hello.bpf.o > hello.skel.h

# 4. 编译用户态程序
clang -g -O2 -Wall -I/usr/local/bpf/include -I. -c ../src/hello.c -o hello.o

# 5. 链接
clang -Wall -O2 -g hello.o -static -lbpf -lelf -lz -o hello -L /usr/local/bpf/lib64
```

---

## 第二章：Hello World - 基础 Tracepoint

### 2.1 原理讲解

**Tracepoint**是内核提供的静态跟踪点，它们在内核代码的关键路径上预先定义好了位置。相比Kprobe，Tracepoint更稳定，因为它们不会因为内核函数的变化而失效。

本章示例程序监控所有进程的`write()`系统调用，并通过comm进程名过滤。

**核心组件：**

1. **SEC宏**：定义eBPF程序的section，指定附加的hook点
2. **BPF_MAP_TYPE_HASH**：哈希表类型
3. **bpf_printk**：内核态打印函数，输出到`/sys/kernel/debug/tracing/trace_pipe`
4. **Skeleton**：由bpftool生成的代码框架，简化eBPF程序的加载过程

`tp/syscalls/sys_enter_write`：Tracepoint路径，表示`write()`系统调用入口。

`tp/syscalls/`是`tracepoint/syscalls/`的简写，两者是等价的。
查询挂载点方式
```shell
# 方法1：查看/sys/kernel/debug/tracing/available_events
sudo cat /sys/kernel/debug/tracing/available_events | grep write

# 方法2：使用bpftrace list
sudo bpftrace -l 'tracepoint:syscalls:*' | grep write
```
```c
// 用不到ctx直接void*，也可以直接trace_event_raw_sys_enter
// 函数名可以随便写，只要SEC定义的section名一致即可

// 系统调用进入时触发，可以获取输入参数
SEC("tracepoint/syscalls/sys_enter_write")
int trace_enter_write(struct trace_event_raw_sys_enter *ctx)
{}
// 系统调用退出时触发，可以获取返回值
SEC("tracepoint/syscalls/sys_exit_write")
int trace_enter_exit(struct trace_event_raw_sys_exit *ctx)
{}
```

### 2.2 ctx参数
```c
struct trace_event_raw_sys_enter {
	struct trace_entry ent;
	long int id;
	long unsigned int args[6]; // 系统调用参数数组
	char __data[0];
};
```

查看参数格式细节，可以通过ctx获取:
```shell
# 方法1：查看/sys/kernel/debug/tracing/events
sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_write/format

# 方法2：使用bpftrace list
sudo bpftrace -l tracepoint:syscalls:sys_enter_write -v
```
前 8 个字节的字段（common_type、common_flags 等）普通 eBPF 程序不能直接访问,只能通过特定的 BPF helper 函数访问。
```shell
name: sys_enter_write
ID: 739
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:unsigned int fd;  offset:16;      size:8; signed:0;
        field:const char * buf; offset:24;      size:8; signed:0;
        field:size_t count;     offset:32;      size:8; signed:0;

print fmt: "fd: 0x%08lx, buf: 0x%08lx, count: 0x%08lx", ((unsigned long)(REC->fd)), ((unsigned long)(REC->buf)), ((unsigned long)(REC->count))
```

### 2.3 代码解析
**关键API说明：**

| API | 描述 |
|-----|------|
| `bpf_get_current_pid_tgid()` | 获取当前进程的PID和TGID |
| `bpf_map_lookup_elem(map, key)` | 从Map中查找元素 |
| `bpf_printk(fmt, ...)` | 格式化输出到trace_pipe |

**Skeleton工作流程：**
该头文件是生成的，里面包含了加载、卸载、附加和清理eBPF程序所需的**函数和结构体**。函数名前缀为`<object>_bpf__`，都和编译生成的eBPF程序文件名一致。
```
hello.skel.h
    │
    ├── hello_bpf__open()      → 打开并解析bpf.o
    ├── hello_bpf__load()      → 加载到内核
    ├── hello_bpf__attach()    → 附加到hook点
    └── hello_bpf__destroy()   → 清理资源
```

输出到`/sys/kernel/debug/tracing/trace_pipe`，需要root权限。

---

## 第三章： Raw_tracepoint

**Tracepoint分类：**

| 类型 | 描述 | 特点 |
|-----|------|-----|
| tracepoint | 使用结构化参数 | 参数自动解析，易于使用 |
| raw_tp | 原始tracepoint | 直接访问寄存器，更灵活 |

**参数来源：**
- tracepoint：通过`struct trace_event_raw_sys_enter* ctx->args[]`访问
- raw_tp：通过`struct bpf_raw_tracepoint_args* ctx->args[]`访问

```c
// 监控所有系统调用进入
SEC("raw_tp/sys_enter")
int raw_trace_enter(struct bpf_raw_tracepoint_args *ctx)
{}
```

```c
struct bpf_raw_tracepoint_args {
	__u64 args[0];
};
// raw_tp的args数组：
args[0] = struct pt_regs *    (寄存器状态指针)
args[1] = long syscall_nr     (系统调用号)
```

系统调用号获取
```shell
# 方法1: 查看头文件
grep -r "__NR_unlinkat" /usr/include/

# 方法2: 查看内核符号表
cat /usr/include/asm/unistd_64.h | grep unlinkat
```

从寄存器中获取参数
```c
int unlinkat(int dfd, const char *pathname, int flag);
// x86_64 syscall约定：rdi, rsi, rdx, r10, r8, r9
// 参数2 (pathname) 位于 RSI 寄存器
```

**PT_REGS宏说明：**

| 宏 | 寄存器 | 描述 |
|-----|-----|-----|
| `PT_REGS_PARM1_CORE(regs)` |RDI| 获取第1个参数 |
| `PT_REGS_PARM2_CORE(regs)` |RSI| 获取第2个参数 |
| `PT_REGS_PARM3_CORE(regs)` |RDX| 获取第3个参数 |
| `PT_REGS_PARM4_CORE(regs)` |R10| 获取第4个参数 |
| `PT_REGS_PARM5_CORE(regs)` |R8 | 获取第5个参数 |
| `PT_REGS_PARM6_CORE(regs)` |R9 | 获取第6个参数 |
| `PT_REGS_PARM7_CORE(regs)` | - | 获取第7个参数 |
| `PT_REGS_PARM8_CORE(regs)` | - | 获取第8个参数 |
| `PT_REGS_RET_CORE(regs)`   | - | 获取返回值    |
| `PT_REGS_SP_CORE(regs)`    | - | 获取栈指针    |

**Q: PT_REGS_PARM2_CORE和PT_REGS_PARM2有什么区别？**

A: `_CORE`后缀表示使用BTF进行CO-RE (Compile Once, Run Everywhere) 安全访问（自动处理内核版本间的结构体差异），兼容性更好。PT_REGS_PARM2宏仅适用于kprobe/uprobe。

## 第四章：内核探测 - Kprobe

### 4.1 Kprobe简介

```c
// kprobe：内核函数入口时触发
SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{}
// kretprobe：内核函数返回时触发
SEC("kretprobe/do_unlinkat")
int BPF_KRETPROBE(do_unlinkat_exit, long ret)
{}
```

[BPF_KPROBE](https://docs.ebpf.io/ebpf-library/libbpf/ebpf/BPF_KPROBE/)宏可以在程序中编写参数列表，宏会进行参数转换。

[BPF_KRETPROBE](https://docs.ebpf.io/ebpf-library/libbpf/ebpf/BPF_KRETPROBE/)宏只提供可选的返回值。
**BPF_KPROBE宏解析：**
```c
// 原型：BPF_KPROBE(name, args...)
BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
//            │            │                    │
//            │            │                    └── 参数2
//            │            └── 参数1
//            └── 函数名
```

旧方法
[PT_REGS_PARM](http://docs.ebpf.io/ebpf-library/libbpf/ebpf/PT_REGS_PARM/)宏从上下文中提取给定参数，然后手动将其转换为实际类型。

```c
SEC("kprobe/do_unlinkat")
int trace_unlinkat(struct pt_regs *ctx)
{}
```

[BPF_CORE_READ](https://docs.ebpf.io/ebpf-library/libbpf/ebpf/BPF_CORE_READ/)宏简化了读取多级成员的操作。

```c
// 其他方式参考BTF章节
// BPF_CORE_READ：一次性读取嵌套结构
fileName = BPF_CORE_READ(name, name);

// 手动方式（等价）：
bpf_core_read(&fileName, sizeof(fileName), &name->name);
```

**查找可用的kprobe函数名**

```shell
# 方法1：使用bpftrace list
sudo bpftrace -l 'kprobe:*' | grep do_unlinkat

# 方法2：查看/proc/kallsyms
cat /proc/kallsyms  | grep do_unlinkat
```
## 第五章：用户态探测 - Uprobe

### 5.1 Uprobe简介

**Uprobe**类似于Kprobe，但针对用户态程序。它可以附加到任何用户程序的函数上：
```c
// uprobe：函数入口时触发
SEC("uprobe/uprobe_add")
int BPF_UPROBE(uprobe_add, int a, int b)
{}
//uretprobe：函数返回时触发
SEC("uretprobe/uprobe_add")
int BPF_URETPROBE(uretprobe_add, int ret)
{}
```
uprobe_add_target.c - 测试目标程序包含要hook的函数uprobe_add。


### 5.2 代码解析
LIBBPF_OPTS宏用于初始化各种bpf相关的选项结构体。
```c
struct bpf_uprobe_opts {
    /* size of this struct, for forward/backward compatibility */
    size_t sz;
    size_t ref_ctr_offset;
    __u64 bpf_cookie;
    bool retprobe;         // 是否为返回探针
    const char *func_name; // 要选择附加的函数名称，提供后libbpf自动查找偏移量
    enum probe_attach_mode attach_mode;
    size_t :0;
};
```

使用[bpf_program__attach_uprobe_opts](https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_program__attach_uprobe_opts/)附加探针到目标函数

| 参数 | 描述 |
|-----|------|
| prog | eBPF程序 |
| pid | 进程ID，-1表示所有进程 |
| path | 目标程序路径 |
| offset | 函数在二进制文件中的偏移 |
| opts | uprobe选项（函数名、是否为retprobe等） |

**找函数的偏移量**
```shell
# 方法1：使用nm或readelf
nm ./uprobe_add_target | grep uprobe_add
readelf -s uprobe_add_target| grep uprobe_add
# 输出：
33: 0000000000001149    24 FUNC    GLOBAL DEFAULT   16 uprobe_add

# 方法2：使用objdump
objdump -t ./uprobe_add_target | grep uprobe_add
```

### 5.3 使用

```shell
# 终端1 绑定ebpf
sudo ./uprobe_add ./uprobe_add_target
# 终端2 查看输出
sudo cat /sys/kernel/debug/tracing/trace_pipe
# 终端3 程序运行
./uprobe_add_target
# 检查eBPF程序是否加载
sudo bpftool prog list
# 检查eBPF程序是否加载
sudo bpftool link list
```

## 第六章：事件传递 Perf Buffer vs Ring Buffer

### 6.1 Perf Buffer 原理讲解 
**Perf Buffer**是eBPF程序向用户空间传递数据的传统方式。它使用内核的perf event子系统：
```
eBPF内核程序                    用户空间程序
     │                                │
     │  bpf_perf_event_output()       │
     │───────────► Per-CPU Ring ─────►│  perf_buffer__poll()
     │              Buffer            │
     │                                │
```

**特点：**
- 每个CPU核心有独立的buffer
- 支持事件丢失检测
- 需要手动管理buffer轮询

### 6.2 Perf Buffer 代码解析

[BPF_MAP_TYPE_PERF_EVENT_ARRAY](https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_PERF_EVENT_ARRAY/)

`SEC(".maps")`：定义map

[bpf_perf_event_output](https://docs.ebpf.io/linux/helper-function/bpf_perf_event_output/) 函数将数据从内核态空间传输到用户态空间。事件写入perf buffer，该函数会自动处理buffer的轮询和溢出情况。


**用户态 buffer 操作API：**

| API | 描述 |
|-----|------|
| [perf_buffer__new](https://docs.ebpf.io/ebpf-library/libbpf/userspace/perf_buffer__new/) | 初始化perf buffer |
| [perf_buffer__poll](https://docs.ebpf.io/ebpf-library/libbpf/userspace/perf_buffer__poll/) | 轮询perf buffer，获取事件 |
| [perf_buffer__free](https://docs.ebpf.io/ebpf-library/libbpf/userspace/perf_buffer__free/) | 释放perf buffer |

**perf_buffer__new**
> map_fd: perf event array的文件描述符
> 
> page_cnt：每个 CPU 缓冲区分配的内存页数。默认页面大小是4KB，8页就是32KB。更大的buffer可以减少事件丢失。
> 
> sample_cb：处理事件的回调函数
> 
> lost_cb：处理丢失事件的回调函数
> 
> ctx：传递给回调函数的上下文
> 
> opts: perf buffer选项

[bpf_map__fd](https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_map__fd/)：获取perf buffer的文件描述符

### 6.3 Ring Buffer 
[BPF ring buffer](https://nakryiko.com/posts/bpf-ringbuf/)

perfbuf 是 per-CPU 环形缓冲区（circular buffers），能实现高效的 “内核-用户空间”数据交互。但是有缺陷：

1. 内存使用效率低下（inefficient use of memory）

2. 事件顺序无法保证（event re-ordering）

ringbuf 是一个“多生产者、单消费者”（multi-producer, single-consumer，MPSC） 队列，可安全地在多个 CPU 之间共享和操作。

| Ring Buffer | Perf Buffer |
|---------------------|---------------------|
| 单个共享ring per map | 每个CPU独立的ring    |
| 更少的内存开销        | 内存开销较大         |
| 支持异步reservation  | 需要同步分配         |
| 更简单的API          | 较复杂的API         |

[BPF_MAP_TYPE_RINGBUF](https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_RINGBUF/):环形缓冲映射,数据以队列/先进先出（FIFO）方式发送。

在使用 ringbuf 时，map结构体里max_entries 必须是 2 的幂次方、并且是 PAGE_SIZE 的倍数。

**内核态 buffer 操作API：**

| API | 描述 |
|-----|------|
| [bpf_ringbuf_query](https://docs.ebpf.io/linux/helper-function/bpf_ringbuf_query/) | 查询ring buffer状态，可通过flags设置|
| [bpf_ringbuf_reserve](https://docs.ebpf.io/linux/helper-function/bpf_ringbuf_reserve/) | 预留空间，返回一个指向预留内存的指针 |
| [bpf_ringbuf_submit](https://docs.ebpf.io/linux/helper-function/bpf_ringbuf_submit/) | 提交数据。|


**用户态 buffer 操作API：**

| API | 描述 |
|-----|------|
| [ring_buffer__new](https://docs.ebpf.io/ebpf-library/libbpf/userspace/ring_buffer__new/) | 初始化ring buffer |
| [ring_buffer__poll](https://docs.ebpf.io/ebpf-library/libbpf/userspace/ring_buffer__poll/) | 读取数据 |
| [ring_buffer__free](https://docs.ebpf.io/ebpf-library/libbpf/userspace/ring_buffer__free/) | 释放ring buffer|


## 第七章：BPF Map

### 7.1 常见[BPF Map类型](https://docs.ebpf.io/linux/map-type/)

| 类型 | 描述 | 使用场景 |
|-----|------|---------|
| BPF_MAP_TYPE_ARRAY | 数组 | 固定大小索引查找 |
| BPF_MAP_TYPE_HASH | 哈希表 | 键值对存储 |
| BPF_MAP_TYPE_PERF_EVENT_ARRAY | Perf事件 | 用户空间数据传输 |
| BPF_MAP_TYPE_RINGBUF | Ring Buffer | 高性能数据传输 |
| BPF_MAP_TYPE_PROG_ARRAY | 程序数组 | 尾调用链 |

### 7.2 BPF Map API

**内核态 map 操作API：**

| API | 描述 |
|-----|------|
| [bpf_map_lookup_elem](https://docs.ebpf.io/linux/helper-function/bpf_map_lookup_elem/) | 查找元素 |
| [bpf_map_update_elem](https://docs.ebpf.io/linux/helper-function/bpf_map_update_elem/) | 更新元素 |
| [bpf_map_delete_elem](https://docs.ebpf.io/linux/helper-function/bpf_map_delete_elem/) | 删除元素 |

内核态调用的是helper function，用户态调用的是userspace library function，参数不一样。
> **注意**：比如bpf_map_delete_elem：内核态用指针（如 `&map`），用户态用文件描述符（如 `map_fd`）。

**用户态 map 操作API：**

map可以直接在用户空间创建Map，不依赖skeleton。

`bpf_map__*()` 是 `bpf_map_*()`的高阶等价版本。

| API | 描述 |
|-----|------|
| [bpf_map_create](https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_map_create/) | 创建Map |
| [bpf_map_lookup_elem](https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_map_lookup_elem/) | 查找元素 |
| [bpf_map_update_elem](https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_map_update_elem/) | 更新元素 |
| [bpf_map_delete_elem](https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_map_delete_elem/) | 删除元素 |
| [bpf_map_get_next_key](https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_map_get_next_key/) | 获取下一个key |
| [bpf_map_lookup_and_delete_elem](https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_map_lookup_and_delete_elem/) | 查找并删除元素 |


## 第八章：BTF(BPF Type Format) 

### 8.1 原理讲解

**BTF**是内核类型的元数据格式，它允许eBPF程序在不依赖内核头文件的情况下理解内核数据结构。

**CO-RE**利用BTF信息，使同一份eBPF代码可以在不同内核版本上运行，而不需要重新编译。

不同的内核版本，结构体的大小和布局都可能不同，BTF + CO-RE：自动处理偏移量。CO-RE 依赖 BTF 提供的类型信息。

### 8.2 BTF 读取内存

|特性|[bpf_probe_read](https://docs.ebpf.io/linux/helper-function/bpf_probe_read/) | [bpf_core_read](https://docs.ebpf.io/ebpf-library/libbpf/ebpf/bpf_core_read/)|[BPF_CORE_READ](https://docs.ebpf.io/ebpf-library/libbpf/ebpf/BPF_CORE_READ/) |
|-----|--|-----|-----|
|类型|辅助函数|宏|宏|
|CO-RE支持|不支持|支持|支持|
|场景|读取任意内存|读取单个字段|读取嵌套字段|

**BPF_CORE_READ 安全地读取内核结构体字段**
```c
// BPF_CORE_READ 用于内核结构体,取决于目标地址是谁的内存空间。
struct task_struct *task = (struct task_struct *)bpf_get_current_task();

pid_t pid = BPF_CORE_READ(task, pid); // 读取单个字段 task->pid

pid_t ppid = BPF_CORE_READ(task, real_parent, pid); // 读取嵌套字段 task->real_parent->pid
```

**BPF_CORE_READ_INTO (读取到变量)**
```c
struct task_struct *task = (struct task_struct *)bpf_get_current_task();
pid_t ppid;
BPF_CORE_READ(&ppid, task, real_parent, pid);
```

**BPF_CORE_READ_STR_INTO (读取字符串)**
```c
struct task_struct *task = (struct task_struct *)bpf_get_current_task();
char comm[16];

BPF_CORE_READ_STR_INTO(comm, task, comm);
```

### 8.3 example: 读取ppid
```c
struct task_struct {
    ...
    pid_t pid;
    struct task_struct *real_parent;
    ...
}
```

方法1：bpf_get_current_task + BPF_CORE_READ

```c
struct task_struct *task = (struct task_struct *)bpf_get_current_task();
evt.ppid = BPF_CORE_READ(task, real_parent, pid);
// error : event.ppid = task->real_parent->pid; 
```

方法2：bpf_get_current_task_btf + BPF_CORE_READ

```c
// `bpf_get_current_task_btf`是5.5+内核引入的BTF版本，直接返回指向task_struct的BTF指针，更安全。
struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
evt.ppid = BPF_CORE_READ(task, real_parent, pid);
```

方法3：bpf_get_current_task + bpf_core_read

```c
struct task_struct *task = (struct task_struct *)bpf_get_current_task();
struct task_struct *parent;
pid_t ppid;
bpf_core_read(&parent, sizeof(parent), &task->real_parent);
bpf_core_read(&ppid, sizeof(ppid), &parent->pid);
evt.ppid = ppid;
```
方法4：bpf_get_current_task + bpf_probe_read

```c
struct task_struct *task = (struct task_struct *)bpf_get_current_task();
struct task_struct *parent;
bpf_probe_read(&parent, sizeof(parent), &task->real_parent);
bpf_probe_read(&evt.ppid, sizeof(evt.ppid), &parent->pid);
```
|方式|函数|返回类型|类型安全|
|-----|-----|-----|-----|
|传统方式|	[bpf_get_current_task()](https://docs.ebpf.io/linux/helper-function/bpf_get_current_task/)|	void * (需要强制转换)	|弱|
|BTF方式|	[bpf_get_current_task_btf()](https://docs.ebpf.io/linux/helper-function/bpf_get_current_task_btf/)|	struct task_struct *|强|

## 第九章：TC (Traffic Control)

TC (Traffic Control) 是 Linux 内核的流量控制子系统，eBPF TC Ingress 程序附加到网络接口的入站方向, TC Egress 程序附加到网络接口的出站方向。

### 9.1 代码解析
[tc.bpf.c example](https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/tc.bpf.c)
[tc.c example](https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/tc.c)


**内核态**

 1. 获取包数据边界
 2. 定义以太网和IP头指针
 3. 解析以太网头部
 4. 解析IP头部
 5. 解析是否是ICMP包，放行或者丢弃

```c
struct __sk_buff {  // eBPF 提供的套接字缓冲区结构。
    ...
	__u32 data;     // 数据包起始位置
	__u32 data_end; // 数据包结束位置
    ...
};
```
[bpf_htons](https://docs.ebpf.io/ebpf-library/libbpf/ebpf/bpf_htons/): 将主机字节序转换为网络字节序

**用户态**

 1. 获取网络接口索引：[if_nametoindex](https://www.man7.org/linux/man-pages/man3/if_nametoindex.3.html)
 2. 设置bpf_tc_hook对象: .attach_point = BPF_TC_INGRESS or BPF_TC_EGRESS
 3. 创建 TC hook： [bpf_tc_hook_create](https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_tc_hook_create/)
 4. 设置TC选项prog_fd：指定要附加的eBPF程序 [bpf_program__fd](https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_program__fd/)
 5. 附加 eBPF 程序： [bpf_tc_attach](https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_tc_attach/)
 6. 分离 eBPF 程序： [bpf_tc_detach](https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_tc_detach/)

DECLARE_LIBBPF_OPTS 就是 LIBBPF_OPTS。

[qdisc](https://geek-blogs.com/blog/linux-tc-qdisc/)(Queueing Discipline，排队规则)作为 TC 的核心组件，负责管理网络接口上数据包的排队、调度和丢弃策略。


##  参考阅读

- [eBPF.io官方文档](https://ebpf.io/)
- [awesome-ebpf资源集合](https://github.com/zoidyzoidzoid/awesome-ebpf)
- [libbpf文档](https://docs.ebpf.io/ebpf-library/libbpf/)
- [Brendan Gregg的eBPF博客](https://www.brendangregg.com/)
- [eBPF.party](https://ebpf.party/)
- [eBPF入门教程](http://kerneltravel.net/blog/2021/ebpf_beginner/ebpf_beginner.pdf)
- [eBPF Tutorial](https://www.cse.iitb.ac.in/~puru/courses/spring2024-25/lectures/ebpf-introduction.pdf)
- [bilibili-ebpf零基础入门](https://www.bilibili.com/video/BV1JmVjzaEVX/)