# learn ebpf

## 安装bcc(可选)
```shell
# 安装bcc和bpftrace
# Ubuntu/Debian
sudo apt-get install bpfcc-tools
# 验证安装
dpkg -L bpfcc-tools | head -20
ls /usr/sbin/*-bpfcc
python3 -c "from bcc import BPF; print('BCC OK')" #  检查 BCC Python 模块
sudo apt-get install -y bpftrace
```
## 安装libbpf
```shell
sudo apt install -y libelf-dev pkg-config
sudo apt install clang
# 安装libbpf
git clone https://github.com/libbpf/libbpf.git
cd libbpf/src
NO_PKG_CONFIG=1 make
mkdir build root
sudo BUILD_STATIC_ONLY=y PREFIX=/usr/local/bpf make install

# 安装bpftool, 
ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | head -1
sudo ln -sf $(ls /usr/lib/linux-tools/*/bpftool | head -1) /usr/local/bin/bpftool

```

## 参考阅读

- [Brendan Gregg's Homepage](https://www.brendangregg.com/)
- [awesome-ebpf](https://github.com/zoidyzoidzoid/awesome-ebpf)
- [eBPF.io](https://ebpf.io/)
- [Libbpf-c++](https://docs.ebpf.io/ebpf-library/libbpf/)
- [eBPF.party](https://ebpf.party/)
- [bpf – blog](https://kernelreload.club/wordpress/archives/tag/bpf)
- [ebpf入门](http://kerneltravel.net/blog/2021/ebpf_beginner/ebpf.pdf)
- [eBPF Tutorial](https://www.cse.iitb.ac.in/~puru/courses/spring2024-25/lectures/ebpf-introduction.pdf)
- [bilibili-linux内核调试追踪技术20讲](https://space.bilibili.com/646178510/lists/468091?type=season)
- [bilibili-ebpf零基础入门](https://www.bilibili.com/video/BV1JmVjzaEVX/)