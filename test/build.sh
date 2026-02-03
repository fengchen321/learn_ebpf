#!/bin/bash
set -e
cd build
# 1. 将hello.bpf.c编译成hello.bpf.o
clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I/usr/include/x86_64-linux-gnu -I /usr/local/bpf/include -I include/ \
-c ../src/hello.bpf.c -o hello.bpf.o 
# 2. 将hello.bpf.o转换为hello.skel.h
bpftool gen skeleton hello.bpf.o > hello.skel.h

# 3. 编译用户态程序hello.c和hello.o
clang -g -O2 -Wall -I /usr/local/bpf/include -I .  -c ../src/hello.c -o hello.o
# 4. 链接成为可执行程序hello
clang -Wall -O2 -g hello.o -static -lbpf -lelf -lz -o hello -L/usr/local/bpf/lib64
