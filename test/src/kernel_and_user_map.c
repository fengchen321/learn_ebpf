#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "kernel_and_user_map.skel.h"

struct process_info {
    __u32 pid;  
    char comm[16]; // process name
};

bool running = true;

void signal_handler(int sig) {
    printf("Signal received, exiting...\n");
    running = false;
}
int main(int argc, char **argv) {
    struct kernel_and_user_map_bpf *skel;
    int err;
    int map_fd;

    signal(SIGINT, signal_handler);  // Handle Ctrl+C
    signal(SIGTERM, signal_handler);  // Handle termination signals

    skel = kernel_and_user_map_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = kernel_and_user_map_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        kernel_and_user_map_bpf__destroy(skel);
        return 1;
    }
    map_fd = bpf_map__fd(skel->maps.process_map);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get process_map fd: %d\n", map_fd);
        kernel_and_user_map_bpf__destroy(skel);
        return 1;
    }

    printf("BPF program loaded and attached. Press Ctrl+C to exit.\n");

    while (running) {
        __u32 cur_key = 0;
        __u32 next_key = 0;
        bool has_cur_key = false;

        while (true) {
            err = bpf_map_get_next_key(map_fd, has_cur_key ? &cur_key : NULL, &next_key);
            if (err) {
                if (errno == ENOENT) {
                    break;
                } else {
                    fprintf(stderr, "Error getting next key: %s\n", strerror(errno));
                    break;
                }
            }

            struct process_info info = {};
            err = bpf_map_lookup_elem(map_fd, &next_key, &info);
            if (err) {
                fprintf(stderr, "Error looking up process info: %s\n", strerror(errno));
            } else {
                printf("PID: %d, Name: %s\n", info.pid, info.comm);
            }

            cur_key = next_key;
            has_cur_key = true;
        }
        sleep(1);
    }
    kernel_and_user_map_bpf__destroy(skel);
    printf("Exiting program\n");
    return 0;

}
