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

    __u32 next_key;
    bool hsa_next = false;

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
    }

    printf("BPF program loaded and attached. Press Ctrl+C to exit.\n");

    while (running) {
        next_key = 0;
        hsa_next = true;
        while (hsa_next) {
            int map_fd = bpf_map__fd(skel->maps.process_map);
            err = bpf_map_get_next_key(map_fd, &next_key, &next_key);
            if (err) {
                if (errno == ENOENT) {
                    hsa_next = false;
                    continue;
                } else {
                    fprintf(stderr, "Error getting next key: %s\n", strerror(errno));
                }
            }   
            struct process_info info;
            err = bpf_map_lookup_elem(map_fd, &next_key, &info);
            if (err) {
                fprintf(stderr, "Error looking up process info: %s\n", strerror(errno));
            }
            printf("PID: %d, Name: %s\n", info.pid, info.comm);
        }
        sleep(1);
    }
    kernel_and_user_map_bpf__destroy(skel);
    printf("Exiting program\n");
    return 0;

}