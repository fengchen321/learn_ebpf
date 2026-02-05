// Traffic Control
// https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/tc.bpf.c

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define ETH_P_IP  0x0800
#define PROTOCOL_ICMP 1

char __license[] SEC("license") = "GPL";

SEC("tc")
int tc_ingress_filter(struct __sk_buff *ctx)
{
    // 1. get packet data address
	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
    
    // 2. get ethernet header and ip header
	struct ethhdr *l2;
	struct iphdr *l3;

	if (ctx->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	l2 = data;
	if ((void *)(l2 + 1) > data_end)
		return TC_ACT_OK;

	l3 = (struct iphdr *)(l2 + 1);
	if ((void *)(l3 + 1) > data_end)
		return TC_ACT_OK;
    
    if (l3->protocol == PROTOCOL_ICMP) {
        u32 src_addr = l3->saddr;
        u32 dst_addr = l3->daddr;

        bpf_printk("TC Ingress: Dropping ICMP packet: %pI4 -> %pI4\n",
				   &src_addr, &dst_addr);
        return TC_ACT_SHOT;
    }
	bpf_printk("Got IP packet: tot_len: %d, ttl: %d", bpf_ntohs(l3->tot_len), l3->ttl);
	return TC_ACT_OK;
}