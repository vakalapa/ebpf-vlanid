#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>

#define SEC(NAME) __attribute__((section(NAME), used))
#define OFFSET_BASE_ETH sizeof(struct ethhdr)

static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
    (void *)BPF_FUNC_trace_printk;
static int (*bpf_skb_load_bytes)(void *ctx, int off, void *to, int len) = (void *)BPF_FUNC_skb_load_bytes;

SEC("egress")
static inline int egress_pod_vlan(struct __sk_buff *skb)
{
    uint16_t vlan_id = skb->vlan_tci & 0x0fff;
    if (skb->data_end < (skb->data + OFFSET_BASE_ETH))
        return -1;
    if (vlan_id == 0)
    {
        char msg[] = "Hello, BPF World! received a pkt  %x\n ";
        bpf_trace_printk(msg, sizeof(msg), skb->vlan_present);
    }

    struct ethhdr *eth_hdr = NULL;

    bpf_skb_load_bytes(skb, 0, eth_hdr, sizeof(struct ethhdr));
    char msg[] = "Hello, Packet info: smac %s dmac %s proto %x\n ";
    bpf_trace_printk(msg, sizeof(msg), eth_hdr->h_source, eth_hdr->h_dest, eth_hdr->h_proto);
    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
