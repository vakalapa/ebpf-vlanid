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

// avoid using htons for l2 proto comparison
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD /* IPv6 over bluebook	56710	*/
#define ETH_P_ARP 0x0806  /* Address Resolution packet	*/
#define ETH_P_RARP 0x8035 /* Reverse Addr Res packet	*/

SEC("egress")
static inline int egress_pod_vlan(struct __sk_buff *skb)
{

    //data limits
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    if (data_end < (data + OFFSET_BASE_ETH))
        return TC_ACT_OK;

    /*// check vlan id
    uint16_t vlan_id = skb->vlan_tci & 0x0fff;

    if (vlan_id == 0)
    {
        char msg[] = "Hello, BPF World! received a pkt  %x\n ";
        bpf_trace_printk(msg, sizeof(msg), skb->vlan_present);
    }*/

    struct ethhdr *eth_hdr = data;
    char msgn[] = "Hello, Packet info: proto %d\n";
    if (bpf_ntohs(eth_hdr->h_proto) != ETH_P_IP)
        return TC_ACT_OK;
    bpf_trace_printk(msgn, sizeof(msgn), eth_hdr->h_proto);
    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
