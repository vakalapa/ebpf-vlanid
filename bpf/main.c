#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include "linux/bpf_endian.h"

#define SEC(NAME) __attribute__((section(NAME), used))
#define OFFSET_BASE_ETH sizeof(struct ethhdr)

static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
    (void *)BPF_FUNC_trace_printk;
static int (*bpf_skb_load_bytes)(void *ctx, int off, void *to, int len) = (void *)BPF_FUNC_skb_load_bytes;
static int (*bpf_skb_vlan_push)(void *ctx, __be16 vlan_proto, __u16 vlan_tci) =
    (void *)BPF_FUNC_skb_vlan_push;
static int (*bpf_skb_vlan_pop)(void *ctx) =
    (void *)BPF_FUNC_skb_vlan_pop;

// avoid using htons for l2 proto comparison
//#define ETH_P_IP 8
#define ETH_P_IPV6 56710    /* IPv6 over bluebook	56710	*/
#define ETH_P_ARP 0x0806    /* Address Resolution packet	*/
#define ETH_P_RARP 0x8035   /* Reverse Addr Res packet	*/
#define ETH_P_8021Q 0x8100  /* 802.1Q VLAN Extended Header  */
#define ETH_P_8021AD 0x88A8 /* 802.1ad Service VLAN		*/
/* linux/if_vlan.h have not exposed this as UAPI, thus mirror some here
 *
 *	struct vlan_hdr - vlan header
 *	@h_vlan_TCI: priority and VLAN ID
 *	@h_vlan_encapsulated_proto: packet type ID or len
 */
struct _vlan_hdr
{
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

#define VLAN_PRIO_MASK 0xe000 /* Priority Code Point */
#define VLAN_PRIO_SHIFT 13
#define VLAN_CFI_MASK 0x1000 /* Canonical Format Indicator */
#define VLAN_TAG_PRESENT VLAN_CFI_MASK
#define VLAN_VID_MASK 0x0fff /* VLAN Identifier */
#define VLAN_N_VID 4096

SEC("egress")
static inline int egress_pod_vlan(struct __sk_buff *skb)
{
    /*
    TODO list:

    1. Add suppress ARP req and reply dummy packets
    2. Add support for ICMP proto 1544 



    */

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
    bpf_trace_printk(msgn, sizeof(msgn), eth_hdr->h_proto);
    if (eth_hdr->h_proto != ETH_P_IP)
        return TC_ACT_OK;

    char msgnn[] = "After the check Packet info: proto %d\n";
    bpf_trace_printk(msgnn, sizeof(msgnn), eth_hdr->h_proto);
    bpf_skb_vlan_push(skb, bpf_htons(ETH_P_8021Q), 2);
    return TC_ACT_OK;
}

SEC("ingress")
static inline int ingress_pod_vlan(struct __sk_buff *skb)
{

    //data limits
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    if (data_end < (data + OFFSET_BASE_ETH + sizeof(_vlan_hdr)))
        return TC_ACT_OK;
    struct ethhdr *eth_hdr = data;

    char msgn[] = "Hello, Packet info: proto %d\n";
    bpf_trace_printk(msgn, sizeof(msgn), eth_hdr->h_proto);
    if (eth_hdr->h_proto != ETH_P_IP)
        return TC_ACT_OK;

    /*// check vlan id*/
    uint16_t vlan_id = skb->vlan_tci & 0x0fff;

    if (vlan_id != 2)
    {
        char msg[] = "Hello, received a pkt ingress with invalid vlan  %d\n ";
        bpf_trace_printk(msg, sizeof(msg), vlan_id);
        return TC_ACT_SHOT;
    }
    char msgn[] = "Hello, Packet info: proto %d\n";
    bpf_trace_printk(msgn, sizeof(msgn), eth_hdr->h_proto);
    if (eth_hdr->h_proto != htons(ETH_P_8021Q))
        return TC_ACT_OK;
    bpf_skb_vlan_pop(skb);
    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
