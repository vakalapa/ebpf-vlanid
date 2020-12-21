#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include "linux/bpf_endian.h"
#include "linux/if_vlan.h"

#define SEC(NAME) __attribute__((section(NAME), used))
#define OFFSET_BASE_ETH sizeof(struct ethhdr)

static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
    (void *)BPF_FUNC_trace_printk;
static int (*bpf_skb_load_bytes)(void *ctx, int off, void *to, int len) = (void *)BPF_FUNC_skb_load_bytes;
static int (*bpf_skb_vlan_push)(void *ctx, __be16 vlan_proto, __u16 vlan_tci) =
    (void *)BPF_FUNC_skb_vlan_push;
static int (*bpf_skb_vlan_pop)(void *ctx) =
    (void *)BPF_FUNC_skb_vlan_pop;
static int (*bpf_redirect)(int ifindex, int flags) =
    (void *)BPF_FUNC_redirect;
static int (*bpf_skb_store_bytes)(void *ctx, int off, void *from, int len, int flags) =
    (void *)BPF_FUNC_skb_store_bytes;

// avoid using htons for l2 proto comparison
#define ETH_P_IPN 8
//#define ETH_P_IPV6 56710    /* IPv6 over bluebook	56710	*/
#define ETH_P_ARP 0x0806      /* Address Resolution packet	*/
#define ETH_P_RARP 0x8035     /* Reverse Addr Res packet	*/
#define ETH_P_8021Q 0x8100    /* 802.1Q VLAN Extended Header  */
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

    __u8 ns1_mac[ETH_ALEN] = {0x14, 0xec, 0xd4, 0x01, 0xf1, 0x2b};
    __u8 ns2_mac[ETH_ALEN] = {0x84, 0x12, 0x5d, 0x2f, 0xd2, 0x4c};
    /*// check vlan id
    uint16_t vlan_id = skb->vlan_tci & 0x0fff;

    if (vlan_id == 0)
    {
        char msg[] = "Hello, BPF World! received a pkt  %x\n ";
        bpf_trace_printk(msg, sizeof(msg), skb->vlan_present);
    }*/
    struct ethhdr *eth_hdr = data;
    char msgn[] = "Hello, egress Packet info: proto %d if: %d\n";
    bpf_trace_printk(msgn, sizeof(msgn), eth_hdr->h_proto, skb->ifindex);
    if (eth_hdr->h_proto != ETH_P_IPN)
        return TC_ACT_OK;

    char msgnn[] = "After the check Packet info: proto %d\n";
    bpf_trace_printk(msgnn, sizeof(msgnn), eth_hdr->h_proto);

    int newif = 14;
    if (skb->ifindex == 14)
    {
        newif = 12;
        bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), ns1_mac, ETH_ALEN, 0);
    }
    else
    {
        bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), ns2_mac, ETH_ALEN, 0);
    }

    bpf_skb_vlan_push(skb, (ETH_P_8021Q), 2);
    return bpf_redirect(newif, 0);
}

SEC("ingress")
static inline int ingress_pod_vlan(struct __sk_buff *skb)
{

    //data limits
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    if (data_end < (data + OFFSET_BASE_ETH + (2 * sizeof(__u16))))
        return TC_ACT_OK;
    struct ethhdr *eth_hdr = data;

    __u8 ns1_mac[ETH_ALEN] = {0x14, 0xec, 0xd4, 0x01, 0xf1, 0x2b};
    __u8 ns2_mac[ETH_ALEN] = {0x84, 0x12, 0x5d, 0x2f, 0xd2, 0x4c};
    char msgn[] = "Hello, iingress Packet info: proto %d if: %d\n";
    bpf_trace_printk(msgn, sizeof(msgn), eth_hdr->h_proto, skb->ifindex);

    if (eth_hdr->h_proto != ETH_P_IPN)
        return TC_ACT_OK;

    /*// check vlan id*/
    uint16_t vlan_id = skb->vlan_tci & 0x0fff;

    if (vlan_id != 2)
    {
        char msg[] = "Hello, received a pkt ingress with invalid vlan  %d\n ";
        bpf_trace_printk(msg, sizeof(msg), skb->vlan_tci);
        return TC_ACT_OK;
    }

    int newif = 14;
    if (skb->ifindex == 14)
    {
        newif = 12;
        bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), ns1_mac, ETH_ALEN, 0);
    }
    else
    {
        bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), ns2_mac, ETH_ALEN, 0);
    }
    char msgnn[] = "Hello, before removing vlan : proto %d vlan:%d \n";
    bpf_trace_printk(msgnn, sizeof(msgnn), eth_hdr->h_proto, skb->vlan_tci);
    bpf_skb_vlan_pop(skb);

    char msgm[] = "Final check in ingress after vlan removal present %d vlan:%d \n";
    bpf_trace_printk(msgm, sizeof(msgm), skb->vlan_present, skb->vlan_tci);

    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
