#include <stdint.h>
#include <stddef.h>
#include <linux/bpf.h>

#define SEC(NAME) __attribute__((section(NAME), used))

static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
    (void *)BPF_FUNC_trace_printk;

SEC("egress")
static inline int egress_pod_vlan(struct __sk_buff *skb)
{
    uint16_t vlan_id = skb->vlan_tci & 0x0fff;
    if (vlan_id == 0)
    {
        char msg[] = "Hello, BPF World! received a pkt";
        bpf_trace_printk(msg, sizeof(msg));
    }

    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
