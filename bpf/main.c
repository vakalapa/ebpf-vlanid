#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_vlan.h>
#include <linux/bpf.h>

#define SEC(NAME) __attribute__((section(NAME), used))

static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
    (void *)BPF_FUNC_trace_printk;

SEC("egress")
static inline int egress_pod_vlan(struct __sk_buff *skb)
{
    if (!skb_vlan_tagged(skb))
    {
        char msg[] = "Hello, BPF World! received a pkt";
        bpf_trace_printk(msg, sizeof(msg));
    }
}

char __license[] SEC("license") = "GPL";