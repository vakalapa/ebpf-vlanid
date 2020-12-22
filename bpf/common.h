#include <uapi/linux/ip.h>

#define skb_vlan_tag_present(__skb) ((__skb)->vlan_present)

/**
 * skb_vlan_tagged - check if skb is vlan tagged.
 * @skb: skbuff to query
 *
 * Returns true if the skb is tagged, regardless of whether it is hardware
 * accelerated or not.
 */
static inline bool skb_vlan_tagged(const struct sk_buff *skb)
{
    if (!skb_vlan_tag_present(skb) &&
        likely(!eth_type_vlan(skb->protocol)))
        return false;

    return true;
}

/**
 * eth_type_vlan - check for valid vlan ether type.
 * @ethertype: ether type to check
 *
 * Returns true if the ether type is a vlan ether type.
 */
static inline bool eth_type_vlan(__be16 ethertype)
{
    switch (ethertype)
    {
    case htons(ETH_P_8021Q):
    case htons(ETH_P_8021AD):
        return true;
    default:
        return false;
    }
}