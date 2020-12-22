# ebpf-vlanid


Using https: //github.com/torvalds/linux/blob/master/include/linux/if_vlan.h

Helper functions needed:

static inline int vlan_get_tag(const struct sk_buff *skb, u16 *vlan_tci)
static inline bool skb_vlan_tagged(const struct sk_buff *skb)


/**
 * vlan_put_tag - inserts VLAN tag according to device features
 * @skb: skbuff to tag
 * @vlan_tci: VLAN TCI to insert
 *
 * Assumes skb->dev is the target that will xmit this frame.
 * Returns a VLAN tagged skb.
 */
 static inline struct sk_buff *vlan_put_tag(struct sk_buff *skb, u16 vlan_tci)
 {
     if (skb->dev->features & NETIF_F_HW_VLAN_TX) {
         return __vlan_hwaccel_put_tag(skb, vlan_tci);
    } else {
         return __vlan_put_tag(skb, vlan_tci);
    }
}