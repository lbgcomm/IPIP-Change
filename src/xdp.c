#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <stdatomic.h>

#include <linux/bpf.h>
#include <linux/bpf_common.h>

#include <bpf_helpers.h>

#include "xdp.h"
#include "csum.h"

//#define DEBUG

#ifdef DEBUG
#define bpf_printk(fmt, ...)					\
({								\
	       char ____fmt[] = fmt;				\
	       bpf_trace_printk(____fmt, sizeof(____fmt),	\
				##__VA_ARGS__);			\
})
#endif

SEC("xdp_prog")
int xdp_prog_main(struct xdp_md *ctx)
{
    // Initialize data.
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Scan ethernet header.
    struct ethhdr *eth = data;

    // Check if the ethernet header is valid.
    if (eth + 1 > (struct ethhdr *)data_end)
    {
        return XDP_DROP;
    }

    // Check Ethernet protocol.
    if (unlikely(eth->h_proto != htons(ETH_P_IP)))
    {
        return XDP_PASS;
    }

    // Initialize (outer) IP header.
    struct iphdr *oiph = data + sizeof(struct ethhdr);

    if (unlikely(oiph + 1 > (struct iphdr *)data_end))
    {
        return XDP_DROP;
    }

    // If the IP protocol isn't IPIP, pass along.
    if (oiph->protocol != IPPROTO_IPIP)
    {
        return XDP_PASS;
    }

    // Initialize (inner) IP header.
    struct iphdr *iph = data + sizeof(struct ethhdr) + (oiph->ihl * 4);

    if (unlikely(iph + 1 > (struct iphdr *)data_end))
    {
        return XDP_DROP;
    }

#ifdef REPLACE_SOURCE_REMOTE
    // Replace the outer IP header's source address with this.
    __be32 oldremote = oiph->saddr;

    #ifdef REPLACE_SOURCE_WITH_INNER
    oiph->saddr = iph->daddr;
    #else
    oiph->saddr = REPLACE_SOURCE_REMOTE;
    #endif

#ifdef DEBUG
    bpf_printk("[TC_MAPPER] Replacing source IP %lu with %lu.\n", oldremote, oiph->saddr);
#endif    

    oiph->check = csum_diff4(oldremote, oiph->saddr, oiph->check);
#endif

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";