// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} sockets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __be32);
} local_address SEC(".maps");

SEC("xdp")
int xsk_ingress(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip = (void *)(eth + 1);
    __u32 key = 0;
    __be32 *address;

    if (ctx->rx_queue_index != 0 || (void *)(ip + 1) > end ||
        eth->h_proto != __builtin_bswap16(ETH_P_IP) || ip->version != 4)
        return XDP_PASS;
    address = bpf_map_lookup_elem(&local_address, &key);
    if (!address || ip->daddr != *address)
        return XDP_PASS;
    return bpf_redirect_map(&sockets, key, XDP_PASS);
}

char LICENSE[] SEC("license") = "GPL";
