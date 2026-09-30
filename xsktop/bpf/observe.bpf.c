// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct ns_common { __u32 inum; } __attribute__((preserve_access_index));
struct net { struct ns_common ns; } __attribute__((preserve_access_index));
typedef struct { struct net *net; } possible_net_t;
struct net_device {
    int ifindex;
    possible_net_t nd_net;
} __attribute__((preserve_access_index));
struct xdp_buff {
    void *data;
    void *data_end;
    __u32 flags;
} __attribute__((preserve_access_index));
struct xdp_desc { __u64 addr; __u32 len; __u32 options; };
struct xsk_buff_pool {
    struct net_device *netdev;
    __u16 queue_id;
    struct xdp_desc *tx_descs;
} __attribute__((preserve_access_index));
struct xdp_sock {
    struct net_device *dev;
    struct xsk_buff_pool *pool;
    __u16 queue_id;
} __attribute__((preserve_access_index));
struct sock;
struct sk_buff { __u32 len; } __attribute__((preserve_access_index));

struct key { __u32 ifindex; __u32 queue; };
struct counters {
    __u64 rx_packets;
    __u64 rx_bytes;
    __u64 tx_packets;
    __u64 tx_bytes;
    __u64 rx_frag_packets;
    __u64 tx_unmeasured_packets;
};
struct generic_context { struct key key; };
struct rx_context { struct key key; __u64 bytes; __u32 frags; };

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct key);
    __type(value, struct counters);
} traffic SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target_netns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct generic_context);
} generic_contexts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rx_context);
} rx_contexts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u32);
} generic_packets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u8);
} batch_contexts SEC(".maps");

static __always_inline struct counters *counter(struct key *key) {
    struct counters zero = {};
    struct counters *value = bpf_map_lookup_elem(&traffic, key);
    if (value) return value;
    bpf_map_update_elem(&traffic, key, &zero, BPF_NOEXIST);
    return bpf_map_lookup_elem(&traffic, key);
}

static __always_inline bool in_target_netns(struct net_device *dev) {
    __u32 zero = 0;
    __u32 *target = bpf_map_lookup_elem(&target_netns, &zero);
    if (!target || !dev) return false;
    struct net *net = BPF_CORE_READ(dev, nd_net.net);
    if (!net) return false;
    return BPF_CORE_READ(net, ns.inum) == *target;
}

static __always_inline struct key socket_key(struct xdp_sock *xs) {
    struct net_device *dev = BPF_CORE_READ(xs, dev);
    struct key key = { .queue = BPF_CORE_READ(xs, queue_id) };
    if (in_target_netns(dev)) key.ifindex = BPF_CORE_READ(dev, ifindex);
    return key;
}

static __always_inline struct key pool_key(struct xsk_buff_pool *pool) {
    struct net_device *dev = BPF_CORE_READ(pool, netdev);
    struct key key = { .queue = BPF_CORE_READ(pool, queue_id) };
    if (in_target_netns(dev)) key.ifindex = BPF_CORE_READ(dev, ifindex);
    return key;
}

static __always_inline void rx_start(struct xdp_sock *xs, struct xdp_buff *xdp) {
    if (!xs || !xdp) return;
    struct key key = socket_key(xs);
    if (!key.ifindex) return;
    void *data = BPF_CORE_READ(xdp, data);
    void *end = BPF_CORE_READ(xdp, data_end);
    __u64 len = (__u64)end - (__u64)data;
    if (len > 65535) return;
    __u32 zero = 0;
    struct rx_context *sample = bpf_map_lookup_elem(&rx_contexts, &zero);
    if (!sample) return;
    sample->key = key;
    sample->bytes = len;
    sample->frags = BPF_CORE_READ(xdp, flags) & 1;
}

static __always_inline void rx_end(int result) {
    __u32 zero = 0;
    struct rx_context *sample = bpf_map_lookup_elem(&rx_contexts, &zero);
    if (!sample) return;
    if (!result && sample->key.ifindex) {
        struct counters *value = counter(&sample->key);
        if (value) {
            value->rx_packets++;
            value->rx_bytes += sample->bytes;
            if (sample->frags)
                value->rx_frag_packets++;
        }
    }
    sample->key.ifindex = 0;
}

SEC("fentry/__xsk_map_redirect")
int BPF_PROG(native_rx_start, struct xdp_sock *xs, struct xdp_buff *xdp) {
    rx_start(xs, xdp);
    return 0;
}

SEC("fexit/__xsk_map_redirect")
int BPF_PROG(native_rx, struct xdp_sock *xs, struct xdp_buff *xdp, int result) {
    rx_end(result);
    return 0;
}

SEC("fentry/xsk_generic_rcv")
int BPF_PROG(generic_rx_start, struct xdp_sock *xs, struct xdp_buff *xdp) {
    rx_start(xs, xdp);
    return 0;
}

SEC("fexit/xsk_generic_rcv")
int BPF_PROG(generic_rx, struct xdp_sock *xs, struct xdp_buff *xdp, int result) {
    rx_end(result);
    return 0;
}

SEC("fexit/xsk_tx_peek_desc")
int BPF_PROG(native_tx_single, struct xsk_buff_pool *pool, struct xdp_desc *desc, bool ok) {
    if (!ok || !pool || !desc) return 0;
    __u64 task = bpf_get_current_pid_tgid();
    if (bpf_map_lookup_elem(&batch_contexts, &task)) return 0;
    struct key key = pool_key(pool);
    if (!key.ifindex) return 0;
    struct counters *value = counter(&key);
    if (!value) return 0;
    struct xdp_desc item = {};
    if (bpf_probe_read_kernel(&item, sizeof(item), desc)) return 0;
    if (!(item.options & 1))
        value->tx_packets++;
    value->tx_bytes += item.len;
    return 0;
}

SEC("fentry/xsk_tx_peek_release_desc_batch")
int BPF_PROG(native_tx_batch_start, struct xsk_buff_pool *pool, __u32 requested) {
    /* The batch fallback calls xsk_tx_peek_desc; count it only at batch exit. */
    __u64 task = bpf_get_current_pid_tgid();
    __u8 active = 1;
    bpf_map_update_elem(&batch_contexts, &task, &active, BPF_ANY);
    return 0;
}

SEC("fexit/xsk_tx_peek_release_desc_batch")
int BPF_PROG(native_tx_batch, struct xsk_buff_pool *pool, __u32 requested, __u32 count) {
    __u64 task = bpf_get_current_pid_tgid();
    __u8 *active = bpf_map_lookup_elem(&batch_contexts, &task);
    if (!active) return 0;
    bpf_map_delete_elem(&batch_contexts, &task);
    if (!count || !pool) return 0;
    struct key key = pool_key(pool);
    if (!key.ifindex) return 0;
    struct counters *value = counter(&key);
    if (!value) return 0;
    struct xdp_desc *descs = BPF_CORE_READ(pool, tx_descs);
    __u64 bytes = 0;
    __u64 packets = 0;
    __u32 limit = count < 64 ? count : 64;
    __u32 measured = 0;
    for (__u32 i = 0; i < 64; i++) {
        if (i >= limit) break;
        struct xdp_desc item = {};
        if (bpf_probe_read_kernel(&item, sizeof(item), &descs[i])) break;
        bytes += item.len;
        if (!(item.options & 1)) packets++;
        measured++;
    }
    value->tx_packets += packets;
    value->tx_bytes += bytes;
    if (count > measured)
        value->tx_unmeasured_packets += count - measured;
    return 0;
}

SEC("fentry/__xsk_generic_xmit")
int BPF_PROG(generic_tx_start, struct sock *sk) {
    struct xdp_sock *xs = (struct xdp_sock *)sk;
    struct generic_context source = { .key = socket_key(xs) };
    if (source.key.ifindex) {
        __u64 task = bpf_get_current_pid_tgid();
        bpf_map_update_elem(&generic_contexts, &task, &source, BPF_ANY);
    }
    return 0;
}

SEC("fentry/__dev_direct_xmit")
int BPF_PROG(generic_tx_packet_start, struct sk_buff *skb, __u16 queue) {
    __u64 task = bpf_get_current_pid_tgid();
    if (!bpf_map_lookup_elem(&generic_contexts, &task) || !skb) return 0;
    __u32 len = BPF_CORE_READ(skb, len);
    bpf_map_update_elem(&generic_packets, &task, &len, BPF_ANY);
    return 0;
}

SEC("fexit/__dev_direct_xmit")
int BPF_PROG(generic_tx_sent, struct sk_buff *skb, __u16 queue, int result) {
    __u64 task = bpf_get_current_pid_tgid();
    __u32 *len = bpf_map_lookup_elem(&generic_packets, &task);
    struct generic_context *source = bpf_map_lookup_elem(&generic_contexts, &task);
    /* NET_XMIT_CN can still mean that the frame was accepted. */
    if (len && source && result != 1 && result != 0x10) {
        struct counters *value = counter(&source->key);
        if (value) {
            value->tx_packets++;
            value->tx_bytes += *len;
        }
    }
    bpf_map_delete_elem(&generic_packets, &task);
    return 0;
}

SEC("fexit/__xsk_generic_xmit")
int BPF_PROG(generic_tx_end, struct sock *sk, int result) {
    __u64 task = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&generic_contexts, &task);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
