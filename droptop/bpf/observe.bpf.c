// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

struct ns_common { __u32 inum; } __attribute__((preserve_access_index));
struct net { struct ns_common ns; } __attribute__((preserve_access_index));
typedef struct { struct net *net; } possible_net_t;
struct net_device {
    int ifindex;
    possible_net_t nd_net;
} __attribute__((preserve_access_index));
struct inode { unsigned long i_ino; } __attribute__((preserve_access_index));
struct file { struct inode *f_inode; } __attribute__((preserve_access_index));
struct socket { struct file *file; } __attribute__((preserve_access_index));
struct sock_common { __u8 skc_state; } __attribute__((preserve_access_index));
struct sock {
    struct sock_common __sk_common;
    struct socket *sk_socket;
} __attribute__((preserve_access_index));
struct sk_buff {
    struct net_device *dev;
    struct sock *sk;
    __u16 protocol;
    int skb_iif;
    __u32 len;
    unsigned char *head;
    __u32 tail;
    __u16 network_header;
} __attribute__((preserve_access_index));

struct drop_key {
    __u64 location;
    __u32 reason;
    __u32 ifindex;
    __u32 netns;
    __u16 protocol;
    __u16 pad;
};

struct focus {
    __u64 location;
    __u32 reason;
    __u32 ifindex;
    __u32 netns;
    __u32 mask;
    __u32 generation;
    __u32 pad;
};

struct skb_event {
    __u64 timestamp_ns;
    __u64 location;
    __u32 reason;
    __u32 ifindex;
    __u32 ingress_ifindex;
    __u32 netns;
    __u32 length;
    __u32 generation;
    __u8 family;
    __u8 l4_protocol;
    __u8 status;
    __u8 pad;
    __u16 source_port;
    __u16 dest_port;
    __u8 source[16];
    __u8 dest[16];
    __u64 socket_inode;
    __u32 cpu;
    __u32 reserved;
};

_Static_assert(sizeof(struct skb_event) == 96, "skb event layout");

struct sample_budget {
    __u64 second;
    __u32 used;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct drop_key);
    __type(value, __u64);
} drops SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct focus);
} selected SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 2048);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, 127 * sizeof(__u64));
} stacks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 2048);
    __type(key, __u32);
    __type(value, __u64);
} stack_counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u64);
} errors SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct focus);
} interface_filter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} samples SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct sample_budget);
} budget SEC(".maps");

static __always_inline void error(__u32 index) {
    __u64 *value = bpf_map_lookup_elem(&errors, &index);
    if (value) (*value)++;
}

static __always_inline void read_tuple(struct sk_buff *skb, __u16 ethertype,
                                       struct skb_event *event) {
    unsigned char *head = BPF_CORE_READ(skb, head);
    __u32 tail = BPF_CORE_READ(skb, tail);
    __u32 offset = BPF_CORE_READ(skb, network_header);
    if (!head || offset >= tail || offset > 65535 || tail - offset < 20) {
        event->status = 1; /* No readable network header in the linear area. */
        return;
    }
    __u32 l4_offset;
    if (ethertype == 0x0800) {
        __u8 ip[20];
        if (bpf_probe_read_kernel(ip, sizeof(ip), head + offset)) {
            event->status = 2;
            return;
        }
        if ((ip[0] >> 4) != 4 || (ip[0] & 15) < 5) {
            event->status = 2;
            return;
        }
        event->family = 4;
        event->l4_protocol = ip[9];
        __builtin_memcpy(event->source, &ip[12], 4);
        __builtin_memcpy(event->dest, &ip[16], 4);
        l4_offset = offset + (ip[0] & 15) * 4;
        if (((ip[6] & 0x1f) << 8) | ip[7]) {
            event->status = 3;
            return;
        }
    } else if (ethertype == 0x86dd) {
        __u8 ip6[40];
        if (tail - offset < sizeof(ip6) ||
            bpf_probe_read_kernel(ip6, sizeof(ip6), head + offset)) {
            event->status = 2;
            return;
        }
        if ((ip6[0] >> 4) != 6) {
            event->status = 2;
            return;
        }
        event->family = 6;
        event->l4_protocol = ip6[6];
        __builtin_memcpy(event->source, &ip6[8], 16);
        __builtin_memcpy(event->dest, &ip6[24], 16);
        l4_offset = offset + 40;
        if (ip6[6] == 0 || ip6[6] == 43 || ip6[6] == 44 ||
            ip6[6] == 50 || ip6[6] == 51 || ip6[6] == 60) {
            event->status = 4; /* Extension header: do not guess ports. */
            return;
        }
    } else {
        event->status = 5;
        return;
    }
    if (event->l4_protocol != 6 && event->l4_protocol != 17) {
        event->status = 6; /* IP header only; protocol has no TCP/UDP ports. */
        return;
    }
    if (l4_offset >= tail || tail - l4_offset < 4) {
        event->status = 2;
        return;
    }
    __u8 ports[4];
    if (bpf_probe_read_kernel(ports, sizeof(ports), head + l4_offset)) {
        event->status = 2;
        return;
    }
    event->source_port = ((__u16)ports[0] << 8) | ports[1];
    event->dest_port = ((__u16)ports[2] << 8) | ports[3];
}

static __always_inline void emit_sample(struct sk_buff *skb, struct drop_key *key,
                                        struct focus *focus, __u64 now) {
    __u32 zero = 0;
    struct sample_budget *limit = bpf_map_lookup_elem(&budget, &zero);
    if (!limit) return;
    __u64 second = now / 1000000000ULL;
    if (limit->second != second) {
        limit->second = second;
        limit->used = 0;
    }
    if (limit->used >= 4) {
        error(3);
        return;
    }
    limit->used++;
    struct skb_event *event = bpf_ringbuf_reserve(&samples, sizeof(*event), 0);
    if (!event) {
        error(4);
        return;
    }
    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = now;
    event->location = key->location;
    event->reason = key->reason;
    event->ifindex = key->ifindex;
    event->netns = key->netns;
    event->ingress_ifindex = BPF_CORE_READ(skb, skb_iif);
    event->length = BPF_CORE_READ(skb, len);
    event->generation = focus->generation;
    event->cpu = bpf_get_smp_processor_id();
    struct sock *sk = BPF_CORE_READ(skb, sk);
    if (sk) {
        __u8 state = BPF_CORE_READ(sk, __sk_common.skc_state);
        /* TIME_WAIT and request sockets do not have a full struct sock. */
        if (state != 6 && state != 12) {
            struct inode *inode = BPF_CORE_READ(sk, sk_socket, file, f_inode);
            if (inode) {
                /* i_ino is unsigned long: four bytes on ARMv7 kernels. */
                if (bpf_core_field_size(inode->i_ino) == 4) {
                    __u32 number = 0;
                    bpf_core_read(&number, sizeof(number), &inode->i_ino);
                    event->socket_inode = number;
                } else {
                    event->socket_inode = BPF_CORE_READ(inode, i_ino);
                }
            }
        }
    }
    read_tuple(skb, key->protocol, event);
    bpf_ringbuf_submit(event, 0);
}

SEC("raw_tp/kfree_skb")
int on_drop(struct bpf_raw_tracepoint_args *ctx) {
    struct sk_buff *skb = (void *)ctx->args[0];
    if (!skb) return 0;
    struct drop_key key = {
        .location = ctx->args[1],
        .reason = (__u32)ctx->args[2],
        .protocol = bpf_ntohs(BPF_CORE_READ(skb, protocol)),
    };
    struct net_device *dev = BPF_CORE_READ(skb, dev);
    if (dev) {
        key.ifindex = BPF_CORE_READ(dev, ifindex);
        struct net *net = BPF_CORE_READ(dev, nd_net.net);
        if (net) key.netns = BPF_CORE_READ(net, ns.inum);
    }
    __u32 zero = 0;
    struct focus *iface = bpf_map_lookup_elem(&interface_filter, &zero);
    if (iface && iface->mask &&
        (key.ifindex != iface->ifindex || key.netns != iface->netns)) return 0;

    __u64 *count = bpf_map_lookup_elem(&drops, &key);
    if (!count) {
        __u64 initial = 0;
        bpf_map_update_elem(&drops, &key, &initial, BPF_NOEXIST);
        count = bpf_map_lookup_elem(&drops, &key);
    }
    if (count) (*count)++;
    else error(0);

    struct focus *focus = bpf_map_lookup_elem(&selected, &zero);
    if (!focus || !focus->mask) return 0;
    if ((focus->mask & 1) && focus->reason != key.reason) return 0;
    if ((focus->mask & 2) &&
        (focus->ifindex != key.ifindex || focus->netns != key.netns)) return 0;
    if ((focus->mask & 4) && focus->location != key.location) return 0;
    int stack_id = bpf_get_stackid(ctx, &stacks, BPF_F_FAST_STACK_CMP);
    if (stack_id < 0) {
        error(1);
    } else {
        __u32 id = stack_id;
        __u64 *stack_count = bpf_map_lookup_elem(&stack_counts, &id);
        if (!stack_count) {
            __u64 initial = 0;
            bpf_map_update_elem(&stack_counts, &id, &initial, BPF_NOEXIST);
            stack_count = bpf_map_lookup_elem(&stack_counts, &id);
        }
        if (stack_count) (*stack_count)++;
        else error(2);
    }
    emit_sample(skb, &key, focus, bpf_ktime_get_ns());
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
