// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct ns_common { __u32 inum; } __attribute__((preserve_access_index));
struct net { struct ns_common ns; } __attribute__((preserve_access_index));
typedef struct { struct net *net; } possible_net_t;
struct net_device {
    int ifindex;
    possible_net_t nd_net;
} __attribute__((preserve_access_index));
struct napi_struct {
    struct net_device *dev;
    unsigned int napi_id;
} __attribute__((preserve_access_index));

struct key {
    __u32 ifindex;
    __u32 netns;
    __u32 napi_id;
    __u32 cpu;
};
struct counters {
    __u64 polls;
    __u64 work;
    __u64 budget_hits;
    __u64 duration_ns;
    __u64 timed_polls;
    __u64 latency_us[16];
};
struct start {
    __u64 napi;
    __u64 time_ns;
};
struct filter {
    __u32 netns;
    __u32 ifindex;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct key);
    __type(value, struct counters);
} stats SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct start);
} starts SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct filter);
} scope SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} errors SEC(".maps");

static __always_inline void error(__u32 index) {
    __u64 *value = bpf_map_lookup_elem(&errors, &index);
    if (value) (*value)++;
}

SEC("fentry/__napi_poll")
int BPF_PROG(on_enter, struct napi_struct *napi) {
    __u32 zero = 0;
    struct start *start = bpf_map_lookup_elem(&starts, &zero);
    if (start) {
        start->napi = (__u64)napi;
        start->time_ns = bpf_ktime_get_ns();
    }
    return 0;
}

SEC("raw_tp/napi_poll")
int on_poll(struct bpf_raw_tracepoint_args *ctx) {
    struct napi_struct *napi = (void *)ctx->args[0];
    if (!napi) return 0;
    struct net_device *dev = BPF_CORE_READ(napi, dev);
    if (!dev) return 0;
    struct net *net = BPF_CORE_READ(dev, nd_net.net);
    if (!net) return 0;
    struct key key = {
        .ifindex = BPF_CORE_READ(dev, ifindex),
        .netns = BPF_CORE_READ(net, ns.inum),
        .napi_id = BPF_CORE_READ(napi, napi_id),
        .cpu = bpf_get_smp_processor_id(),
    };
    __u32 zero = 0;
    struct filter *filter = bpf_map_lookup_elem(&scope, &zero);
    if (!filter || key.netns != filter->netns ||
        (filter->ifindex && key.ifindex != filter->ifindex)) return 0;

    struct counters *value = bpf_map_lookup_elem(&stats, &key);
    if (!value) {
        struct counters empty = {};
        if (bpf_map_update_elem(&stats, &key, &empty, BPF_NOEXIST) &&
            !bpf_map_lookup_elem(&stats, &key)) {
            error(0);
            return 0;
        }
        value = bpf_map_lookup_elem(&stats, &key);
        if (!value) { error(0); return 0; }
    }
    __u32 work = (__u32)ctx->args[1];
    __u32 budget = (__u32)ctx->args[2];
    __sync_fetch_and_add(&value->polls, 1);
    __sync_fetch_and_add(&value->work, work);
    if (budget && work >= budget)
        __sync_fetch_and_add(&value->budget_hits, 1);

    struct start *start = bpf_map_lookup_elem(&starts, &zero);
    if (!start || start->napi != (__u64)napi) {
        error(1);
        return 0;
    }
    __u64 elapsed = bpf_ktime_get_ns() - start->time_ns;
    start->napi = 0;
    __sync_fetch_and_add(&value->duration_ns, elapsed);
    __sync_fetch_and_add(&value->timed_polls, 1);
    __u64 us = (elapsed + 999) / 1000;
    __u32 bucket = 0;
#pragma unroll
    for (int i = 0; i < 15; i++) {
        if (us > (1ULL << i)) bucket = i + 1;
    }
    __sync_fetch_and_add(&value->latency_us[bucket], 1);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
