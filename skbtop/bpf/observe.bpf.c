// SPDX-License-Identifier: GPL-2.0
#ifdef SKBTOP_UNIT_TEST
#include "../tests/bpf_test.h"
#else
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#endif

struct ns_common { __u32 inum; } __attribute__((preserve_access_index));
struct net { struct ns_common ns; } __attribute__((preserve_access_index));
typedef struct { struct net *net; } __attribute__((preserve_access_index)) possible_net_t;
struct net_device { int ifindex; possible_net_t nd_net; unsigned long priv_flags; } __attribute__((preserve_access_index));
struct dst_entry { struct net_device *dev; } __attribute__((preserve_access_index));
struct sk_buff {
    struct sk_buff *next;
    struct net_device *dev;
    __u32 len;
    __u16 protocol;
    __u64 _skb_refdst;
    unsigned char cb[48];
} __attribute__((preserve_access_index));

#define BINS 256
#define ROUTE 1
#define BRIDGE 2
#define REPLACED 4
#define UNSUPPORTED 8
#define TIMEOUT_NS 30000000000ULL
// Use this only for decoded scalar pointers. Typed pointers use direct reads;
// libbpf relocates both their field offsets and 32-bit load widths.
#define CORE_PTR(src, field) ({ __u64 _ptr = 0; bpf_core_read(&_ptr, bpf_core_field_size((src)->field), &(src)->field); (typeof((src)->field))_ptr; })

struct path {
    __u32 kind, ingress, egress, netns;
    __u64 ingress_generation, egress_generation;
};
struct latency {
    __u64 samples, sum, min, max;
    __u64 newest_seq, newest_at, newest_ns, newest_missed_at;
    __u64 bins[BINS];
};
// Normal interval samples live in a per-CPU shard. Histogram bins use u32:
// an interval is bounded by the refresh interval and a u32 bin is sufficient
// for the supported packet rates. The lifetime fallback keeps u64 bins.
struct interval_latency {
    __u64 samples, sum, min, max, newest_at, newest_ns;
    __u32 bins[BINS];
};
struct interval_timings { struct interval_latency stages[3]; };
struct stats { __u64 counts[8]; __u64 pending; struct latency stages[3]; };
struct traffic { __u64 counts[8]; };
struct period_key { struct path path; __u64 epoch; };
struct interval_writer { __u64 depth, epoch; };
struct interval_write { struct interval_writer *writer; __u64 epoch; };
struct iface { __u64 generation; __u32 enabled, pad; __u64 device; };
struct config { __u32 netns, capacity; __u64 interval_ns, started_ns; };
// Inventory generations are unique across interfaces in this namespace.
struct tx_key { __u64 skb, birth, egress_generation; };
struct meta {
    __u64 birth, start_ns, queue_ns;
    __u64 ingress_generation, egress_generation;
    __u32 ingress, egress, input_len, flags;
    __u32 local, delivered;
};
struct tx {
    struct path path;
    __u64 start_ns, queue_ns;
    __u32 flags, input_len;
    __u32 attempting, free_seen;
};
struct attempt { struct tx_key key; __u64 dev, time_ns; __u32 length, active; };
struct attempts { __u32 depth; __u32 pad; struct attempt frames[16]; };

#define HASH(name, key_t, value_t, size) \
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(map_flags, BPF_F_NO_PREALLOC); \
    __uint(max_entries, size); __type(key, key_t); __type(value, value_t); } name SEC(".maps")
#define PERCPU_HASH(name, key_t, value_t, size) \
struct { __uint(type, BPF_MAP_TYPE_PERCPU_HASH); __uint(map_flags, BPF_F_NO_PREALLOC); \
    __uint(max_entries, size); __type(key, key_t); __type(value, value_t); } name SEC(".maps")
#define ARRAY(name, value_t, size, kind) \
struct { __uint(type, kind); __uint(max_entries, size); \
    __type(key, __u32); __type(value, value_t); } name SEC(".maps")
HASH(paths, struct path, struct stats, 4096);
PERCPU_HASH(periods, struct period_key, struct traffic, 16384);
HASH(interfaces, __u32, struct iface, 65536);
HASH(origins, __u64, struct meta, 262144);
HASH(transmits, struct tx_key, struct tx, 262144);
#ifdef SKBTOP_UNIT_TEST
ARRAY(scope, struct config, 1, BPF_MAP_TYPE_ARRAY);
#else
struct config scope SEC(".data.scope") = {};
#endif
ARRAY(empty, struct stats, 1, BPF_MAP_TYPE_PERCPU_ARRAY);
ARRAY(empty_traffic, struct traffic, 1, BPF_MAP_TYPE_PERCPU_ARRAY);
ARRAY(errors, __u64, 18, BPF_MAP_TYPE_PERCPU_ARRAY);
ARRAY(gauges, __u64, 2, BPF_MAP_TYPE_ARRAY);
ARRAY(global, struct traffic, 1, BPF_MAP_TYPE_PERCPU_ARRAY);
ARRAY(interval_writers, struct interval_writer, 1, BPF_MAP_TYPE_PERCPU_ARRAY);
ARRAY(callstack, struct attempts, 1, BPF_MAP_TYPE_PERCPU_ARRAY);
ARRAY(empty_interval_latency, struct interval_timings, 1, BPF_MAP_TYPE_PERCPU_ARRAY);
PERCPU_HASH(interval_latency, struct period_key, struct interval_timings, 16384);

static __always_inline void error(__u32 index) {
    __u64 *n = bpf_map_lookup_elem(&errors, &index);
    if (n) (*n)++;
}
static __always_inline struct config *configuration(void) {
#ifdef SKBTOP_UNIT_TEST
    __u32 zero = 0;
    return bpf_map_lookup_elem(&scope, &zero);
#else
    return &scope;
#endif
}
static __always_inline int enabled(void) {
    struct config *cfg = configuration();
    return cfg && cfg->netns && cfg->capacity;
}
static __always_inline __u64 selected_generation(__u64 address, __u32 index) {
    struct iface *value = bpf_map_lookup_elem(&interfaces, &index);
    if (!value || !value->enabled) return 0;
    if (!value->device) __sync_val_compare_and_swap(&value->device, 0, address);
    if (value->device != address) { error(11); return 0; }
    return value->generation;
}
static __always_inline __u64 device_generation(struct net_device *dev, struct config *cfg) {
    if (!dev) return 0;
    struct net *net = dev->nd_net.net;
    if (!cfg || !net || net->ns.inum != cfg->netns) return 0;
    return selected_generation((__u64)dev, dev->ifindex);
}
// A dst decoded from _skb_refdst does not carry verifier pointer provenance.
static __always_inline __u64 probed_device_generation(struct net_device *dev, struct config *cfg) {
    if (!dev) return 0;
    struct net *net = CORE_PTR(dev, nd_net.net);
    if (!cfg || !net || BPF_CORE_READ(net, ns.inum) != cfg->netns) return 0;
    return selected_generation((__u64)dev, BPF_CORE_READ(dev, ifindex));
}
SEC("fentry/unregister_netdevice_queue")
int BPF_PROG(on_unregister, struct net_device *dev) {
    if (!dev) return 0;
    struct config *cfg = configuration();
    struct net *net = dev->nd_net.net;
    if (!cfg || !cfg->netns || !net || net->ns.inum != cfg->netns) return 0;
    __u32 index = dev->ifindex;
    struct iface *iface = bpf_map_lookup_elem(&interfaces, &index);
    if (iface && (!iface->device || iface->device == (__u64)dev)) iface->enabled = 0;
    return 0;
}
static __always_inline __u64 *reserve(struct config *cfg, __u64 existing_origin) {
    __u32 zero = 0;
    __u64 *count = bpf_map_lookup_elem(&gauges, &zero);
    if (!cfg || !count) return 0;
    __u64 previous = __sync_fetch_and_add(count, 1);
    if (previous >= cfg->capacity) {
        __sync_fetch_and_sub(count, 1);
        if (existing_origin && bpf_map_lookup_elem(&origins, &existing_origin)) return 0;
        error(0);
        return 0;
    }
    return count;
}
static __always_inline void release(void) {
    __u32 zero = 0;
    __u64 *count = bpf_map_lookup_elem(&gauges, &zero);
    if (count) __sync_fetch_and_sub(count, 1);
}
static __always_inline void extremum(__u64 *value, __u64 ns, int minimum) {
    for (int i = 0; i < 32; i++) {
        __u64 old = *value;
        if ((minimum && old && old <= ns) || (!minimum && old >= ns)) return;
        if (__sync_val_compare_and_swap(value, old, ns) == old) return;
    }
    error(14);
}
static __always_inline __u32 bucket(__u64 ns) {
    if (ns < 4) return ns;
    __u32 exponent = 0;
    __u64 n = ns;
    if (n >> 32) { exponent += 32; n >>= 32; }
    if (n >> 16) { exponent += 16; n >>= 16; }
    if (n >> 8) { exponent += 8; n >>= 8; }
    if (n >> 4) { exponent += 4; n >>= 4; }
    if (n >> 2) { exponent += 2; n >>= 2; }
    if (n >> 1) exponent++;
    __u32 index = exponent * 4 + ((ns >> (exponent - 2)) & 3);
    return index < BINS ? index : BINS - 1;
}
// A bounded CAS section keeps timestamp and duration paired across CPUs.
// A nested writer must not spin waiting for the writer it interrupted.
static __always_inline void newest(struct latency *l, __u64 now, __u64 ns) {
    for (int i = 0; i < 8; i++) {
        __u64 seq = l->newest_seq;
        if (seq & 1) continue;
        if (__sync_val_compare_and_swap(&l->newest_seq, seq, seq + 1) != seq) continue;
        if (now >= l->newest_at) {
            l->newest_ns = ns;
            l->newest_at = now;
        }
        __sync_val_compare_and_swap(&l->newest_seq, seq + 1, seq + 2);
        return;
    }
    extremum(&l->newest_missed_at, now, 0);
    error(17);
}
static __always_inline void duration(struct stats *s, __u32 stage, __u64 ns, __u64 now) {
    if (stage >= 3) return;
    struct latency *l = &s->stages[stage];
    __sync_fetch_and_add(&l->samples, 1);
    __sync_fetch_and_add(&l->sum, ns);
    __u32 index = bucket(ns) & (BINS - 1);
    __sync_fetch_and_add(&l->bins[index], 1);
    extremum(&l->min, ns + 1, 1); // Zero remains an empty-value sentinel.
    extremum(&l->max, ns, 0);
    newest(l, now, ns);
}
static __always_inline struct interval_timings *period_timings(struct path *path, __u64 epoch) {
    struct period_key key = { .path = *path, .epoch = epoch };
    struct interval_timings *l = bpf_map_lookup_elem(&interval_latency, &key);
    if (!l) {
        __u32 zero = 0;
        struct interval_timings *initial = bpf_map_lookup_elem(&empty_interval_latency, &zero);
        if (initial) bpf_map_update_elem(&interval_latency, &key, initial, BPF_NOEXIST);
        l = bpf_map_lookup_elem(&interval_latency, &key);
    }
    if (!l) error(2);
    return l;
}
static __always_inline void duration_interval(struct interval_latency *l, __u64 ns, __u64 now) {
    __sync_fetch_and_add(&l->samples, 1);
    __sync_fetch_and_add(&l->sum, ns);
    __u32 index = bucket(ns) & (BINS - 1);
    __sync_fetch_and_add(&l->bins[index], 1);
    extremum(&l->min, ns + 1, 1);
    extremum(&l->max, ns, 0);
    // This map is per-CPU, so the timestamp/value pair needs no cross-CPU
    // sequence lock. A nested same-CPU invocation can only delay this update.
    if (now >= l->newest_at) {
        l->newest_ns = ns;
        l->newest_at = now;
    }
}
static __always_inline struct stats *path_stats(struct path *path) {
    struct stats *s = bpf_map_lookup_elem(&paths, path);
    if (s) return s;
    __u32 zero = 0;
    struct stats *initial = bpf_map_lookup_elem(&empty, &zero);
    if (!initial) return 0;
    bpf_map_update_elem(&paths, path, initial, BPF_NOEXIST);
    s = bpf_map_lookup_elem(&paths, path);
    return s;
}
static __always_inline struct traffic *period_stats(struct path *path, __u64 now,
        struct interval_write *write, struct config *cfg) {
    if (!cfg || !cfg->interval_ns || now < cfg->started_ns) return 0;
    __u32 zero = 0;
    write->writer = bpf_map_lookup_elem(&interval_writers, &zero);
    if (!write->writer) { error(14); return 0; }
    __u64 previous = __sync_fetch_and_add(&write->writer->depth, 1);
    // Register before reading the epoch clock. A collector that saw no writer
    // can retire old epochs safely: a subsequent writer selects a newer epoch.
    now = bpf_ktime_get_ns();
    __u64 epoch = (now - cfg->started_ns) / cfg->interval_ns;
    if (!previous) write->writer->epoch = epoch;
    write->epoch = epoch;
    struct period_key key = { .path = *path, .epoch = epoch };
    struct traffic *s = bpf_map_lookup_elem(&periods, &key);
    if (s) return s;
    struct traffic *initial = bpf_map_lookup_elem(&empty_traffic, &zero);
    if (!initial) return 0;
    bpf_map_update_elem(&periods, &key, initial, BPF_NOEXIST);
    s = bpf_map_lookup_elem(&periods, &key);
    if (!s) error(2);
    return s;
}
static __always_inline void period_done(struct interval_write *write) {
    if (write->writer) __sync_fetch_and_sub(&write->writer->depth, 1);
}
static __always_inline void increment_counts(__u64 *counts, __u32 event,
        __u32 length, __u32 flags) {
    if (event == 0) {
        __sync_fetch_and_add(&counts[0], 1);
        __sync_fetch_and_add(&counts[1], length);
    } else if (event == 1) {
        __sync_fetch_and_add(&counts[2], 1);
        __sync_fetch_and_add(&counts[3], length);
        if ((flags & 3) == 3) __sync_fetch_and_add(&counts[6], 1);
        else if (flags & BRIDGE) __sync_fetch_and_add(&counts[5], 1);
        else if (flags & ROUTE) __sync_fetch_and_add(&counts[4], 1);
    } else if (event == 2) __sync_fetch_and_add(&counts[7], 1);
}
static __always_inline void increment(struct stats *s, __u32 event, __u32 length, __u32 flags) {
    if (s) increment_counts(s->counts, event, length, flags);
}
static __always_inline void count_global(__u32 event, __u32 length, __u32 flags) {
    __u32 zero = 0;
    struct traffic *s = bpf_map_lookup_elem(&global, &zero);
    if (s) increment_counts(s->counts, event, length, flags);
}
static __always_inline void flow_resolved(struct stats *s, struct traffic *p,
        __u32 event, __u32 length, __u32 flags) {
    // Periods hold normal traffic; shared counters hold only capacity fallback.
    // Userspace merges retired and live periods for lifetime totals.
    if (p) increment_counts(p->counts, event, length, flags);
    else increment(s, event, length, flags);
}
static __always_inline void flow(struct path *key, __u64 now, __u32 event, __u32 length,
        __u32 flags, struct config *cfg) {
    struct stats *s = path_stats(key);
    if (!s) { error(1); return; }
    struct interval_write write = {};
    flow_resolved(s, period_stats(key, now, &write, cfg), event, length, flags);
    period_done(&write);
}
static __always_inline void timings_resolved(struct stats *s, struct traffic *p,
        struct path *path, struct interval_write *write, __u64 now,
        __u64 start, __u64 queue, __u64 end) {
    if (!s || end < start || (queue && (queue < start || end < queue))) {
        if (s) error(14);
        return;
    }
    // Normal completions update one interval distribution. Paths retain only
    // overflow samples, so period capacity failures do not lose lifetime data.
    struct interval_timings *l = p ? period_timings(path, write->epoch) : 0;
    if (l) duration_interval(&l->stages[2], end - start, now);
    else duration(s, 2, end - start, now);
    if (queue) {
        if (l) {
            duration_interval(&l->stages[0], queue - start, now);
            duration_interval(&l->stages[1], end - queue, now);
        } else {
            duration(s, 0, queue - start, now);
            duration(s, 1, end - queue, now);
        }
    } else {
        if (l) duration_interval(&l->stages[0], end - start, now);
        else duration(s, 0, end - start, now);
    }
}
static __always_inline void timings(struct path *key, __u64 now, __u64 start,
        __u64 queue, __u64 end, struct config *cfg) {
    struct stats *s = path_stats(key);
    if (!s) return;
    struct interval_write write = {};
    timings_resolved(s, period_stats(key, now, &write, cfg), key, &write,
        now, start, queue, end);
    period_done(&write);
}
static __always_inline void pending_resolved(struct stats *s, int add) {
    if (s) {
        if (add) __sync_fetch_and_add(&s->pending, 1);
        else __sync_fetch_and_sub(&s->pending, 1);
    }
}
static __always_inline void pending(struct path *key, int add) {
    pending_resolved(bpf_map_lookup_elem(&paths, key), add);
}
// A successful CAS owns retirement. Free, completion and GC cannot delete a
// replacement at the same skb address while another path still owns the entry.
static __always_inline int claim(__u64 *field) {
    __u64 old = *field;
    return old && __sync_val_compare_and_swap(field, old, 0) == old;
}
static int origin_expire(void *map, __u64 *key, struct meta *value, void *ctx) {
    __u64 now = *(__u64 *)ctx;
    if (now < value->start_ns || now - value->start_ns < TIMEOUT_NS || !claim(&value->birth)) return 0;
    error(5);
    bpf_map_delete_elem(map, key);
    release();
    return 0;
}
static int tx_expire(void *map, struct tx_key *key, struct tx *value, void *ctx) {
    __u64 now = *(__u64 *)ctx;
    if (now < value->start_ns || now - value->start_ns < TIMEOUT_NS || !claim(&value->start_ns)) return 0;
    pending(&value->path, 0);
    error(5);
    bpf_map_delete_elem(map, key);
    release();
    return 0;
}
SEC("socket")
int cleanup(struct __sk_buff *skb) {
    __u32 zero = 0;
    __u64 *count = bpf_map_lookup_elem(&gauges, &zero);
    // Even empty hash maps scan all buckets. A reservation precedes insertion;
    // newly admitted records after this check can wait for the next sweep.
    if (count && !*count) return 0;
    __u64 now = bpf_ktime_get_ns();
    bpf_for_each_map_elem(&origins, origin_expire, &now, 0);
    bpf_for_each_map_elem(&transmits, tx_expire, &now, 0);
    return 0;
}
static __always_inline void begin(struct sk_buff *skb, int local, __u64 now,
        struct config *cfg) {
    if (!skb || !cfg || !cfg->netns || !cfg->capacity) return;
    __u64 address = (__u64)skb;
    struct net_device *dev = skb->dev;
    __u64 generation = device_generation(dev, cfg);
    if (local && !generation) {
        __u64 address = skb->_skb_refdst & ~3ULL;
        struct dst_entry *dst = (void *)address;
        struct net_device *dst_dev = dst ? CORE_PTR(dst, dev) : 0;
        generation = probed_device_generation(dst_dev, cfg);
    }
    if (!generation) return;
    // NOEXIST deduplicates under the insertion lock. A separate lookup is only
    // needed at capacity to avoid reporting a repeated receive as an omission.
    __u64 *count = reserve(cfg, address);
    if (!count) return;
    struct meta initial = { .birth = now, .start_ns = now, .local = local,
        .input_len = skb->len };
    if (!local) {
        initial.ingress = dev->ifindex;
        initial.ingress_generation = generation;
    }
    if (bpf_map_update_elem(&origins, &address, &initial, BPF_NOEXIST)) {
        __sync_fetch_and_sub(count, 1);
        return;
    }
    count_global(0, initial.input_len, 0);
}
// Emitted inside __netif_receive_skb_core, including the list receive path.
static __always_inline int receive_event(struct sk_buff *skb) {
    __u64 now = bpf_ktime_get_ns();
    begin(skb, 0, now, configuration());
    return 0;
}
#ifdef SKBTOP_UNIT_TEST
SEC("raw_tp/netif_receive_skb")
int on_receive(struct bpf_raw_tracepoint_args *ctx) {
    return receive_event((void *)ctx->args[0]);
}
#else
SEC("tp_btf/netif_receive_skb")
int BPF_PROG(on_receive, struct sk_buff *skb) {
    return receive_event(skb);
}
#endif
SEC("fentry/__ip_local_out")
int BPF_PROG(on_output4, struct net *net, void *sk, struct sk_buff *skb) {
    struct config *cfg = configuration();
    if (cfg && net && net->ns.inum == cfg->netns) begin(skb, 1, bpf_ktime_get_ns(), cfg);
    return 0;
}
SEC("fentry/__ip6_local_out")
int BPF_PROG(on_output6, struct net *net, void *sk, struct sk_buff *skb) {
    struct config *cfg = configuration();
    if (cfg && net && net->ns.inum == cfg->netns) begin(skb, 1, bpf_ktime_get_ns(), cfg);
    return 0;
}
static __always_inline void mark(struct sk_buff *skb, __u32 flag) {
    if (!enabled()) return;
    __u64 key = (__u64)skb;
    struct meta *m = bpf_map_lookup_elem(&origins, &key);
    if (m && m->birth) {
        m->flags |= flag;
        if (flag == ROUTE) {
            struct net_device *dev = skb->dev;
            if (dev && (dev->priv_flags & 2)) m->flags |= BRIDGE;
        }
    }
}
SEC("fentry/ip_forward")
int BPF_PROG(on_route4, struct sk_buff *skb) { mark(skb, ROUTE); return 0; }
SEC("fentry/ip6_forward")
int BPF_PROG(on_route6, struct sk_buff *skb) { mark(skb, ROUTE); return 0; }
SEC("fentry/br_forward_finish")
int BPF_PROG(on_bridge, struct net *net, void *sk, struct sk_buff *skb) { mark(skb, BRIDGE); return 0; }
SEC("fentry/br_dev_queue_push_xmit")
int BPF_PROG(on_bridge_transmit, struct net *net, void *sk, struct sk_buff *skb) { mark(skb, BRIDGE); return 0; }
SEC("fentry/br_handle_frame_finish")
int BPF_PROG(on_bridge_receive, struct net *net, void *sk, struct sk_buff *skb) { mark(skb, BRIDGE); return 0; }
SEC("fentry/br_forward")
int BPF_PROG(on_bridge_branch, void *to, struct sk_buff *skb) { mark(skb, BRIDGE); return 0; }
SEC("fentry/br_flood")
int BPF_PROG(on_bridge_flood, void *br, struct sk_buff *skb) { mark(skb, BRIDGE); return 0; }
SEC("fentry/br_dev_xmit")
int BPF_PROG(on_bridge_output, struct sk_buff *skb) { mark(skb, BRIDGE); return 0; }
static __always_inline void deliver(struct sk_buff *skb, struct config *cfg) {
    __u64 now = bpf_ktime_get_ns();
    if (!cfg || !cfg->netns || !cfg->capacity) return;
    __u64 address = (__u64)skb;
    struct meta *m = bpf_map_lookup_elem(&origins, &address);
    if (!m || !m->birth || m->local || m->delivered) return;
    struct iface *iface = bpf_map_lookup_elem(&interfaces, &m->ingress);
    if (!iface || !iface->enabled || iface->generation != m->ingress_generation) { error(11); return; }
    m->delivered = 1;
    struct path key = { .kind = 1, .ingress = m->ingress, .netns = cfg->netns,
        .ingress_generation = m->ingress_generation };
    __u32 len = skb->len;
    struct stats *s = path_stats(&key);
    struct interval_write write = {};
    struct traffic *p = s ? period_stats(&key, now, &write, cfg) : 0;
    if (s) {
        flow_resolved(s, p, 0, m->input_len, 0);
        flow_resolved(s, p, 1, len, 0);
    } else {
        // Keep the original retry behavior if a transient map lookup fails.
        flow(&key, now, 0, m->input_len, 0, cfg);
        flow(&key, now, 1, len, 0, cfg);
    }
    count_global(1, len, 0);
    if (!(m->flags & UNSUPPORTED)) {
        if (s) timings_resolved(s, p, &key, &write, now, m->start_ns, 0, now);
        else timings(&key, now, m->start_ns, 0, now, cfg);
    }
    period_done(&write);
}
SEC("fentry/ip_protocol_deliver_rcu")
int BPF_PROG(on_input4, struct net *net, struct sk_buff *skb) {
    struct config *cfg = configuration();
    if (cfg && net && net->ns.inum == cfg->netns) deliver(skb, cfg);
    return 0;
}
SEC("fentry/ip6_protocol_deliver_rcu")
int BPF_PROG(on_input6, struct net *net, struct sk_buff *skb) {
    struct config *cfg = configuration();
    if (cfg && net && net->ns.inum == cfg->netns) deliver(skb, cfg);
    return 0;
}
static __always_inline void conversion(struct sk_buff *skb, __u32 code, __u32 flag) {
    if (!enabled()) return;
    __u64 key = (__u64)skb;
    struct meta *m = bpf_map_lookup_elem(&origins, &key);
    if (m && m->birth) { error(code); m->flags |= flag; }
}
SEC("fentry/ip_do_fragment")
int BPF_PROG(on_fragment4, struct net *net, void *sk, struct sk_buff *skb) { conversion(skb, 12, UNSUPPORTED | REPLACED); return 0; }
SEC("fentry/ip6_fragment")
int BPF_PROG(on_fragment6, struct net *net, void *sk, struct sk_buff *skb) { conversion(skb, 12, UNSUPPORTED | REPLACED); return 0; }
SEC("fentry/ip_defrag")
int BPF_PROG(on_reassembly4, struct net *net, struct sk_buff *skb) { conversion(skb, 13, UNSUPPORTED); return 0; }
SEC("fentry/ipv6_frag_rcv")
int BPF_PROG(on_reassembly6, struct sk_buff *skb) { conversion(skb, 13, UNSUPPORTED); return 0; }
static __always_inline void enqueue(struct sk_buff *skb) {
    __u64 now = bpf_ktime_get_ns();
    struct config *cfg = configuration();
    if (!cfg || !cfg->netns || !cfg->capacity) return;
    __u64 address = (__u64)skb;
    struct net_device *dev = skb->dev;
    __u64 generation = device_generation(dev, cfg);
    if (!generation) return;
    struct meta *m = bpf_map_lookup_elem(&origins, &address);
    if (!m || !m->birth) { error(3); return; }
    if (!m->local) {
        struct iface *iface = bpf_map_lookup_elem(&interfaces, &m->ingress);
        if (!iface || !iface->enabled || iface->generation != m->ingress_generation) { error(11); return; }
    }
    // The bridge writes its master into the control buffer after forwarding
    // decisions. Validate the device instead of inferring from port membership;
    // optimized/inlined bridge functions can otherwise evade function probes.
    if (!(m->flags & BRIDGE)) {
        __u64 address = 0;
        if (bpf_core_field_size(dev->nd_net.net) == 4)
            __builtin_memcpy(&address, skb->cb, 4);
        else
            __builtin_memcpy(&address, skb->cb, 8);
        struct net_device *master = (void *)address;
        if (master && (BPF_CORE_READ_BITFIELD_PROBED(master, priv_flags) & 2)) {
            struct net *net = CORE_PTR(master, nd_net.net);
            __u32 index = BPF_CORE_READ(master, ifindex);
            struct iface *iface = bpf_map_lookup_elem(&interfaces, &index);
            if (net && BPF_CORE_READ(net, ns.inum) == cfg->netns && iface) m->flags |= BRIDGE;
        }
    }
    __u32 egress = dev->ifindex;
    struct tx_key txkey = { .skb = address, .birth = m->birth, .egress_generation = generation };
    // A fresh origin cannot have a transmit. Requeues and inherited origins
    // still need the lookup: their previous transmit may already be retired.
    if (m->queue_ns && bpf_map_lookup_elem(&transmits, &txkey)) return;
    struct tx initial = { .path = { .kind = m->local ? 2 : 3, .netns = cfg->netns,
        .ingress = m->ingress, .ingress_generation = m->ingress_generation,
        .egress = egress, .egress_generation = generation },
        .start_ns = m->start_ns, .queue_ns = now,
        .flags = m->flags, .input_len = m->input_len };
    struct stats *s = path_stats(&initial.path);
    __u64 *count = reserve(cfg, 0);
    if (!count) return;
    if (bpf_map_update_elem(&transmits, &txkey, &initial, BPF_NOEXIST)) {
        __sync_fetch_and_sub(count, 1);
        error(8);
        return;
    }
    m->queue_ns = initial.queue_ns;
    m->egress = egress;
    m->egress_generation = generation;
    if (s) {
        struct interval_write write = {};
        struct traffic *p = period_stats(&initial.path, initial.queue_ns, &write, cfg);
        flow_resolved(s, p, 0, m->input_len, m->flags);
        pending_resolved(s, 1);
        period_done(&write);
    } else {
        flow(&initial.path, initial.queue_ns, 0, m->input_len, m->flags, cfg);
        pending(&initial.path, 1);
    }
}
static __always_inline int attempt_event(struct sk_buff *skb, struct net_device *dev) {
    __u64 now = bpf_ktime_get_ns();
    struct config *cfg = configuration();
    if (!cfg || !cfg->netns || !cfg->capacity) return 0;
    __u32 zero = 0;
    struct attempts *stack = bpf_map_lookup_elem(&callstack, &zero);
    if (!stack) return 0;
    __u32 index = stack->depth++;
    if (index >= 16) { error(7); return 0; }
    struct attempt *a = &stack->frames[index];
    a->active = 0;
    a->dev = (__u64)dev;
    if (!dev) return 0;
    __u64 generation = device_generation(dev, cfg);
    if (!generation) return 0;
    __u64 address = (__u64)skb;
    struct meta *m = bpf_map_lookup_elem(&origins, &address);
    if (!m) return 0;
    a->key.skb = address;
    a->key.birth = m->birth;
    a->key.egress_generation = generation;
    struct tx *t = bpf_map_lookup_elem(&transmits, &a->key);
    if (!t || !t->start_ns) return 0;
    __sync_fetch_and_add(&t->attempting, 1);
    a->time_ns = now;
    a->length = skb->len;
    a->active = 1;
    return 0;
}
static __always_inline int result_event(struct sk_buff *skb, int rc, struct net_device *dev) {
    struct config *cfg = configuration();
    if (!cfg || !cfg->netns || !cfg->capacity) return 0;
    __u32 zero = 0;
    struct attempts *stack = bpf_map_lookup_elem(&callstack, &zero);
    if (!stack || !stack->depth) { error(14); return 0; }
    __u32 index = --stack->depth;
    if (index >= 16) return 0;
    struct attempt *a = &stack->frames[index];
    if (!a->active) return 0;
    a->active = 0;
    if (a->key.skb != (__u64)skb || a->dev != (__u64)dev) { error(14); return 0; }
    struct tx *t = bpf_map_lookup_elem(&transmits, &a->key);
    if (!t) { error(4); return 0; }
    if (rc) {
        __sync_fetch_and_sub(&t->attempting, 1);
        error(9);
        if (t->free_seen && !t->attempting && claim(&t->start_ns)) {
            error(6);
            __u64 now = bpf_ktime_get_ns();
            struct stats *s = path_stats(&t->path);
            if (s) {
                struct interval_write write = {};
                flow_resolved(s, period_stats(&t->path, now, &write, cfg), 2, 0, 0);
                pending_resolved(s, 0);
                period_done(&write);
            } else {
                pending(&t->path, 0);
                flow(&t->path, now, 2, 0, 0, cfg);
            }
            count_global(2, 0, 0);
            bpf_map_delete_elem(&transmits, &a->key);
            release();
        }
        return 0;
    }
    __u64 start = t->start_ns;
    // Keep the attempt reference until success owns retirement; a concurrent
    // consume must not classify an accepted transmission as a premature free.
    int owned = claim(&t->start_ns);
    __sync_fetch_and_sub(&t->attempting, 1);
    if (!owned) return 0;
    __u64 now = bpf_ktime_get_ns();
    if (t->path.kind == 3 && !(t->flags & (ROUTE | BRIDGE))) error(16);
    struct stats *s = path_stats(&t->path);
    struct interval_write write = {};
    struct traffic *p = s ? period_stats(&t->path, now, &write, cfg) : 0;
    if (s) flow_resolved(s, p, 1, a->length, t->flags);
    else flow(&t->path, now, 1, a->length, t->flags, cfg);
    count_global(1, a->length, t->flags);
    if (!(t->flags & UNSUPPORTED)) {
        if (s) timings_resolved(s, p, &t->path, &write, now,
            start, t->queue_ns, a->time_ns);
        else timings(&t->path, now, start, t->queue_ns, a->time_ns, cfg);
    }
    if (s) pending_resolved(s, 0);
    else pending(&t->path, 0);
    period_done(&write);
    bpf_map_delete_elem(&transmits, &a->key);
    release();
    return 0;
}
#ifdef SKBTOP_UNIT_TEST
SEC("raw_tp/net_dev_queue")
int on_queue(struct bpf_raw_tracepoint_args *ctx) { enqueue((void *)ctx->args[0]); return 0; }
SEC("raw_tp/net_dev_start_xmit")
int on_attempt(struct bpf_raw_tracepoint_args *ctx) {
    return attempt_event((void *)ctx->args[0], (void *)ctx->args[1]);
}
SEC("raw_tp/net_dev_xmit")
int on_result(struct bpf_raw_tracepoint_args *ctx) {
    return result_event((void *)ctx->args[0], (__s32)ctx->args[1], (void *)ctx->args[2]);
}
#else
SEC("tp_btf/net_dev_queue")
int BPF_PROG(on_queue, struct sk_buff *skb) {
    enqueue(skb);
    return 0;
}
SEC("tp_btf/net_dev_start_xmit")
int BPF_PROG(on_attempt, struct sk_buff *skb, struct net_device *dev) {
    return attempt_event(skb, dev);
}
SEC("tp_btf/net_dev_xmit")
int BPF_PROG(on_result, struct sk_buff *skb, int rc, struct net_device *dev,
        unsigned int skb_len) {
    return result_event(skb, rc, dev);
}
#endif
static __always_inline struct tx *parent_transmit(__u64 source, struct meta *m) {
    if (!m || !m->birth || !m->queue_ns || !m->egress) return 0;
    struct tx_key key = { .skb = source, .birth = m->birth,
        .egress_generation = m->egress_generation };
    return bpf_map_lookup_elem(&transmits, &key);
}
static __always_inline void inherit_origin(__u64 source, struct sk_buff *new,
        struct meta *m, struct tx *parent_tx, struct config *cfg, __u32 netns) {
    // The array/map values remain valid for this invocation, but another CPU
    // can stop collection or claim retirement between segments.
    if (!cfg || !cfg->netns || !cfg->capacity || cfg->netns != netns) return;
    if (!new || (__u64)new >= (__u64)-4095 || source == (__u64)new) return;
    __u64 dest = (__u64)new;
    if (!m || !m->birth || bpf_map_lookup_elem(&origins, &dest)) return;
    __u64 *count = reserve(cfg, 0);
    if (!count) return;
    struct meta copy = { .birth = bpf_ktime_get_ns(), .start_ns = m->start_ns,
        .queue_ns = m->queue_ns, .ingress_generation = m->ingress_generation,
        .egress_generation = m->egress_generation, .ingress = m->ingress,
        .egress = m->egress, .input_len = m->input_len, .flags = m->flags & ~REPLACED,
        .local = m->local, .delivered = m->delivered };
    if (bpf_map_update_elem(&origins, &dest, &copy, BPF_NOEXIST)) {
        __sync_fetch_and_sub(count, 1);
        error(10);
        return;
    }
    if (copy.queue_ns && copy.egress) {
        if (!parent_tx || !parent_tx->start_ns) return;
        struct tx_key key = { .skb = dest, .birth = copy.birth, .egress_generation = copy.egress_generation };
        count = reserve(cfg, 0);
        if (!count) return;
        struct tx value = { .path = { .kind = copy.local ? 2 : 3, .ingress = copy.ingress,
            .egress = copy.egress, .netns = cfg->netns,
            .ingress_generation = copy.ingress_generation, .egress_generation = copy.egress_generation },
            .start_ns = copy.start_ns, .queue_ns = copy.queue_ns,
            .flags = copy.flags, .input_len = copy.input_len };
        if (bpf_map_update_elem(&transmits, &key, &value, BPF_NOEXIST)) {
            __sync_fetch_and_sub(count, 1);
            error(10);
            return;
        }
        pending(&value.path, 1);
    }
}
static __always_inline void inherit(struct sk_buff *old, struct sk_buff *new) {
    struct config *cfg = configuration();
    if (!cfg || !cfg->netns || !cfg->capacity) return;
    if (!new || (__u64)new >= (__u64)-4095 || old == new) return;
    __u64 source = (__u64)old;
    struct meta *m = bpf_map_lookup_elem(&origins, &source);
    if (!m || !m->birth) return;
    struct net_device *dev = old->dev;
    struct net *net = dev ? dev->nd_net.net : 0;
    if (!net || net->ns.inum != cfg->netns) return;
    inherit_origin(source, new, m, parent_transmit(source, m), cfg, net->ns.inum);
}
SEC("fexit/skb_clone")
int BPF_PROG(on_clone, struct sk_buff *skb, __u32 mask, struct sk_buff *result) { inherit(skb, result); return 0; }
SEC("fexit/skb_copy")
int BPF_PROG(on_copy, struct sk_buff *skb, __u32 mask, struct sk_buff *result) { inherit(skb, result); return 0; }
SEC("fexit/skb_copy_expand")
int BPF_PROG(on_expand, struct sk_buff *skb, int head, int tail, __u32 mask, struct sk_buff *result) { inherit(skb, result); return 0; }
SEC("fexit/__pskb_copy_fclone")
int BPF_PROG(on_pskb, struct sk_buff *skb, int head, __u32 mask, int fclone, struct sk_buff *result) { inherit(skb, result); return 0; }
SEC("fexit/skb_morph")
int BPF_PROG(on_morph, struct sk_buff *dest, struct sk_buff *src, struct sk_buff *result) { inherit(src, result); return 0; }
struct segment_walk {
    struct sk_buff *next;
    __u64 source;
    struct meta *meta;
    struct tx *parent;
    struct config *cfg;
    __u32 netns;
};
static long segment_step(__u32 index, void *opaque) {
    struct segment_walk *walk = opaque;
    struct sk_buff *list = walk->next;
    if (!list) return 1;
    if (walk->netns) inherit_origin(walk->source, list, walk->meta, walk->parent,
        walk->cfg, walk->netns);
    walk->next = list->next;
    return 0;
}
static __always_inline void segments(struct sk_buff *source, struct sk_buff *list) {
    if (!list || (__u64)list >= (__u64)-4095) return;
    struct config *cfg = configuration();
    __u64 address = (__u64)source;
    struct meta *m = cfg && cfg->netns && cfg->capacity ? bpf_map_lookup_elem(&origins, &address) : 0;
    if (m && m->birth) m->flags |= REPLACED;
    struct net_device *dev = m && m->birth ? source->dev : 0;
    struct net *net = dev ? dev->nd_net.net : 0;
    __u32 netns = net ? net->ns.inum : 0;
    struct tx *parent_tx = net && cfg && netns == cfg->netns ? parent_transmit(address, m) : 0;
    // A helper callback is checked once rather than exploring every branch of
    // 128 iterations; cached parent map pointers remain valid in this invocation.
    struct segment_walk walk = { .next = list, .source = address, .meta = m,
        .parent = parent_tx, .cfg = cfg, .netns = netns };
    bpf_loop(128, segment_step, &walk, 0);
    if (walk.next) error(7);
}
SEC("fexit/skb_segment")
int BPF_PROG(on_segment, struct sk_buff *skb, __u64 features, struct sk_buff *result) { segments(skb, result); return 0; }
SEC("fexit/skb_segment_list")
int BPF_PROG(on_segment_list, struct sk_buff *skb, __u64 features, unsigned int offset, struct sk_buff *result) { segments(skb, result); return 0; }
static __always_inline void forget(struct sk_buff *skb) {
    struct config *cfg = configuration();
    if (!cfg || !cfg->netns || !cfg->capacity) return;
    __u64 key = (__u64)skb;
    struct meta *m = bpf_map_lookup_elem(&origins, &key);
    if (m) {
        __u64 birth = m->birth;
        if (!claim(&m->birth)) return;
        if (m->queue_ns && m->egress) {
            struct tx_key txkey = { .skb = key, .birth = birth, .egress_generation = m->egress_generation };
            struct tx *t = bpf_map_lookup_elem(&transmits, &txkey);
            if (t) t->free_seen = 1;
            if (t && !t->attempting && claim(&t->start_ns)) {
                __u64 now = bpf_ktime_get_ns();
                struct stats *s = path_stats(&t->path);
                if (!(m->flags & REPLACED)) {
                    error(6);
                    if (s) {
                        struct interval_write write = {};
                        flow_resolved(s, period_stats(&t->path, now, &write, cfg), 2, 0, 0);
                        period_done(&write);
                    } else flow(&t->path, now, 2, 0, 0, cfg);
                    count_global(2, 0, 0);
                }
                if (s) pending_resolved(s, 0);
                else pending(&t->path, 0);
                bpf_map_delete_elem(&transmits, &txkey);
                release();
            }
        } else if (!m->delivered && !(m->flags & REPLACED)) error(15);
        bpf_map_delete_elem(&origins, &key);
        release();
    }
}
#ifdef SKBTOP_UNIT_TEST
// __kfree_skb always calls skb_release_head_state. Keep this native entry for
// existing lifecycle scenarios, but avoid a redundant production attachment.
int BPF_PROG(on_free, struct sk_buff *skb) { forget(skb); return 0; }
#endif
SEC("fentry/skb_release_head_state")
int BPF_PROG(on_release, struct sk_buff *skb) { forget(skb); return 0; }
static __always_inline int consume_event(struct sk_buff *skb) {
    forget(skb);
    return 0;
}
static __always_inline int drop_event(struct sk_buff *skb) {
    forget(skb);
    return 0;
}
#ifdef SKBTOP_UNIT_TEST
SEC("raw_tp/consume_skb")
int on_consume(struct bpf_raw_tracepoint_args *ctx) {
    return consume_event((void *)ctx->args[0]);
}
SEC("raw_tp/kfree_skb")
int on_drop(struct bpf_raw_tracepoint_args *ctx) {
    return drop_event((void *)ctx->args[0]);
}
#else
SEC("tp_btf/consume_skb")
int BPF_PROG(on_consume, struct sk_buff *skb, void *location) {
    (void)location;
    return consume_event(skb);
}
SEC("tp_btf/kfree_skb")
int BPF_PROG(on_drop, struct sk_buff *skb, void *location, int reason) {
    (void)location;
    (void)reason;
    return drop_event(skb);
}
#endif
char LICENSE[] SEC("license") = "GPL";
