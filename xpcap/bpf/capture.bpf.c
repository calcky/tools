// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "capture.h"

struct net_device { int ifindex; } __attribute__((preserve_access_index));
struct xdp_rxq_info { struct net_device *dev; __u32 queue_index; } __attribute__((preserve_access_index));
struct xdp_buff {
    void *data;
    void *data_end;
    void *data_hard_start;
    struct xdp_rxq_info *rxq;
    __u32 frame_sz;
    __u32 flags;
} __attribute__((preserve_access_index));
struct skb_shared_info { __u32 xdp_frags_size; } __attribute__((preserve_access_index));
struct bpf_prog_aux { __u32 id; } __attribute__((preserve_access_index));
struct bpf_prog { struct bpf_prog_aux *aux; } __attribute__((preserve_access_index));
struct xdp_desc { __u64 addr; __u32 len; __u32 options; };
struct xsk_buff_pool {
    struct net_device *netdev;
    __u16 queue_id;
    struct xdp_desc *tx_descs;
    __u64 addrs_cnt;
    __u32 chunk_size;
    bool unaligned;
    void *addrs;
} __attribute__((preserve_access_index));
struct xdp_sock {
    struct net_device *dev;
    struct xsk_buff_pool *pool;
    __u16 queue_id;
} __attribute__((preserve_access_index));
struct sock;
struct sk_buff {
    __u32 len;
    __u32 data_len;
    struct net_device *dev;
    unsigned char *data;
} __attribute__((preserve_access_index));
struct sample { struct event_meta meta; __u8 data[XPCAP_SCRATCH_BYTES]; };
struct redirect_tracepoint {
    __u64 common;
    int prog_id;
    __u32 action;
    int ifindex;
    int err;
    int to_ifindex;
    __u32 map_id;
    int map_index;
};
struct tx_state { struct xsk_buff_pool *pool; struct xdp_desc *desc; __u8 batch; };
struct tx_batch_state {
    void *ctx;
    struct xsk_buff_pool *pool;
    struct xdp_desc *descs;
    struct sample *sample;
};
struct generic_tx_context { __u32 ifindex; __u32 queue; };

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct capture_config);
} config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
    __type(key, int);
    __type(value, __u32);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct sample);
} scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct sample);
} rx_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct sample);
} redirect_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tx_state);
} tx_context SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct generic_tx_context);
} generic_tx_contexts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 30);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

#include "filter.bpf.h"

static __always_inline void count(__u32 stage, __u32 reason) {
    if (stage < 1 || stage > 5) return;
    __u32 key = (stage - 1) * 6 + reason;
    __u64 *value = bpf_map_lookup_elem(&stats, &key);
    if (value) (*value)++;
}

static __always_inline void count_many(__u32 stage, __u32 reason, __u64 amount) {
    __u32 key = (stage - 1) * 6 + reason;
    __u64 *value = bpf_map_lookup_elem(&stats, &key);
    if (value) *value += amount;
}

static __always_inline struct capture_config *cfg_get(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&config, &key);
}

static __always_inline bool stage_enabled(struct capture_config *cfg, __u8 stage) {
    return cfg && (cfg->stage_mask & (1U << (stage - 1)));
}

static __always_inline bool sample_matches(struct capture_config *cfg, __u8 stage) {
    if (cfg->sample <= 1 || bpf_get_prandom_u32() % cfg->sample == 0) return true;
    count(stage, 5);
    return false;
}

static __always_inline bool location_matches(struct capture_config *cfg, __u32 ifindex, __u32 queue) {
    if (!cfg || (cfg->has_queue && cfg->queue != queue)) return false;
    if (cfg->ifcount == 0) return true;
    for (int i = 0; i < XPCAP_MAX_IFACES; i++) {
        if ((__u32)i >= cfg->ifcount) break;
        if (cfg->ifindexes[i] == ifindex) return true;
    }
    return false;
}

static __always_inline bool xdp_info(struct xdp_buff *xdp, void **data, __u32 *len,
                                     __u32 *linear_len, __u32 *ifindex, __u32 *queue,
                                     __u8 *flags) {
    void *end = BPF_CORE_READ(xdp, data_end);
    *data = BPF_CORE_READ(xdp, data);
    struct xdp_rxq_info *rxq = BPF_CORE_READ(xdp, rxq);
    if (!rxq || !*data || end <= *data) return false;
    *linear_len = end - *data;
    *len = *linear_len;
    *ifindex = BPF_CORE_READ(rxq, dev, ifindex);
    *queue = BPF_CORE_READ(rxq, queue_index);
    *flags = BPF_CORE_READ(xdp, flags) & 1 ? FLAG_XDP_FRAGS : 0;
    if (*flags & FLAG_XDP_FRAGS) {
        void *hard_start = BPF_CORE_READ(xdp, data_hard_start);
        __u32 frame_sz = BPF_CORE_READ(xdp, frame_sz);
        __u32 info_size = bpf_core_type_size(struct skb_shared_info);
        if (!hard_start || frame_sz < info_size) return false;
        struct skb_shared_info *info = hard_start + frame_sz - info_size;
        __u32 frag_len = BPF_CORE_READ(info, xdp_frags_size);
        if (frag_len > ((__u32)-1) - *len) return false;
        *len += frag_len;
    }
    return true;
}

static __always_inline void fill_meta(struct event_meta *meta, __u8 stage, __u32 ifindex,
                                      __u32 queue, __u32 len, __u32 cap, __u8 flags) {
    __builtin_memset(meta, 0, sizeof(*meta));
    meta->ts_ns = bpf_ktime_get_ns();
    meta->ifindex = ifindex;
    meta->queue = queue;
    meta->packet_len = len;
    meta->cap_len = cap;
    meta->stage = stage;
    meta->flags = flags | (cap < len ? FLAG_PARTIAL : 0);
}

static __always_inline void emit_xdp(void *ctx, struct xdp_buff *xdp, __u8 stage, __u8 action) {
    struct capture_config *cfg = cfg_get();
    if (!stage_enabled(cfg, stage)) return;
    void *data;
    __u32 len, linear_len, ifindex, queue;
    __u8 flags;
    if (!xdp_info(xdp, &data, &len, &linear_len, &ifindex, &queue, &flags)) return;
    if (!location_matches(cfg, ifindex, queue) || !filter_matches(data, linear_len, len)) {
        count(stage, 0); return;
    }
    if (!sample_matches(cfg, stage)) return;
    struct event_meta meta;
    __u32 cap = cfg->snaplen;
    if (cap > XPCAP_MAX_SNAPLEN) cap = XPCAP_MAX_SNAPLEN;
    if (cap > len) cap = len;
    fill_meta(&meta, stage, ifindex, queue, len, cap, flags);
    meta.action = action;
    meta.prog_id = cfg->prog_id;
    if (meta.flags & FLAG_PARTIAL) count(stage, 3);
    if (bpf_xdp_output(xdp, &events, ((__u64)cap << 32) | BPF_F_CURRENT_CPU,
                       &meta, sizeof(meta))) count(stage, 2);
}

static __always_inline void *sample_get(void *map) {
    __u32 key = 0;
    return bpf_map_lookup_elem(map, &key);
}

static __always_inline bool capture_xdp_sample(struct sample *sample, struct xdp_buff *xdp,
                                               __u8 stage, struct capture_config *cfg) {
    void *data;
    __u32 len, linear_len, ifindex, queue;
    __u8 flags;
    if (!sample || !xdp_info(xdp, &data, &len, &linear_len, &ifindex, &queue, &flags)) return false;
    if (!location_matches(cfg, ifindex, queue) || !filter_matches(data, linear_len, len)) {
        count(stage, 0); return false;
    }
    if (!sample_matches(cfg, stage)) return false;
    __u32 cap = cfg->snaplen;
    if (cap > XPCAP_MAX_SNAPLEN) cap = XPCAP_MAX_SNAPLEN;
    if (cap > linear_len) cap = linear_len;
    fill_meta(&sample->meta, stage, ifindex, queue, len, cap, flags);
    if (bpf_probe_read_kernel(sample->data, cap, data)) { count(stage, 1); return false; }
    if (sample->meta.flags & FLAG_PARTIAL) count(stage, 3);
    return true;
}

static __always_inline void emit_sample(void *ctx, struct sample *sample) {
    __u32 cap = sample->meta.cap_len;
    if (cap > XPCAP_MAX_SNAPLEN) { count(sample->meta.stage, 1); return; }
    cap &= 0x3fff;
    if (bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, sample,
                              sizeof(sample->meta) + cap)) count(sample->meta.stage, 2);
}

static __always_inline bool capture_desc(struct sample *sample, struct xsk_buff_pool *pool,
                                         struct xdp_desc *desc, __u8 mode) {
    struct capture_config *cfg = cfg_get();
    if (!stage_enabled(cfg, STAGE_XSK_TX) || !sample || !pool || !desc) return false;
    __u32 ifindex = BPF_CORE_READ(pool, netdev, ifindex);
    __u32 queue = BPF_CORE_READ(pool, queue_id);
    if (!location_matches(cfg, ifindex, queue)) return false;
    struct xdp_desc d;
    if (bpf_probe_read_kernel(&d, sizeof(d), desc) || !d.len) { count(STAGE_XSK_TX, 1); return false; }
    __u64 addr = d.addr;
    if (BPF_CORE_READ(pool, unaligned)) addr = (addr & ((1ULL << 48) - 1)) + (addr >> 48);
    if (addr >= BPF_CORE_READ(pool, addrs_cnt) || d.len > BPF_CORE_READ(pool, addrs_cnt) - addr)
        { count(STAGE_XSK_TX, 1); return false; }
    void *data = BPF_CORE_READ(pool, addrs) + addr;
    if (!filter_matches(data, d.len, d.len)) { count(STAGE_XSK_TX, 0); return false; }
    if (!sample_matches(cfg, STAGE_XSK_TX)) return false;
    __u32 cap = cfg->snaplen;
    if (cap > XPCAP_MAX_SNAPLEN) cap = XPCAP_MAX_SNAPLEN;
    if (cap > d.len) cap = d.len;
    fill_meta(&sample->meta, STAGE_XSK_TX, ifindex, queue, d.len, cap,
              d.options & 1 ? FLAG_PARTIAL : 0);
    sample->meta.action = mode;
    if (bpf_probe_read_kernel(sample->data, cap, data)) { count(STAGE_XSK_TX, 1); return false; }
    if (sample->meta.flags) count(STAGE_XSK_TX, 3);
    return true;
}

SEC("fentry/func")
int BPF_PROG(xdp_entry, struct xdp_buff *xdp) {
    emit_xdp(ctx, xdp, STAGE_XDP_ENTRY, 0);
    return 0;
}

SEC("fexit/func")
int BPF_PROG(xdp_exit, struct xdp_buff *xdp, int action) {
    emit_xdp(ctx, xdp, STAGE_XDP_EXIT, action);
    return 0;
}

static __always_inline void start_redirect(struct xdp_buff *xdp) {
    struct capture_config *cfg = cfg_get();
    if (!stage_enabled(cfg, STAGE_REDIRECT)) return;
    struct sample *sample = sample_get(&redirect_scratch);
    if (!sample) return;
    sample->meta.stage = 0;
    if (capture_xdp_sample(sample, xdp, STAGE_REDIRECT, cfg)) sample->meta.prog_id = cfg->prog_id;
}

static __always_inline void finish_redirect(void *ctx, int result) {
    struct sample *sample = sample_get(&redirect_scratch);
    if (!sample || sample->meta.stage != STAGE_REDIRECT) return;
    sample->meta.result = result;
    emit_sample(ctx, sample);
    sample->meta.stage = 0;
}

SEC("fentry/xdp_do_redirect")
int BPF_PROG(redirect_entry, struct net_device *dev, struct xdp_buff *xdp) {
    start_redirect(xdp);
    return 0;
}

SEC("fexit/xdp_do_redirect")
int BPF_PROG(redirect_exit, struct net_device *dev, struct xdp_buff *xdp,
             struct bpf_prog *prog, int result) {
    finish_redirect(ctx, result);
    return 0;
}

SEC("fentry/xdp_do_redirect_frame")
int BPF_PROG(redirect_frame_entry, struct net_device *dev, struct xdp_buff *xdp) {
    start_redirect(xdp);
    return 0;
}

SEC("fexit/xdp_do_redirect_frame")
int BPF_PROG(redirect_frame_exit, struct net_device *dev, struct xdp_buff *xdp,
             void *frame, struct bpf_prog *prog, int result) {
    finish_redirect(ctx, result);
    return 0;
}

SEC("fentry/xdp_do_generic_redirect")
int BPF_PROG(redirect_generic_entry, struct net_device *dev, void *skb,
             struct xdp_buff *xdp, struct bpf_prog *prog) {
    start_redirect(xdp);
    return 0;
}

SEC("fexit/xdp_do_generic_redirect")
int BPF_PROG(redirect_generic_exit, struct net_device *dev, void *skb,
             struct xdp_buff *xdp, struct bpf_prog *prog, int result) {
    finish_redirect(ctx, result);
    return 0;
}

static __always_inline void redirect_metadata(struct redirect_tracepoint *tp) {
    struct sample *sample = sample_get(&redirect_scratch);
    if (!sample || sample->meta.stage != STAGE_REDIRECT || sample->meta.ifindex != tp->ifindex) return;
    sample->meta.prog_id = tp->prog_id;
    sample->meta.map_id = tp->map_id;
    sample->meta.map_index = tp->map_index;
    sample->meta.to_ifindex = tp->to_ifindex;
    sample->meta.result = tp->err;
    sample->meta.flags |= FLAG_REDIRECT_META;
}

SEC("tracepoint/xdp/xdp_redirect")
int redirect_trace(struct redirect_tracepoint *tp) { redirect_metadata(tp); return 0; }

SEC("tracepoint/xdp/xdp_redirect_err")
int redirect_error_trace(struct redirect_tracepoint *tp) { redirect_metadata(tp); return 0; }

static __always_inline void start_rx(struct xdp_sock *xs, struct xdp_buff *xdp) {
    struct capture_config *cfg = cfg_get();
    if (!stage_enabled(cfg, STAGE_XSK_RX)) return;
    struct sample *sample = sample_get(&rx_scratch);
    if (!sample) return;
    sample->meta.stage = 0;
    if (capture_xdp_sample(sample, xdp, STAGE_XSK_RX, cfg)) {
        sample->meta.ifindex = BPF_CORE_READ(xs, dev, ifindex);
        sample->meta.queue = BPF_CORE_READ(xs, queue_id);
    }
}

static __always_inline void finish_rx(void *ctx, int result) {
    struct sample *sample = sample_get(&rx_scratch);
    if (!sample || sample->meta.stage != STAGE_XSK_RX) return;
    if (result == 0) emit_sample(ctx, sample);
    sample->meta.stage = 0;
}

SEC("fentry/__xsk_map_redirect")
int BPF_PROG(xsk_rx_entry, struct xdp_sock *xs, struct xdp_buff *xdp) {
    start_rx(xs, xdp);
    return 0;
}

SEC("fexit/__xsk_map_redirect")
int BPF_PROG(xsk_rx_exit, struct xdp_sock *xs, struct xdp_buff *xdp, int result) {
    finish_rx(ctx, result);
    return 0;
}

SEC("fentry/xsk_generic_rcv")
int BPF_PROG(xsk_generic_rx_entry, struct xdp_sock *xs, struct xdp_buff *xdp) {
    start_rx(xs, xdp);
    return 0;
}

SEC("fexit/xsk_generic_rcv")
int BPF_PROG(xsk_generic_rx_exit, struct xdp_sock *xs, struct xdp_buff *xdp, int result) {
    finish_rx(ctx, result);
    return 0;
}

SEC("fentry/xsk_build_skb")
int BPF_PROG(xsk_generic_tx_entry, struct xdp_sock *xs, struct xdp_desc *desc) {
    struct sample *sample = sample_get(&scratch);
    if (!sample) return 0;
    sample->meta.stage = 0;
    if (capture_desc(sample, BPF_CORE_READ(xs, pool), desc, 0)) sample->meta.stage = STAGE_XSK_TX;
    return 0;
}

SEC("fexit/xsk_build_skb")
int BPF_PROG(xsk_generic_tx_exit, struct xdp_sock *xs, struct xdp_desc *desc, void *result) {
    struct sample *sample = sample_get(&scratch);
    if (sample && sample->meta.stage == STAGE_XSK_TX) {
        if (result && (unsigned long)result < (unsigned long)-4095) emit_sample(ctx, sample);
        sample->meta.stage = 0;
    }
    return 0;
}

SEC("fentry/__xsk_generic_xmit")
int BPF_PROG(xsk_generic_xmit_entry, struct sock *sk) {
    struct capture_config *cfg = cfg_get();
    if (!stage_enabled(cfg, STAGE_XSK_TX)) return 0;
    struct xdp_sock *xs = (void *)sk;
    struct generic_tx_context value = {
        .ifindex = BPF_CORE_READ(xs, dev, ifindex),
        .queue = BPF_CORE_READ(xs, queue_id),
    };
    if (!location_matches(cfg, value.ifindex, value.queue)) return 0;
    __u64 key = bpf_get_current_pid_tgid();
    if (bpf_map_update_elem(&generic_tx_contexts, &key, &value, BPF_ANY))
        count(STAGE_XSK_TX, 1);
    return 0;
}

SEC("fexit/__xsk_generic_xmit")
int BPF_PROG(xsk_generic_xmit_exit, struct sock *sk, int result) {
    __u64 key = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&generic_tx_contexts, &key);
    return 0;
}

SEC("fentry/__dev_direct_xmit")
int BPF_PROG(xsk_generic_direct_xmit, struct sk_buff *skb, __u16 queue_id) {
    __u64 key = bpf_get_current_pid_tgid();
    struct generic_tx_context *source = bpf_map_lookup_elem(&generic_tx_contexts, &key);
    struct capture_config *cfg = cfg_get();
    if (!source || !stage_enabled(cfg, STAGE_XSK_TX) ||
        source->queue != queue_id || source->ifindex != BPF_CORE_READ(skb, dev, ifindex))
        return 0;
    __u32 len = BPF_CORE_READ(skb, len);
    __u32 data_len = BPF_CORE_READ(skb, data_len);
    if (data_len > len) { count(STAGE_XSK_TX, 1); return 0; }
    __u32 linear = len - data_len;
    void *data = BPF_CORE_READ(skb, data);
    if (!data || !linear) { count(STAGE_XSK_TX, 1); return 0; }
    if (!filter_matches(data, linear, len)) { count(STAGE_XSK_TX, 0); return 0; }
    if (!sample_matches(cfg, STAGE_XSK_TX)) return 0;
    struct sample *sample = sample_get(&scratch);
    if (!sample) { count(STAGE_XSK_TX, 1); return 0; }
    __u32 cap = cfg->snaplen;
    if (cap > linear) cap = linear;
    if (cap > XPCAP_MAX_SNAPLEN) cap = XPCAP_MAX_SNAPLEN;
    fill_meta(&sample->meta, STAGE_XSK_TX, source->ifindex, source->queue,
              len, cap, data_len ? FLAG_PARTIAL : 0);
    sample->meta.action = 3;
    // Keep the bound on the value passed to the helper, not on a compiler-created copy.
    asm volatile("%0 &= 16383" : "+r"(cap));
    if (cap > XPCAP_MAX_SNAPLEN) { count(STAGE_XSK_TX, 1); return 0; }
    if (bpf_probe_read_kernel(sample->data, cap, data)) {
        count(STAGE_XSK_TX, 1);
        return 0;
    }
    if (sample->meta.flags) count(STAGE_XSK_TX, 3);
    emit_sample(ctx, sample);
    return 0;
}

SEC("fentry/xsk_tx_peek_desc")
int BPF_PROG(xsk_tx_single_entry, struct xsk_buff_pool *pool, struct xdp_desc *desc) {
    struct tx_state *state = sample_get(&tx_context);
    if (state && !state->batch) { state->pool = pool; state->desc = desc; }
    return 0;
}

SEC("fexit/xsk_tx_peek_desc")
int BPF_PROG(xsk_tx_single_exit, struct xsk_buff_pool *pool, struct xdp_desc *desc, bool success) {
    struct tx_state *state = sample_get(&tx_context);
    if (!state || state->batch) return 0;
    if (success && state->pool == pool && state->desc == desc) {
        struct sample *sample = sample_get(&scratch);
        if (capture_desc(sample, pool, desc, 1)) emit_sample(ctx, sample);
    }
    state->pool = 0;
    state->desc = 0;
    return 0;
}

SEC("fentry/xsk_tx_peek_release_desc_batch")
int BPF_PROG(xsk_tx_batch_entry, struct xsk_buff_pool *pool) {
    struct tx_state *state = sample_get(&tx_context);
    if (state) { state->batch = 1; state->pool = pool; }
    return 0;
}

static long capture_tx_batch_desc(__u32 index, void *context) {
    struct tx_batch_state *batch = context;
    if (capture_desc(batch->sample, batch->pool, &batch->descs[index], 2))
        emit_sample(batch->ctx, batch->sample);
    return 0;
}

SEC("fexit/xsk_tx_peek_release_desc_batch")
int BPF_PROG(xsk_tx_batch_exit, struct xsk_buff_pool *pool, __u32 requested, __u32 count_out) {
    struct tx_state *state = sample_get(&tx_context);
    if (!state || !state->batch) return 0;
    if (state->pool != pool) {
        state->batch = 0;
        state->pool = 0;
        return 0;
    }
    struct xdp_desc *descs = BPF_CORE_READ(pool, tx_descs);
    struct sample *sample = sample_get(&scratch);
    if (!descs || !sample) {
        count_many(STAGE_XSK_TX, 1, count_out);
        state->batch = 0;
        state->pool = 0;
        return 0;
    }
    struct tx_batch_state batch = { .ctx = ctx, .pool = pool, .descs = descs, .sample = sample };
    __u32 limit = count_out < XPCAP_MAX_BATCH ? count_out : XPCAP_MAX_BATCH;
    if (bpf_loop(limit, capture_tx_batch_desc, &batch, 0) < 0)
        count_many(STAGE_XSK_TX, 1, limit);
    if (count_out > XPCAP_MAX_BATCH) count_many(STAGE_XSK_TX, 4, count_out - XPCAP_MAX_BATCH);
    state->batch = 0;
    state->pool = 0;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
