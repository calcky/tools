#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <stdbool.h>

#define CORE __attribute__((preserve_access_index))
#define MAP_SLOT_LIMIT 16384
#define TOTAL_SLOT_LIMIT 65536

struct bpf_map {
    enum bpf_map_type map_type;
    __u32 max_entries;
    __u32 id;
    __s64 *elem_count;
} CORE;
struct bpf_iter_meta { struct seq_file *seq; __u64 session_id, seq_num; } CORE;
struct bpf_iter__bpf_map { struct bpf_iter_meta *meta; struct bpf_map *map; } CORE;
struct xsk_map { struct bpf_map map; void *xsk_map[]; } CORE;
struct bpf_array { struct bpf_map map; void *ptrs[]; } CORE;
struct bpf_dtab { struct bpf_map map; void **netdev_map; unsigned int items; } CORE;
struct bpf_cpu_map { struct bpf_map map; void **cpu_map; } CORE;
struct bpf_stab { struct bpf_map map; void **sks; } CORE;
struct reuseport_array { struct bpf_map map; void *ptrs[]; } CORE;
struct lpm_trie { struct bpf_map map; unsigned long n_entries; } CORE;
typedef struct { int counter; } CORE atomic_t;
struct bpf_shtab { struct bpf_map map; atomic_t count; } CORE;
struct bpf_queue_stack { struct bpf_map map; __u32 head, tail, size; } CORE;
struct bpf_stack_map { struct bpf_map map; __u32 n_buckets; void *buckets[]; } CORE;
struct bpf_ringbuf { unsigned long consumer_pos, producer_pos; } CORE;
struct bpf_ringbuf_map { struct bpf_map map; struct bpf_ringbuf *rb; } CORE;

enum count_kind { UNKNOWN, COUNTER, SLOTS, OCCUPIED, PARTIAL, BYTES };
struct count_record {
    __u32 id, type, capacity, kind;
    __s64 count;
    __u32 scanned, reserved;
};
struct pointer_scan {
    __u64 base, count;
    __u32 stride, limit, scanned, error;
};

extern __s64 bpf_map_sum_elem_count(const struct bpf_map *map) __ksym;
static __u32 scanned_slots;

/* Field sizes are relocated too, including 32-bit kernel pointers/longs. */
#define READ_SCALAR(dst, field) ({ \
    __u32 size = bpf_core_field_size(field); \
    (dst) = 0; \
    (size == 4 || size == 8) ? \
        bpf_probe_read_kernel(&(dst), size, &(field)) : -1; \
})

static long scan_pointer(__u32 index, void *data)
{
    struct pointer_scan *scan = data;
    __u64 pointer = 0;
    if (index >= MAP_SLOT_LIMIT || index >= scan->limit ||
        (scan->stride != 4 && scan->stride != 8))
        return 1;
    if (bpf_probe_read_kernel(&pointer, scan->stride,
                             (void *)(scan->base + (__u64)index * scan->stride))) {
        scan->error = 1;
        return 1;
    }
    scan->scanned++;
    scan->count += pointer != 0;
    return 0;
}

static void occupied(struct count_record *record, __u64 base, __u32 stride, __u32 slots)
{
    __u32 remaining = scanned_slots < TOTAL_SLOT_LIMIT ? TOTAL_SLOT_LIMIT - scanned_slots : 0;
    struct pointer_scan scan = {
        .stride = stride,
        .limit = slots < MAP_SLOT_LIMIT ? slots : MAP_SLOT_LIMIT,
    };
    if (!base || (stride != 4 && stride != 8))
        return;
    /* Convert the trusted map address to a scalar before bounded slot reads. */
    if (bpf_probe_read_kernel(&scan.base, sizeof(scan.base), &base))
        return;
    if (scan.limit > remaining)
        scan.limit = remaining;
    bpf_loop(scan.limit, scan_pointer, &scan, 0);
    scanned_slots += scan.scanned;
    record->scanned = scan.scanned;
    if (scan.error)
        return;
    record->count = scan.count;
    record->kind = scan.scanned == slots ? OCCUPIED : PARTIAL;
}

static void count_map(struct bpf_map *map, struct count_record *record)
{
    __u64 pointer = 0, number = 0;
    if (bpf_core_field_exists(map->elem_count) &&
        !READ_SCALAR(pointer, map->elem_count) && pointer) {
        record->count = bpf_map_sum_elem_count(map);
        record->kind = COUNTER;
        return;
    }
    switch (record->type) {
    case BPF_MAP_TYPE_ARRAY:
    case BPF_MAP_TYPE_PERCPU_ARRAY:
    case BPF_MAP_TYPE_STRUCT_OPS:
        record->kind = SLOTS;
        record->count = record->capacity;
        break;
    case BPF_MAP_TYPE_LPM_TRIE: {
        struct lpm_trie *trie = (void *)map;
        if (bpf_core_field_exists(trie->n_entries) && !READ_SCALAR(number, trie->n_entries)) {
            record->kind = COUNTER;
            record->count = number;
        }
        break;
    }
    case BPF_MAP_TYPE_DEVMAP_HASH: {
        struct bpf_dtab *dtab = (void *)map;
        if (bpf_core_field_exists(dtab->items) && !READ_SCALAR(number, dtab->items)) {
            record->kind = COUNTER;
            record->count = number;
        }
        break;
    }
    case BPF_MAP_TYPE_SOCKHASH: {
        struct bpf_shtab *htab = (void *)map;
        if (bpf_core_field_exists(htab->count.counter) && !READ_SCALAR(number, htab->count.counter)) {
            record->kind = COUNTER;
            record->count = (__s32)number;
        }
        break;
    }
    case BPF_MAP_TYPE_QUEUE:
    case BPF_MAP_TYPE_STACK: {
        struct bpf_queue_stack *queue = (void *)map;
        __u32 head = 0, tail = 0, size = 0;
        if (bpf_core_field_exists(queue->head) && bpf_core_field_exists(queue->tail) &&
            bpf_core_field_exists(queue->size) &&
            !bpf_core_read(&head, sizeof(head), &queue->head) &&
            !bpf_core_read(&tail, sizeof(tail), &queue->tail) &&
            !bpf_core_read(&size, sizeof(size), &queue->size) &&
            size > 0 && head < size && tail < size) {
            record->kind = COUNTER;
            record->count = head >= tail ? head - tail : (__u64)size - tail + head;
        }
        break;
    }
    case BPF_MAP_TYPE_XSKMAP: {
        struct xsk_map *xsk = (void *)map;
        if (bpf_core_field_exists(xsk->xsk_map))
            occupied(record, (__u64)xsk + bpf_core_field_offset(xsk->xsk_map),
                     bpf_core_field_size(map->elem_count), record->capacity);
        break;
    }
    case BPF_MAP_TYPE_PROG_ARRAY:
    case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
    case BPF_MAP_TYPE_CGROUP_ARRAY:
    case BPF_MAP_TYPE_ARRAY_OF_MAPS: {
        struct bpf_array *array = (void *)map;
        if (bpf_core_field_exists(array->ptrs))
            occupied(record, (__u64)array + bpf_core_field_offset(array->ptrs),
                     bpf_core_field_size(map->elem_count), record->capacity);
        break;
    }
    case BPF_MAP_TYPE_REUSEPORT_SOCKARRAY: {
        struct reuseport_array *array = (void *)map;
        if (bpf_core_field_exists(array->ptrs))
            occupied(record, (__u64)array + bpf_core_field_offset(array->ptrs),
                     bpf_core_field_size(map->elem_count), record->capacity);
        break;
    }
    case BPF_MAP_TYPE_STACK_TRACE: {
        struct bpf_stack_map *stacks = (void *)map;
        if (bpf_core_field_exists(stacks->buckets) && bpf_core_field_exists(stacks->n_buckets) &&
            !READ_SCALAR(number, stacks->n_buckets) && number <= 0xffffffffULL)
            occupied(record, (__u64)stacks + bpf_core_field_offset(stacks->buckets),
                     bpf_core_field_size(map->elem_count), number);
        break;
    }
    case BPF_MAP_TYPE_DEVMAP: {
        struct bpf_dtab *dtab = (void *)map;
        if (bpf_core_field_exists(dtab->netdev_map) && !READ_SCALAR(pointer, dtab->netdev_map))
            occupied(record, pointer, bpf_core_field_size(map->elem_count), record->capacity);
        break;
    }
    case BPF_MAP_TYPE_CPUMAP: {
        struct bpf_cpu_map *cpus = (void *)map;
        if (bpf_core_field_exists(cpus->cpu_map) && !READ_SCALAR(pointer, cpus->cpu_map))
            occupied(record, pointer, bpf_core_field_size(map->elem_count), record->capacity);
        break;
    }
    case BPF_MAP_TYPE_SOCKMAP: {
        struct bpf_stab *socks = (void *)map;
        if (bpf_core_field_exists(socks->sks) && !READ_SCALAR(pointer, socks->sks))
            occupied(record, pointer, bpf_core_field_size(map->elem_count), record->capacity);
        break;
    }
    case BPF_MAP_TYPE_RINGBUF:
    case BPF_MAP_TYPE_USER_RINGBUF: {
        struct bpf_ringbuf_map *ring = (void *)map;
        __u64 consumer = 0, producer = 0;
        if (bpf_core_field_exists(ring->rb) && !READ_SCALAR(pointer, ring->rb) && pointer) {
            struct bpf_ringbuf *rb = (void *)pointer;
            if (bpf_core_field_exists(rb->consumer_pos) && bpf_core_field_exists(rb->producer_pos) &&
                !READ_SCALAR(consumer, rb->consumer_pos) && !READ_SCALAR(producer, rb->producer_pos)) {
                __u64 used = producer - consumer;
                if (bpf_core_field_size(rb->producer_pos) == 4)
                    used = (__u32)used;
                if (used <= record->capacity) {
                    record->kind = BYTES;
                    record->count = used;
                }
            }
        }
        break;
    }
    }
}

SEC("iter/bpf_map")
int count_maps(struct bpf_iter__bpf_map *ctx)
{
    struct bpf_map *map = ctx->map;
    if (!map)
        return 0;
    if (ctx->meta->seq_num == 0)
        scanned_slots = 0;
    struct count_record record = {
        .id = BPF_CORE_READ(map, id),
        .type = BPF_CORE_READ(map, map_type),
        .capacity = BPF_CORE_READ(map, max_entries),
    };
    count_map(map, &record);
    bpf_seq_write(ctx->meta->seq, &record, sizeof(record));
    return 0;
}

struct ns_common { unsigned int inum; } CORE;
struct net { struct ns_common ns; } CORE;
typedef struct { struct net *net; } CORE possible_net_t;
struct net_device { char name[16]; int ifindex; possible_net_t nd_net; } CORE;
struct xdp_sock {
    struct net_device *dev;
    __u16 queue_id;
    bool zc;
    enum { XSK_READY = 0, XSK_BOUND = 1, XSK_UNBOUND = 2 } state;
} CORE;

struct xsk_request { __u32 map_id, limit; };
struct xsk_request xsk_request SEC(".data.xsk") = { .limit = 64 };

/* Kind 0 is coverage: key=scanned, ifindex=capacity, netns=read errors,
 * queue=rows, state=map ID. Kind 1 contains socket fields. */
struct xsk_record {
    __u32 kind, key, ifindex, netns, queue, state, mode, flags;
    char iface[16];
};
struct xsk_scan {
    struct seq_file *seq;
    __u64 base;
    __u32 stride, limit;
    struct xsk_record summary;
};

static long read_xsk(__u32 key, void *data)
{
    struct xsk_scan *scan = data;
    __u64 pointer = 0, device = 0;
    if (key >= MAP_SLOT_LIMIT)
        return 1;
    scan->summary.key++;
    if (bpf_probe_read_kernel(&pointer, scan->stride,
                             (void *)(scan->base + (__u64)key * scan->stride))) {
        scan->summary.netns++;
        return 0;
    }
    if (!pointer)
        return 0;
    if (scan->summary.queue >= scan->limit) {
        scan->summary.flags |= 4;
        return 1;
    }
    struct xdp_sock *xs = (void *)pointer;
    struct xsk_record row = {
        .kind = 1, .key = key, .queue = 0xffffffff, .state = 0xffffffff,
    };
    __u32 state = 0;
    if (bpf_core_field_exists(xs->state) &&
        !bpf_core_read(&state, sizeof(state), &xs->state))
        row.state = state;
    else
        row.flags |= 1;
    if (bpf_core_field_exists(xs->dev) && !READ_SCALAR(device, xs->dev)) {
        if (device) {
            struct net_device *dev = (void *)device;
            __u16 queue = 0;
            bool zc = false;
            if (bpf_core_read(&row.ifindex, sizeof(row.ifindex), &dev->ifindex) ||
                bpf_core_read_str(row.iface, sizeof(row.iface), &dev->name) < 0)
                row.flags |= 1;
            if (bpf_core_field_exists(xs->queue_id) &&
                !bpf_core_read(&queue, sizeof(queue), &xs->queue_id))
                row.queue = queue;
            else
                row.flags |= 1;
            if (bpf_core_field_exists(xs->zc) &&
                !bpf_core_read(&zc, sizeof(zc), &xs->zc))
                row.mode = zc ? 2 : 1;
            else
                row.flags |= 1;
            if (bpf_core_field_exists(dev->nd_net.net)) {
                __u64 network = 0;
                if (!READ_SCALAR(network, dev->nd_net.net) && network) {
                    struct net *net = (void *)network;
                    if (bpf_core_read(&row.netns, sizeof(row.netns), &net->ns.inum))
                        row.flags |= 1;
                } else
                    row.flags |= 1;
            }
        }
    } else {
        row.flags |= 1;
    }
    scan->summary.netns += row.flags != 0;
    scan->summary.queue++;
    bpf_seq_write(scan->seq, &row, sizeof(row));
    return 0;
}

SEC("iter/bpf_map")
int xsk_entries(struct bpf_iter__bpf_map *ctx)
{
    struct bpf_map *map = ctx->map;
    if (!map || BPF_CORE_READ(map, id) != xsk_request.map_id)
        return 0;
    struct xsk_map *xsk = (void *)map;
    struct xsk_scan scan = {
        .seq = ctx->meta->seq,
        .stride = bpf_core_field_size(map->elem_count),
        .limit = xsk_request.limit < 256 ? xsk_request.limit : 256,
        .summary = {
            .ifindex = BPF_CORE_READ(map, max_entries),
            .state = xsk_request.map_id,
        },
    };
    if (BPF_CORE_READ(map, map_type) != BPF_MAP_TYPE_XSKMAP ||
        !bpf_core_field_exists(xsk->xsk_map) ||
        (scan.stride != 4 && scan.stride != 8) || !scan.limit) {
        scan.summary.flags = 1;
    } else {
        __u64 base = (__u64)xsk + bpf_core_field_offset(xsk->xsk_map);
        if (bpf_probe_read_kernel(&scan.base, sizeof(scan.base), &base)) {
            scan.summary.flags = 1;
        } else {
            __u32 slots = scan.summary.ifindex < MAP_SLOT_LIMIT ? scan.summary.ifindex : MAP_SLOT_LIMIT;
            bpf_loop(slots, read_xsk, &scan, 0);
            if (scan.summary.key < scan.summary.ifindex && !(scan.summary.flags & 4))
                scan.summary.flags |= 2;
        }
    }
    bpf_seq_write(ctx->meta->seq, &scan.summary, sizeof(scan.summary));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
