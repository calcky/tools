/* SPDX-License-Identifier: GPL-2.0 */
#include <errno.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wsign-compare"
#include "../bpf/observe.bpf.c"
#pragma GCC diagnostic pop

_Static_assert(sizeof(struct iface) == 24, "interface map ABI size");
_Static_assert(offsetof(struct iface, device) == 16, "interface device ABI offset");
_Static_assert(sizeof(struct tx) == 64, "transmit map ABI size");
_Static_assert(offsetof(struct tx, attempting) == 56, "transmit attempt reference offset");
_Static_assert(offsetof(struct tx, free_seen) == 60, "transmit free marker offset");
_Static_assert(sizeof(struct tx_key) == 24, "transmit key ABI size");
_Static_assert(offsetof(struct tx_key, egress_generation) == 16, "transmit key generation offset");
_Static_assert(sizeof(struct config) == 24, "configuration map ABI size");
_Static_assert(sizeof(struct traffic) == 64, "compact traffic ABI size");
_Static_assert(sizeof(struct interval_timings) == 3216, "grouped timings ABI size");
_Static_assert(sizeof(struct period_key) == 40, "period key ABI size");

#define CPUS 4
#define ERROR_SLOTS (sizeof(*errors.max_entries) / sizeof(int))
_Static_assert(ERROR_SLOTS == 18, "health counter map ABI capacity");
#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s: %s\n", __FILE__, __LINE__, __func__, #condition); \
        exit(EXIT_FAILURE); \
    } \
} while (0)
#define EQ(actual, expected) do { \
    unsigned long long got = (actual), want = (expected); \
    if (got != want) { \
        fprintf(stderr, "%s:%d: %s: %s = %llu, expected %llu\n", \
                __FILE__, __LINE__, __func__, #actual, got, want); \
        exit(EXIT_FAILURE); \
    } \
} while (0)
#define MAP(symbol, is_array, is_percpu) { \
    .identity = &symbol, .key_size = sizeof(*symbol.key), \
    .value_size = sizeof(*symbol.value), \
    .capacity = sizeof(*symbol.max_entries) / sizeof(int), \
    .array = is_array, .percpu = is_percpu, \
}

static const struct mock_map specifications[] = {
    MAP(paths, false, false), MAP(periods, false, true),
    MAP(interfaces, false, false), MAP(origins, false, false),
    MAP(transmits, false, false), MAP(scope, true, false),
    MAP(empty, true, true), MAP(empty_traffic, true, true), MAP(errors, true, true),
    MAP(gauges, true, false), MAP(global, true, true),
    MAP(interval_writers, true, true),
    MAP(callstack, true, true),
    MAP(empty_interval_latency, true, true),
    MAP(interval_latency, false, true),
};
static struct mock_map maps[sizeof(specifications) / sizeof(specifications[0])];
static unsigned int cpu, cas_failures;
static __u64 clock_ns, lookup_cost_ns;
static __u64 *consume_before_cas;
static struct sk_buff *consume_on_cas;
static struct sk_buff *stop_after_origin, *expire_parent_after_origin;
static struct tx *parent_to_expire;
static struct sk_buff *admission_racer;
static bool stop_before_admission;
static struct net ns = { .ns.inum = 42 }, other_ns = { .ns.inum = 99 };
static struct net_device ingress = { .ifindex = 10, .nd_net.net = &ns };
static struct net_device egress = { .ifindex = 20, .nd_net.net = &ns };
static struct net_device branch = { .ifindex = 30, .nd_net.net = &ns };
static struct net_device foreign = { .ifindex = 20, .nd_net.net = &other_ns };

static void *allocate(size_t bytes) {
    void *result = calloc(1, bytes);
    CHECK(result);
    return result;
}

static struct mock_map *mock_map_for(void *identity) {
    for (size_t i = 0; i < sizeof(maps) / sizeof(maps[0]); i++)
        if (maps[i].identity == identity) return &maps[i];
    CHECK(!"unknown BPF map");
    return NULL;
}

static struct mock_entry *entry_for(struct mock_map *map, const void *key) {
    for (struct mock_entry *entry = map->entries; entry; entry = entry->next)
        if (entry->live && !memcmp(entry->key, key, map->key_size)) return entry;
    return NULL;
}

static void *bpf_map_lookup_elem(void *identity, const void *key) {
    clock_ns += lookup_cost_ns;
    struct mock_map *map = mock_map_for(identity);
    map->lookups++;
    CHECK(cpu < CPUS);
    if (map->array) {
        __u32 index;
        memcpy(&index, key, sizeof(index));
        if (index >= map->capacity) return NULL;
        size_t slot = map->percpu ? index * CPUS + cpu : index;
        return (char *)map->values + slot * map->value_size;
    }
    struct mock_entry *entry = entry_for(map, key);
    if (!entry) return NULL;
    return map->percpu ? (char *)entry->values + cpu * map->value_size : entry->values;
}

static long bpf_map_update_elem(void *identity, const void *key, const void *value, __u64 flags) {
    struct mock_map *map = mock_map_for(identity);
    if (flags > BPF_EXIST) return -EINVAL;
    if (map->array) {
        void *destination = bpf_map_lookup_elem(identity, key);
        if (!destination) return -E2BIG;
        if (flags == BPF_NOEXIST) return -EEXIST;
        memcpy(destination, value, map->value_size);
        return 0;
    }
    struct mock_entry *entry = entry_for(map, key);
    if (entry && flags == BPF_NOEXIST) return -EEXIST;
    if (!entry && flags == BPF_EXIST) return -ENOENT;
    if (map->reject_updates) {
        map->reject_updates--;
        return -ENOMEM;
    }
    if (!entry) {
        if (map->count >= map->capacity) return -E2BIG;
        entry = allocate(sizeof(*entry));
        entry->key = allocate(map->key_size);
        entry->values = allocate(map->value_size * (map->percpu ? CPUS : 1));
        memcpy(entry->key, key, map->key_size);
        entry->next = map->entries;
        map->entries = entry;
        entry->live = true;
        map->count++;
    }
    if (map->percpu)
        memcpy((char *)entry->values + cpu * map->value_size, value, map->value_size);
    else
        memcpy(entry->values, value, map->value_size);
    if (identity == &origins) {
        __u64 address;
        memcpy(&address, key, sizeof(address));
        if (address == (__u64)stop_after_origin) {
            stop_after_origin = NULL;
            __u32 zero = 0;
            struct config *cfg = bpf_map_lookup_elem(&scope, &zero);
            cfg->capacity = 0;
        }
        if (address == (__u64)expire_parent_after_origin) {
            expire_parent_after_origin = NULL;
            CHECK(parent_to_expire);
            parent_to_expire->start_ns = 0;
        }
    }
    return 0;
}

static long bpf_map_delete_elem(void *identity, const void *key) {
    struct mock_map *map = mock_map_for(identity);
    if (map->array) return -EINVAL;
    struct mock_entry *entry = entry_for(map, key);
    if (!entry) return -ENOENT;
    /* A BPF value remains addressable until the invocation ends. */
    entry->live = false;
    map->count--;
    return 0;
}

static __u64 bpf_ktime_get_ns(void) { return clock_ns; }

static void mock_before_add(void *field) {
    if (field != mock_map_for(&gauges)->values) return;
    if (stop_before_admission) {
        stop_before_admission = false;
        __u32 zero = 0;
        ((struct config *)bpf_map_lookup_elem(&scope, &zero))->capacity = 0;
    }
    if (admission_racer) {
        struct sk_buff *packet = admission_racer;
        admission_racer = NULL;
        unsigned int saved_cpu = cpu;
        cpu = 1;
        EQ(on_receive((void *)(__u64[]){(__u64)packet}), 0);
        cpu = saved_cpu;
    }
}

static __u64 mock_compare_swap(__u64 *field, __u64 old, __u64 next) {
    if (field == consume_before_cas) {
        /* Interleave CPU1's NAPI retirement at CPU0's completion claim. */
        consume_before_cas = NULL;
        unsigned int saved_cpu = cpu;
        cpu = 1;
        __u64 args[4] = { (__u64)consume_on_cas };
        EQ(on_consume((void *)args), 0);
        cpu = saved_cpu;
    }
    if (cas_failures) {
        cas_failures--;
        return old ^ 1;
    }
    __u64 observed = old;
    __atomic_compare_exchange_n(field, &observed, next, false,
                               __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    return observed;
}

static void dispose(void) {
    for (size_t i = 0; i < sizeof(maps) / sizeof(maps[0]); i++) {
        struct mock_entry *entry = maps[i].entries;
        while (entry) {
            struct mock_entry *next = entry->next;
            free(entry->key);
            free(entry->values);
            free(entry);
            entry = next;
        }
        free(maps[i].values);
    }
    memset(maps, 0, sizeof(maps));
}

static void reset(void) {
    dispose();
    memcpy(maps, specifications, sizeof(maps));
    cpu = 0;
    cas_failures = 0;
    consume_before_cas = NULL;
    consume_on_cas = NULL;
    stop_after_origin = expire_parent_after_origin = NULL;
    parent_to_expire = NULL;
    admission_racer = NULL;
    stop_before_admission = false;
    probe_reads = 0;
    lookup_cost_ns = 0;
    clock_ns = 100;
    for (size_t i = 0; i < sizeof(maps) / sizeof(maps[0]); i++)
        if (maps[i].array)
            maps[i].values = allocate(maps[i].capacity * maps[i].value_size *
                                      (maps[i].percpu ? CPUS : 1));
    __u32 zero = 0;
    struct config cfg = { .netns = 42, .capacity = 512, .interval_ns = 100, .started_ns = 100 };
    CHECK(!bpf_map_update_elem(&scope, &zero, &cfg, BPF_ANY));
    struct net_device *devices[] = { &ingress, &egress, &branch };
    for (size_t i = 0; i < 3; i++) {
        __u32 index = devices[i]->ifindex;
        struct iface value = { .generation = index * 10, .enabled = 1 };
        CHECK(!bpf_map_update_elem(&interfaces, &index, &value, BPF_NOEXIST));
    }
}

static struct meta *origin(struct sk_buff *skb) {
    __u64 address = (__u64)skb;
    return bpf_map_lookup_elem(&origins, &address);
}

static struct tx_key transmit_key(struct sk_buff *skb) {
    struct meta *m = origin(skb);
    CHECK(m);
    return (struct tx_key){ .skb = (__u64)skb, .birth = m->birth,
        .egress_generation = m->egress_generation };
}

static struct path path_key(__u32 kind, struct net_device *in, struct net_device *out) {
    return (struct path){ .kind = kind, .netns = 42,
        .ingress = in ? in->ifindex : 0, .egress = out ? out->ifindex : 0,
        .ingress_generation = in ? in->ifindex * 10 : 0,
        .egress_generation = out ? out->ifindex * 10 : 0 };
}

static struct stats *statistics(struct path key) {
    struct stats *s = bpf_map_lookup_elem(&paths, &key);
    CHECK(s);
    return s;
}

static struct traffic *period(struct path path, __u64 epoch) {
    struct period_key key = { .path = path, .epoch = epoch };
    struct traffic *s = bpf_map_lookup_elem(&periods, &key);
    CHECK(s);
    return s;
}

// Read lifetime or period counters without modifying production fallback maps.
static __u64 counted(const void *value, int index) {
    struct mock_map *path_map = mock_map_for(&paths), *period_map = mock_map_for(&periods);
    for (struct mock_entry *path = path_map->entries; path; path = path->next) {
        if (!path->live || path->values != value) continue;
        __u64 result = ((struct stats *)value)->counts[index];
        for (struct mock_entry *entry = period_map->entries; entry; entry = entry->next) {
            if (!entry->live || memcmp(entry->key, path->key, sizeof(struct path))) continue;
            for (int c = 0; c < CPUS; c++) {
                struct traffic *shard = (void *)((char *)entry->values + c * period_map->value_size);
                result += shard->counts[index];
            }
        }
        return result;
    }
    for (struct mock_entry *entry = period_map->entries; entry; entry = entry->next) {
        if (!entry->live) continue;
        for (int c = 0; c < CPUS; c++) {
            if ((char *)entry->values + c * period_map->value_size != value) continue;
            __u64 result = 0;
            for (int other = 0; other < CPUS; other++) {
                struct traffic *shard = (void *)((char *)entry->values + other * period_map->value_size);
                result += shard->counts[index];
            }
            return result;
        }
    }
    return ((const struct traffic *)value)->counts[index];
}

static __u64 gauge(void) {
    __u32 zero = 0;
    return *(__u64 *)bpf_map_lookup_elem(&gauges, &zero);
}

static __u64 errors_on(unsigned int on_cpu, __u32 index) {
    unsigned int saved = cpu;
    cpu = on_cpu;
    __u64 value = *(__u64 *)bpf_map_lookup_elem(&errors, &index);
    cpu = saved;
    return value;
}

static __u64 error_count(__u32 index) {
    __u64 sum = 0;
    for (unsigned int i = 0; i < CPUS; i++) sum += errors_on(i, index);
    return sum;
}

static struct traffic *global_stats(void) {
    static struct traffic total;
    memset(&total, 0, sizeof(total));
    struct mock_map *map = mock_map_for(&global);
    for (unsigned int i = 0; i < CPUS; i++) {
        struct traffic *value = (void *)((char *)map->values + i * map->value_size);
        for (int n = 0; n < 8; n++) total.counts[n] += value->counts[n];
    }
    return &total;
}

static struct attempts *attempt_stack(unsigned int on_cpu) {
    unsigned int saved = cpu;
    cpu = on_cpu;
    __u32 zero = 0;
    struct attempts *value = bpf_map_lookup_elem(&callstack, &zero);
    cpu = saved;
    return value;
}

static void receive_at(struct sk_buff *skb, __u64 now) {
    clock_ns = now;
    __u64 args[4] = { (__u64)skb };
    EQ(on_receive((void *)args), 0);
}

static void receive_routed_at(struct sk_buff *skb, __u64 now) {
    receive_at(skb, now);
    EQ(on_route4(skb), 0);
}

static void queue_at(struct sk_buff *skb, struct net_device *dev, __u64 now) {
    clock_ns = now;
    skb->dev = dev;
    __u64 args[4] = { (__u64)skb };
    EQ(on_queue((void *)args), 0);
}

static void attempt_at(struct sk_buff *skb, struct net_device *dev, __u64 now) {
    clock_ns = now;
    __u64 args[4] = { (__u64)skb, (__u64)dev };
    EQ(on_attempt((void *)args), 0);
}

static void result_at(struct sk_buff *skb, struct net_device *dev, int result, __u64 now) {
    clock_ns = now;
    __u64 args[4] = { (__u64)skb, result, (__u64)dev };
    EQ(on_result((void *)args), 0);
}

static void complete_at(struct sk_buff *skb, struct net_device *dev, __u64 now) {
    attempt_at(skb, dev, now);
    result_at(skb, dev, 0, now + 1);
}

static void collect_at(__u64 now) {
    clock_ns = now;
    EQ(cleanup(NULL), 0);
}

static void no_tracking(void) {
    EQ(gauge(), 0);
    EQ(mock_map_for(&origins)->count, 0);
    EQ(mock_map_for(&transmits)->count, 0);
    struct mock_map *writers = mock_map_for(&interval_writers);
    for (unsigned int i = 0; i < CPUS; i++) {
        struct interval_writer *writer = (void *)((char *)writers->values + i * writers->value_size);
        EQ(writer->depth, 0);
    }
}

static void no_errors(void) {
    for (__u32 i = 0; i < ERROR_SLOTS; i++) EQ(error_count(i), 0);
}

// Lifetime distributions are the disjoint sum of intervals and overflow data.
static struct latency combined_latency(struct latency *l) {
    struct latency result = *l;
    struct mock_map *paths_map = mock_map_for(&paths);
    for (struct mock_entry *path = paths_map->entries; path; path = path->next) {
        if (!path->live) continue;
        struct stats *stats = path->values;
        for (int stage = 0; stage < 3; stage++) {
            if (l != &stats->stages[stage]) continue;
            struct mock_map *shard_map = mock_map_for(&interval_latency);
            for (struct mock_entry *shard = shard_map->entries; shard; shard = shard->next) {
                if (!shard->live) continue;
                struct period_key *key = shard->key;
                if (memcmp(&key->path, path->key, sizeof(struct path))) continue;
                struct interval_timings *values = shard->values;
                for (unsigned int cpu_index = 0; cpu_index < CPUS; cpu_index++) {
                    struct interval_timings *group = (void *)((char *)values +
                        cpu_index * shard_map->value_size);
                    struct interval_latency *value = &group->stages[stage];
                    result.samples += value->samples;
                    result.sum += value->sum;
                    if (value->min && (!result.min || value->min < result.min)) result.min = value->min;
                    if (value->max > result.max) result.max = value->max;
                    for (int bin = 0; bin < BINS; bin++) result.bins[bin] += value->bins[bin];
                }
            }
            return result;
        }
    }
    return result;
}

static void latency(struct latency *l, __u64 samples, __u64 sum, __u64 min, __u64 max) {
    struct latency observed = combined_latency(l);
    l = &observed;
    EQ(l->samples, samples);
    EQ(l->sum, sum);
    EQ(l->min, samples ? min + 1 : 0);
    EQ(l->max, max);
    __u64 bins = 0;
    for (int i = 0; i < BINS; i++) bins += l->bins[i];
    EQ(bins, samples);
}

static void latency_period(struct path path, __u64 epoch, int stage,
        __u64 samples, __u64 sum, __u64 min, __u64 max) {
    struct latency observed = {};
    struct mock_map *shard_map = mock_map_for(&interval_latency);
    for (struct mock_entry *shard = shard_map->entries; shard; shard = shard->next) {
        if (!shard->live) continue;
        struct period_key *key = shard->key;
        if (key->epoch != epoch ||
            memcmp(&key->path, &path, sizeof(path))) continue;
        struct interval_timings *values = shard->values;
        for (unsigned int cpu_index = 0; cpu_index < CPUS; cpu_index++) {
            struct interval_timings *group = (void *)((char *)values +
                cpu_index * shard_map->value_size);
            struct interval_latency *value = &group->stages[stage];
            observed.samples += value->samples;
            observed.sum += value->sum;
            if (value->min && (!observed.min || value->min < observed.min)) observed.min = value->min;
            if (value->max > observed.max) observed.max = value->max;
            for (int bin = 0; bin < BINS; bin++) observed.bins[bin] += value->bins[bin];
        }
    }
    EQ(observed.samples, samples);
    EQ(observed.sum, sum);
    EQ(observed.min, samples ? min + 1 : 0);
    EQ(observed.max, max);
}

static void mock_map_semantics(void) {
    reset();
    __u64 key = 17;
    struct meta initial = { .birth = 123 };
    CHECK(bpf_map_update_elem(&origins, &key, &initial, BPF_EXIST) == -ENOENT);
    CHECK(!bpf_map_update_elem(&origins, &key, &initial, BPF_NOEXIST));
    initial.birth = 456;
    EQ(((struct meta *)bpf_map_lookup_elem(&origins, &key))->birth, 123);
    CHECK(bpf_map_update_elem(&origins, &key, &initial, BPF_NOEXIST) == -EEXIST);
    CHECK(!bpf_map_update_elem(&origins, &key, &initial, BPF_EXIST));
    EQ(((struct meta *)bpf_map_lookup_elem(&origins, &key))->birth, 456);
    CHECK(!bpf_map_delete_elem(&origins, &key));
    CHECK(!bpf_map_lookup_elem(&origins, &key));
    CHECK(bpf_map_delete_elem(&origins, &key) == -ENOENT);
    __u32 zero = 0, bad_index = ERROR_SLOTS;
    CHECK(!bpf_map_lookup_elem(&errors, &bad_index));
    EQ(mock_map_for(&errors)->capacity, 18);
    CHECK(bpf_map_delete_elem(&scope, &zero) == -EINVAL);
    CHECK(bpf_map_update_elem(&scope, &zero, configuration(), BPF_NOEXIST) == -EEXIST);
    error(3);
    cpu = 1;
    EQ(errors_on(1, 3), 0);
    error(3);
    EQ(errors_on(0, 3), 1);
    EQ(errors_on(1, 3), 1);
    EQ(error_count(3), 2);
    EQ(mock_map_for(&paths)->capacity, 4096);
    EQ(mock_map_for(&periods)->capacity, 16384);
    EQ(mock_map_for(&origins)->capacity, 262144);
    EQ(mock_map_for(&transmits)->capacity, 262144);
    no_tracking();
}

static void receive_input(void) {
    for (int ipv6 = 0; ipv6 < 2; ipv6++) {
        reset();
        struct sk_buff skb = { .dev = &ingress, .len = 64 };
        receive_at(&skb, 100);
        receive_at(&skb, 105);
        EQ(gauge(), 1);
        EQ(global_stats()->counts[0], 1);
        EQ(global_stats()->counts[1], 64);
        EQ(origin(&skb)->birth, 100);
        skb.len = 60;
        clock_ns = 120;
        if (ipv6) EQ(on_input6(&ns, &skb), 0);
        else EQ(on_input4(&ns, &skb), 0);
        EQ(on_input4(&ns, &skb), 0);
        EQ(on_input6(&ns, &skb), 0);
        struct stats *s = statistics(path_key(1, &ingress, NULL));
        EQ(counted(s, 0), 1); EQ(counted(s, 1), 64);
        EQ(counted(s, 2), 1); EQ(counted(s, 3), 60);
        latency(&s->stages[0], 1, 20, 20, 20);
        latency(&s->stages[1], 0, 0, 0, 0);
        latency(&s->stages[2], 1, 20, 20, 20);
        EQ(global_stats()->counts[2], 1);
        EQ(global_stats()->counts[3], 60);
        EQ(on_free(&skb), 0);
        EQ(on_free(&skb), 0);
        no_tracking(); no_errors();
    }
}

static void input_namespace_isolation(void) {
    for (int ipv6 = 0; ipv6 < 2; ipv6++) {
        reset();
        struct sk_buff skb = { .dev = &ingress, .len = 64 };
        receive_at(&skb, 100);
        skb.dev = &foreign;
        clock_ns = 110;
        EQ(on_input4(&other_ns, &skb), 0);
        EQ(on_input6(&other_ns, &skb), 0);
        EQ(origin(&skb)->delivered, 0);
        EQ(global_stats()->counts[0], 1); EQ(global_stats()->counts[1], 64);
        EQ(global_stats()->counts[2], 0); EQ(global_stats()->counts[3], 0);
        EQ(mock_map_for(&paths)->count, 0); EQ(mock_map_for(&periods)->count, 0);
        EQ(gauge(), 1); no_errors();
        skb.dev = &ingress;
        clock_ns = 130;
        if (ipv6) EQ(on_input6(&ns, &skb), 0);
        else EQ(on_input4(&ns, &skb), 0);
        struct stats *s = statistics(path_key(1, &ingress, NULL));
        EQ(counted(s, 0), 1); EQ(counted(s, 2), 1);
        latency(&s->stages[2], 1, 30, 30, 30);
        clock_ns = 140;
        EQ(on_input4(&other_ns, &skb), 0);
        EQ(on_input6(&other_ns, &skb), 0);
        EQ(counted(s, 2), 1); EQ(global_stats()->counts[2], 1);
        EQ(on_free(&skb), 0); no_tracking(); no_errors();
    }
}

static void selection_and_generations(void) {
    reset();
    struct sk_buff skb = { .dev = &foreign, .len = 64 };
    receive_at(&skb, 100);
    CHECK(!origin(&skb));
    __u32 index = ingress.ifindex;
    struct iface *iface = bpf_map_lookup_elem(&interfaces, &index);
    iface->enabled = 0;
    skb.dev = &ingress;
    receive_at(&skb, 101);
    CHECK(!origin(&skb));
    iface->enabled = 1;
    configuration()->netns = 0;
    receive_at(&skb, 102);
    CHECK(!origin(&skb));
    configuration()->netns = 42;
    receive_at(&skb, 103);
    iface->generation++;
    EQ(on_input4(&ns, &skb), 0);
    queue_at(&skb, &egress, 120);
    EQ(error_count(11), 2);
    EQ(mock_map_for(&paths)->count, 0);
    collect_at(103 + TIMEOUT_NS);
    no_tracking();
    reset();
    skb = (struct sk_buff){ .dev = &ingress, .len = 64 };
    receive_routed_at(&skb, 100);
    queue_at(&skb, &egress, 120);
    struct path old_key = path_key(3, &ingress, &egress);
    struct stats *old = statistics(old_key);
    index = egress.ifindex;
    iface = bpf_map_lookup_elem(&interfaces, &index);
    attempt_at(&skb, &egress, 130);
    iface->generation++;
    result_at(&skb, &egress, 0, 140);
    EQ(counted(old, 2), 1);
    EQ(on_free(&skb), 0);
    skb.dev = &ingress;
    receive_routed_at(&skb, 150);
    queue_at(&skb, &egress, 160);
    struct path new_key = old_key;
    new_key.egress_generation++;
    complete_at(&skb, &egress, 170);
    EQ(counted(statistics(new_key), 2), 1);
    EQ(mock_map_for(&paths)->count, 2);
    EQ(on_free(&skb), 0);
    no_tracking(); no_errors();
}

static void local_output_dst(void) {
    for (int ipv6 = 0; ipv6 < 2; ipv6++) {
        for (int foreign_dev = 0; foreign_dev < 2; foreign_dev++) {
            reset();
            struct dst_entry dst = { .dev = &egress };
            struct sk_buff skb = { .dev = foreign_dev ? &foreign : NULL,
                .len = 100, ._skb_refdst = (__u64)&dst | 3 };
            EQ(on_output4(&other_ns, NULL, &skb), 0);
            CHECK(!origin(&skb));
            if (ipv6) EQ(on_output6(&ns, NULL, &skb), 0);
            else EQ(on_output4(&ns, NULL, &skb), 0);
            CHECK(origin(&skb));
            EQ(origin(&skb)->local, 1);
            EQ(origin(&skb)->ingress, 0);
            EQ(on_input4(&ns, &skb), 0);
            EQ(on_input6(&ns, &skb), 0);
            EQ(mock_map_for(&paths)->count, 0);
            queue_at(&skb, &branch, 150);
            complete_at(&skb, &branch, 175);
            struct stats *s = statistics(path_key(2, NULL, &branch));
            EQ(counted(s, 0), 1); EQ(counted(s, 1), 100);
            EQ(counted(s, 2), 1); EQ(counted(s, 3), 100);
            latency(&s->stages[0], 1, 50, 50, 50);
            latency(&s->stages[1], 1, 25, 25, 25);
            latency(&s->stages[2], 1, 75, 75, 75);
            EQ(on_free(&skb), 0);
            no_tracking(); no_errors();
        }
    }
    reset();
    struct dst_entry dst = { .dev = &foreign };
    struct sk_buff skb = { ._skb_refdst = (__u64)&dst | 1, .len = 64 };
    EQ(on_output4(&ns, NULL, &skb), 0);
    skb._skb_refdst = 0;
    EQ(on_output6(&ns, NULL, &skb), 0);
    CHECK(!origin(&skb));
    no_tracking(); no_errors();
}

static void unregister_and_ifindex_reuse(void) {
    reset();
    struct net_device replacement = ingress;
    __u32 index = ingress.ifindex;
    struct iface *iface = bpf_map_lookup_elem(&interfaces, &index);
    EQ(iface->device, 0);
    cas_failures = 1;
    EQ(device_generation(&ingress, configuration()), 0);
    EQ(error_count(11), 1); EQ(iface->device, 0);
    EQ(device_generation(&ingress, configuration()), 100);
    EQ(iface->device, (__u64)&ingress);
    struct sk_buff completed = { .dev = &ingress, .len = 64 };
    struct sk_buff outstanding = completed, new_skb = completed;
    receive_at(&completed, 100);
    clock_ns = 105;
    EQ(on_input4(&ns, &completed), 0); EQ(on_free(&completed), 0);
    struct path old_input = path_key(1, &ingress, NULL);
    struct stats saved = *statistics(old_input);
    receive_at(&outstanding, 110);
    new_skb.dev = &replacement;
    receive_at(&new_skb, 115);
    CHECK(!origin(&new_skb)); EQ(error_count(11), 2);
    EQ(on_unregister(&foreign), 0); EQ(iface->enabled, 1);
    EQ(on_unregister(&replacement), 0); EQ(iface->enabled, 1);
    EQ(on_unregister(&ingress), 0); EQ(iface->enabled, 0);
    receive_at(&new_skb, 125);
    CHECK(!origin(&new_skb)); EQ(error_count(11), 2);
    EQ(on_input4(&ns, &outstanding), 0);
    EQ(error_count(11), 3);
    CHECK(!bpf_map_delete_elem(&interfaces, &index));
    struct iface rebuilt = { .generation = 101, .enabled = 1 };
    CHECK(!bpf_map_update_elem(&interfaces, &index, &rebuilt, BPF_NOEXIST));
    iface = bpf_map_lookup_elem(&interfaces, &index);
    EQ(iface->device, 0);
    receive_at(&new_skb, 130);
    CHECK(origin(&new_skb)); EQ(origin(&new_skb)->ingress_generation, 101);
    EQ(iface->device, (__u64)&replacement);
    EQ(on_unregister(&ingress), 0); EQ(iface->enabled, 1);
    EQ(on_input6(&ns, &outstanding), 0);
    queue_at(&outstanding, &egress, 135);
    EQ(error_count(11), 5);
    clock_ns = 140;
    EQ(on_input6(&ns, &new_skb), 0);
    struct path new_input = old_input;
    new_input.ingress_generation = 101;
    EQ(counted(statistics(new_input), 2), 1);
    CHECK(!memcmp(statistics(old_input), &saved, sizeof(saved)));
    EQ(on_free(&new_skb), 0);
    new_skb = (struct sk_buff){ .dev = &replacement, .len = 128 };
    receive_routed_at(&new_skb, 150); queue_at(&new_skb, &egress, 160);
    struct path new_forward = path_key(3, &ingress, &egress);
    new_forward.ingress_generation = 101;
    attempt_at(&new_skb, &egress, 165);
    EQ(on_unregister(&egress), 0);
    __u32 out_index = egress.ifindex;
    EQ(((struct iface *)bpf_map_lookup_elem(&interfaces, &out_index))->enabled, 0);
    result_at(&new_skb, &egress, 0, 170);
    EQ(counted(statistics(new_forward), 2), 1);
    EQ(statistics(new_forward)->pending, 0);
    EQ(on_free(&new_skb), 0);
    collect_at(110 + TIMEOUT_NS);
    EQ(error_count(5), 1); EQ(error_count(11), 5);
    no_tracking();
    reset();
    iface = bpf_map_lookup_elem(&interfaces, &index);
    EQ(iface->device, 0);
    EQ(on_unregister(&ingress), 0); EQ(iface->enabled, 0);
    new_skb = (struct sk_buff){ .dev = &replacement, .len = 64 };
    receive_at(&new_skb, 100);
    CHECK(!origin(&new_skb)); no_tracking(); no_errors();
}

static void egress_generation_isolation(void) {
    reset();
    struct net_device recreated = egress;
    struct sk_buff skb = { .dev = &ingress, .len = 64 };
    receive_routed_at(&skb, 100); queue_at(&skb, &egress, 120);
    struct tx_key old_tx = transmit_key(&skb);
    EQ(old_tx.egress_generation, 200);
    struct path old_path = path_key(3, &ingress, &egress);
    struct path new_path = old_path;
    new_path.egress_generation = 201;
    struct stats *old = statistics(old_path), saved = *old;
    EQ(on_unregister(&egress), 0);
    __u32 index = egress.ifindex;
    CHECK(!bpf_map_delete_elem(&interfaces, &index));
    struct iface rebuilt = { .generation = 201, .enabled = 1 };
    CHECK(!bpf_map_update_elem(&interfaces, &index, &rebuilt, BPF_NOEXIST));
    skb.dev = &recreated;
    attempt_at(&skb, &recreated, 150);
    EQ(attempt_stack(0)->frames[0].key.egress_generation, 201);
    EQ(attempt_stack(0)->frames[0].active, 0);
    result_at(&skb, &recreated, 0, 160);
    CHECK(bpf_map_lookup_elem(&transmits, &old_tx));
    CHECK(!memcmp(old, &saved, sizeof(saved)));
    EQ(global_stats()->counts[2], 0); EQ(gauge(), 2); no_errors();
    queue_at(&skb, &recreated, 170);
    struct tx_key new_tx = transmit_key(&skb);
    EQ(new_tx.skb, old_tx.skb); EQ(new_tx.birth, old_tx.birth);
    EQ(new_tx.egress_generation, 201);
    EQ(mock_map_for(&transmits)->count, 2);
    struct stats *current = statistics(new_path);
    EQ(old->pending, 1); EQ(current->pending, 1);
    struct sk_buff child = skb;
    clock_ns = 175;
    EQ(on_clone(&skb, 0, &child), 0);
    struct tx_key child_tx = transmit_key(&child);
    EQ(child_tx.egress_generation, 201);
    CHECK(bpf_map_lookup_elem(&transmits, &child_tx));
    EQ(current->pending, 2); EQ(old->pending, 1);
    complete_at(&skb, &recreated, 180); complete_at(&child, &recreated, 185);
    EQ(counted(current, 0), 1); EQ(counted(current, 2), 2);
    EQ(current->pending, 0);
    latency(&current->stages[0], 2, 140, 70, 70);
    latency(&current->stages[1], 2, 25, 10, 15);
    latency(&current->stages[2], 2, 165, 80, 85);
    CHECK(!memcmp(old, &saved, sizeof(saved)));
    EQ(on_release(&skb), 0); EQ(on_release(&child), 0);
    EQ(gauge(), 1); EQ(old->pending, 1);
    collect_at(100 + TIMEOUT_NS);
    EQ(old->pending, 0); EQ(counted(old, 2), 0); EQ(counted(old, 7), 0);
    latency(&old->stages[2], 0, 0, 0, 0);
    EQ(global_stats()->counts[0], 1); EQ(global_stats()->counts[2], 2);
    EQ(error_count(5), 1); EQ(error_count(4), 0); EQ(error_count(6), 0);
    no_tracking();

    reset();
    skb = (struct sk_buff){ .dev = &ingress, .len = 64 };
    receive_routed_at(&skb, 100); queue_at(&skb, &egress, 120);
    old_tx = transmit_key(&skb);
    attempt_at(&skb, &egress, 130);
    EQ(attempt_stack(0)->frames[0].key.egress_generation, 200);
    cpu = 1;
    EQ(on_unregister(&egress), 0);
    CHECK(!bpf_map_delete_elem(&interfaces, &index));
    CHECK(!bpf_map_update_elem(&interfaces, &index, &rebuilt, BPF_NOEXIST));
    __u64 consume_args[4] = { (__u64)&skb };
    EQ(on_consume((void *)consume_args), 0);
    struct tx *old_value = bpf_map_lookup_elem(&transmits, &old_tx);
    CHECK(old_value); EQ(old_value->attempting, 1); EQ(old_value->free_seen, 1);
    CHECK(!origin(&skb)); EQ(gauge(), 1);
    skb = (struct sk_buff){ .dev = &ingress, .len = 256 };
    receive_routed_at(&skb, 150); queue_at(&skb, &recreated, 160);
    new_tx = transmit_key(&skb);
    EQ(new_tx.birth, 150);
    EQ(new_tx.egress_generation, 201);
    cpu = 0;
    result_at(&skb, &egress, 0, 170);
    CHECK(!bpf_map_lookup_elem(&transmits, &old_tx));
    CHECK(bpf_map_lookup_elem(&transmits, &new_tx));
    old = statistics(old_path); current = statistics(new_path);
    EQ(counted(old, 2), 1); EQ(counted(old, 3), 64); EQ(old->pending, 0);
    EQ(counted(current, 2), 0); EQ(current->pending, 1);
    latency(&old->stages[2], 1, 30, 30, 30);
    cpu = 2;
    complete_at(&skb, &recreated, 180);
    EQ(counted(current, 2), 1); EQ(counted(current, 3), 256); EQ(current->pending, 0);
    latency(&current->stages[2], 1, 30, 30, 30);
    EQ(on_release(&skb), 0);
    EQ(global_stats()->counts[2], 2); EQ(global_stats()->counts[3], 320);
    no_tracking(); no_errors();
}

static void forward_nat_identity(void) {
    reset();
    struct { struct sk_buff skb; __u32 source, destination; __u16 sport, dport; } packet = {
        .skb = { .dev = &ingress, .len = 96, .protocol = 0x0008 },
        .source = 0xc0000201, .destination = 0xc6336402, .sport = 1234, .dport = 443,
    };
    receive_at(&packet.skb, 100);
    EQ(on_route4(&packet.skb), 0);
    EQ(on_route6(&packet.skb), 0);
    packet.source = 0xcb007107; packet.destination = 0x0a000001;
    packet.sport = 50000; packet.dport = 8443;
    packet.skb.len = 80;
    queue_at(&packet.skb, &egress, 120);
    struct tx_key key = transmit_key(&packet.skb);
    EQ(key.birth, 100);
    complete_at(&packet.skb, &egress, 150);
    struct stats *s = statistics(path_key(3, &ingress, &egress));
    EQ(mock_map_for(&paths)->count, 1);
    EQ(counted(s, 0), 1); EQ(counted(s, 1), 96);
    EQ(counted(s, 2), 1); EQ(counted(s, 3), 80); EQ(counted(s, 4), 1);
    EQ(counted(s, 5), 0); EQ(counted(s, 6), 0); EQ(s->pending, 0);
    latency(&s->stages[0], 1, 20, 20, 20);
    latency(&s->stages[1], 1, 30, 30, 30);
    latency(&s->stages[2], 1, 50, 50, 50);
    CHECK(!bpf_map_lookup_elem(&transmits, &key));
    EQ(on_free(&packet.skb), 0);
    no_tracking(); no_errors();
}

static void unclassified_forward_keeps_counts_and_latency(void) {
    reset();
    struct sk_buff skb = { .dev = &ingress, .len = 96 };
    receive_at(&skb, 100);
    cpu = 1;
    queue_at(&skb, &egress, 190);
    struct tx_key txkey = transmit_key(&skb);
    struct tx *t = bpf_map_lookup_elem(&transmits, &txkey);
    CHECK(t); EQ(t->flags, 0);
    cpu = 2;
    attempt_at(&skb, &egress, 195);
    result_at(&skb, &egress, 16, 196);
    EQ(error_count(16), 0); EQ(errors_on(2, 9), 1);
    EQ(global_stats()->counts[2], 0); EQ(t->attempting, 0);
    skb.len = 80;
    cpu = 3;
    attempt_at(&skb, &egress, 205);
    result_at(&skb, &egress, 0, 210);
    struct path key = path_key(3, &ingress, &egress);
    struct stats *s = statistics(key);
    struct traffic *before = period(key, 0), *after = period(key, 1);
    EQ(counted(s, 0), 1); EQ(counted(s, 1), 96);
    EQ(counted(s, 2), 1); EQ(counted(s, 3), 80); EQ(counted(s, 7), 0);
    EQ(s->pending, 0);
    EQ(counted(before, 0), 1); EQ(counted(before, 1), 96);
    EQ(counted(before, 2), 0); latency_period(key, 0, 2, 0, 0, 0, 0);
    EQ(counted(after, 0), 0); EQ(counted(after, 2), 1); EQ(counted(after, 3), 80);
    for (int stage = 0; stage < 3; stage++) {
        __u64 elapsed[] = {90, 15, 105};
        latency(&s->stages[stage], 1, elapsed[stage], elapsed[stage], elapsed[stage]);
        latency_period(key, 1, stage, 1, elapsed[stage], elapsed[stage], elapsed[stage]);
    }
    for (int i = 4; i < 7; i++) {
        EQ(counted(s, i), 0); EQ(counted(before, i), 0); EQ(counted(after, i), 0);
        EQ(global_stats()->counts[i], 0);
    }
    EQ(global_stats()->counts[0], 1); EQ(global_stats()->counts[1], 96);
    EQ(global_stats()->counts[2], 1); EQ(global_stats()->counts[3], 80);
    EQ(global_stats()->counts[7], 0);
    CHECK(!bpf_map_lookup_elem(&transmits, &txkey));
    EQ(on_release(&skb), 0); no_tracking();
    for (unsigned int on_cpu = 0; on_cpu < CPUS; on_cpu++)
        for (__u32 index = 0; index < ERROR_SLOTS; index++)
            EQ(errors_on(on_cpu, index),
               (on_cpu == 2 && index == 9) || (on_cpu == 3 && index == 16) ? 1 : 0);
}

static void bridge_cb_fallback_without_hooks(void) {
    for (int routed = 0; routed < 2; routed++) {
        for (int cloned = 0; cloned < 2; cloned++) {
            reset();
            struct net_device master = {
                .ifindex = 40, .nd_net.net = &ns, .priv_flags = 2UL,
            };
            __u32 index = master.ifindex;
            struct iface inventory = { .generation = 400, .enabled = 0 };
            CHECK(!bpf_map_update_elem(&interfaces, &index, &inventory, BPF_NOEXIST));
            struct sk_buff source = { .dev = &ingress, .len = 128 };
            struct net_device *master_pointer = &master;
            memcpy(source.cb, &master_pointer, sizeof(master_pointer));
            receive_at(&source, 100);
            if (routed) EQ(on_route4(&source), 0);
            EQ(origin(&source)->flags, routed ? ROUTE : 0);
            struct sk_buff copy = source;
            if (cloned) {
                clock_ns = 110;
                EQ(on_clone(&source, 0, &copy), 0);
                EQ(origin(&copy)->flags, routed ? ROUTE : 0);
            }
            /* No bridge hook is invoked; only the CB identifies forwarding. */
            queue_at(&source, &egress, 120);
            EQ(origin(&source)->flags, BRIDGE | (routed ? ROUTE : 0));
            struct tx_key txkey = transmit_key(&source);
            struct tx *t = bpf_map_lookup_elem(&transmits, &txkey);
            CHECK(t); EQ(t->flags, BRIDGE | (routed ? ROUTE : 0));
            if (cloned) queue_at(&copy, &egress, 130);
            complete_at(&source, &egress, 140);
            if (cloned) complete_at(&copy, &egress, 150);
            struct stats *s = statistics(path_key(3, &ingress, &egress));
            __u64 completed = cloned ? 2 : 1;
            EQ(counted(s, 0), completed); EQ(counted(s, 1), completed * 128);
            EQ(counted(s, 2), completed); EQ(counted(s, 3), completed * 128);
            EQ(counted(s, 4), 0); EQ(counted(s, 5), routed ? 0 : completed);
            EQ(counted(s, 6), routed ? completed : 0); EQ(s->pending, 0);
            EQ(global_stats()->counts[0], 1); EQ(global_stats()->counts[1], 128);
            EQ(global_stats()->counts[2], completed);
            EQ(global_stats()->counts[4], 0);
            EQ(global_stats()->counts[5], routed ? 0 : completed);
            EQ(global_stats()->counts[6], routed ? completed : 0);
            latency(&s->stages[2], completed, cloned ? 90 : 40, 40, cloned ? 50 : 40);
            struct iface *record = bpf_map_lookup_elem(&interfaces, &index);
            EQ(record->enabled, 0); EQ(record->device, 0);
            EQ(on_release(&source), 0);
            if (cloned) EQ(on_release(&copy), 0);
            no_tracking(); no_errors();
        }
    }
}

static void bridge_cb_rejects_route_metadata(void) {
    for (int invalid = 0; invalid < 5; invalid++) {
        reset();
        struct net_device master = {
            .ifindex = 40, .nd_net.net = &ns, .priv_flags = 2UL,
        };
        __u32 index = master.ifindex;
        struct iface inventory = { .generation = 400, .enabled = 0 };
        if (invalid != 3)
            CHECK(!bpf_map_update_elem(&interfaces, &index, &inventory, BPF_NOEXIST));
        if (invalid == 1) master.priv_flags = 1UL | 4UL;
        if (invalid == 2) master.nd_net.net = &other_ns;
        struct sk_buff skb = { .dev = &ingress, .len = 64 };
        struct net_device *cb_pointer = invalid == 0 ? NULL : &master;
        if (invalid == 4) cb_pointer = (void *)(uintptr_t)0x100;
        memcpy(skb.cb, &cb_pointer, sizeof(cb_pointer));
        receive_at(&skb, 100);
        EQ(on_route4(&skb), 0);
        queue_at(&skb, &egress, 120);
        EQ(origin(&skb)->flags, ROUTE);
        complete_at(&skb, &egress, 140);
        struct stats *s = statistics(path_key(3, &ingress, &egress));
        EQ(counted(s, 2), 1); EQ(counted(s, 4), 1);
        EQ(counted(s, 5), 0); EQ(counted(s, 6), 0);
        EQ(global_stats()->counts[4], 1);
        EQ(global_stats()->counts[5], 0); EQ(global_stats()->counts[6], 0);
        latency(&s->stages[2], 1, 40, 40, 40);
        EQ(on_release(&skb), 0); no_tracking(); no_errors();
    }
}

static void bridge_cb_receive_is_not_forwarding(void) {
    for (int ipv6 = 0; ipv6 < 2; ipv6++) {
        reset();
        struct net_device master = {
            .ifindex = 40, .nd_net.net = &ns, .priv_flags = 2UL,
        };
        __u32 index = master.ifindex;
        struct iface inventory = { .generation = 400, .enabled = 0 };
        CHECK(!bpf_map_update_elem(&interfaces, &index, &inventory, BPF_NOEXIST));
        struct sk_buff skb = { .dev = &ingress, .len = 64 };
        struct net_device *master_pointer = &master;
        memcpy(skb.cb, &master_pointer, sizeof(master_pointer));
        receive_at(&skb, 100);
        EQ(origin(&skb)->flags, 0);
        EQ(mock_map_for(&paths)->count, 0); EQ(mock_map_for(&transmits)->count, 0);
        EQ(global_stats()->counts[0], 1); EQ(global_stats()->counts[2], 0);
        clock_ns = 120;
        if (ipv6) EQ(on_input6(&ns, &skb), 0);
        else EQ(on_input4(&ns, &skb), 0);
        EQ(origin(&skb)->flags, 0);
        struct stats *s = statistics(path_key(1, &ingress, NULL));
        EQ(counted(s, 0), 1); EQ(counted(s, 2), 1);
        EQ(counted(s, 4) + counted(s, 5) + counted(s, 6), 0);
        EQ(global_stats()->counts[4] + global_stats()->counts[5] + global_stats()->counts[6], 0);
        latency(&s->stages[2], 1, 20, 20, 20);
        EQ(on_release(&skb), 0); no_tracking(); no_errors();
    }
}

static void routing_from_bridge_master_is_combined(void) {
    for (int ipv6 = 0; ipv6 < 2; ipv6++) {
        reset();
        struct net_device master = {
            .ifindex = 40, .nd_net.net = &ns, .priv_flags = 2UL,
        };
        __u32 index = master.ifindex;
        struct iface inventory = { .generation = 400, .enabled = 0 };
        CHECK(!bpf_map_update_elem(&interfaces, &index, &inventory, BPF_NOEXIST));
        struct sk_buff skb = { .dev = &ingress, .len = 64 };
        receive_at(&skb, 100);
        EQ(on_route4(&skb), 0);
        EQ(origin(&skb)->flags, ROUTE);
        /* br_pass_frame_up changes dev to the actual master before routing. */
        skb.dev = &master;
        if (ipv6) EQ(on_route6(&skb), 0);
        else EQ(on_route4(&skb), 0);
        EQ(origin(&skb)->flags, ROUTE | BRIDGE);
        EQ(origin(&skb)->ingress, ingress.ifindex);
        EQ(origin(&skb)->ingress_generation, 100);
        queue_at(&skb, &egress, 120);
        complete_at(&skb, &egress, 140);
        struct stats *s = statistics(path_key(3, &ingress, &egress));
        EQ(counted(s, 0), 1); EQ(counted(s, 2), 1);
        EQ(counted(s, 4), 0); EQ(counted(s, 5), 0); EQ(counted(s, 6), 1);
        EQ(global_stats()->counts[4], 0); EQ(global_stats()->counts[5], 0);
        EQ(global_stats()->counts[6], 1);
        latency(&s->stages[2], 1, 40, 40, 40);
        EQ(on_release(&skb), 0); no_tracking(); no_errors();
    }
}

static void bridge_receive_survives_overwritten_cb(void) {
    for (int local_input = 0; local_input < 2; local_input++) {
        reset();
        struct sk_buff source = { .dev = &ingress, .len = 64 };
        struct net_device *overwritten = (void *)(uintptr_t)0x100;
        memcpy(source.cb, &overwritten, sizeof(overwritten));
        receive_at(&source, 100);
        EQ(origin(&source)->flags, 0);
        EQ(on_bridge_receive(&ns, NULL, &source), 0);
        EQ(on_bridge_receive(&ns, NULL, &source), 0);
        EQ(origin(&source)->flags, BRIDGE);
        if (local_input) {
            clock_ns = 140;
            EQ(on_input4(&ns, &source), 0);
            struct stats *s = statistics(path_key(1, &ingress, NULL));
            EQ(counted(s, 0), 1); EQ(counted(s, 2), 1);
            EQ(counted(s, 4) + counted(s, 5) + counted(s, 6), 0);
            EQ(global_stats()->counts[5], 0);
            latency(&s->stages[2], 1, 40, 40, 40);
            EQ(on_release(&source), 0);
        } else {
            struct sk_buff copy = source;
            clock_ns = 110;
            EQ(on_clone(&source, 0, &copy), 0);
            EQ(origin(&copy)->flags, BRIDGE);
            queue_at(&source, &egress, 120); queue_at(&copy, &egress, 130);
            complete_at(&source, &egress, 140); complete_at(&copy, &egress, 150);
            struct stats *s = statistics(path_key(3, &ingress, &egress));
            EQ(counted(s, 0), 2); EQ(counted(s, 2), 2); EQ(counted(s, 5), 2);
            EQ(counted(s, 4), 0); EQ(counted(s, 6), 0); EQ(s->pending, 0);
            EQ(global_stats()->counts[0], 1); EQ(global_stats()->counts[5], 2);
            latency(&s->stages[2], 2, 90, 40, 50);
            EQ(on_release(&source), 0); EQ(on_release(&copy), 0);
        }
        no_tracking(); no_errors();
    }
}

static void bridge_transmit_callback_before_queue(void) {
    for (int routed = 0; routed < 2; routed++) {
        for (int overwritten_cb = 0; overwritten_cb < 2; overwritten_cb++) {
            reset();
            struct sk_buff source = { .dev = &ingress, .len = 64 }, copy = source;
            if (overwritten_cb) {
                struct net_device *invalid = (void *)(uintptr_t)0x100;
                memcpy(source.cb, &invalid, sizeof(invalid));
                memcpy(copy.cb, source.cb, sizeof(copy.cb));
            }
            receive_at(&source, 100);
            if (routed) EQ(on_route4(&source), 0);
            clock_ns = 110;
            EQ(on_clone(&source, 0, &copy), 0);
            EQ(origin(&copy)->flags, routed ? ROUTE : 0);
            struct sk_buff *packets[] = { &source, &copy };
            for (int i = 0; i < 2; i++) {
                packets[i]->dev = &egress;
                EQ(on_bridge_transmit(&ns, NULL, packets[i]), 0);
                EQ(on_bridge_transmit(&ns, NULL, packets[i]), 0);
                EQ(origin(packets[i])->flags, BRIDGE | (routed ? ROUTE : 0));
                queue_at(packets[i], &egress, 120 + i * 10);
                struct tx_key key = transmit_key(packets[i]);
                struct tx *t = bpf_map_lookup_elem(&transmits, &key);
                CHECK(t); EQ(t->flags, BRIDGE | (routed ? ROUTE : 0));
                complete_at(packets[i], &egress, 140 + i * 10);
                EQ(on_release(packets[i]), 0);
            }
            struct stats *s = statistics(path_key(3, &ingress, &egress));
            EQ(counted(s, 0), 2); EQ(counted(s, 1), 128);
            EQ(counted(s, 2), 2); EQ(counted(s, 3), 128); EQ(s->pending, 0);
            EQ(counted(s, 4), 0); EQ(counted(s, 5), routed ? 0 : 2);
            EQ(counted(s, 6), routed ? 2 : 0); EQ(counted(s, 7), 0);
            EQ(global_stats()->counts[0], 1); EQ(global_stats()->counts[1], 64);
            EQ(global_stats()->counts[2], 2); EQ(global_stats()->counts[3], 128);
            EQ(global_stats()->counts[4], 0); EQ(global_stats()->counts[5], routed ? 0 : 2);
            EQ(global_stats()->counts[6], routed ? 2 : 0);
            latency(&s->stages[0], 2, 50, 20, 30);
            latency(&s->stages[1], 2, 40, 20, 20);
            latency(&s->stages[2], 2, 90, 40, 50);
            no_tracking(); no_errors();
            struct sk_buff untracked = { .dev = &ingress, .len = 64 };
            EQ(on_bridge_transmit(&ns, NULL, &untracked), 0);
            CHECK(!origin(&untracked)); no_tracking(); no_errors();
        }
    }
}

static void bridge_clone_branches(void) {
    reset();
    struct sk_buff source = { .dev = &ingress, .len = 128 };
    struct sk_buff copies[5];
    for (int i = 0; i < 5; i++) copies[i] = source;
    receive_at(&source, 100);
    EQ(on_bridge_flood(NULL, &source), 0);
    EQ(origin(&source)->flags, BRIDGE);
    EQ(on_bridge(&ns, NULL, &source), 0);
    clock_ns = 110; EQ(on_clone(&source, 0, &copies[0]), 0);
    clock_ns = 111; EQ(on_copy(&source, 0, &copies[1]), 0);
    clock_ns = 112; EQ(on_expand(&source, 0, 0, 0, &copies[2]), 0);
    clock_ns = 113; EQ(on_pskb(&source, 0, 0, 0, &copies[3]), 0);
    clock_ns = 114; EQ(on_morph(&copies[4], &source, &copies[4]), 0);
    EQ(gauge(), 6);
    EQ(global_stats()->counts[0], 1);
    for (int i = 0; i < 5; i++) {
        EQ(origin(&copies[i])->start_ns, 100);
        EQ(origin(&copies[i])->birth, 110 + i);
        EQ(origin(&copies[i])->ingress, ingress.ifindex);
    }
    EQ(on_route6(&copies[4]), 0);
    queue_at(&source, &egress, 120);
    queue_at(&source, &egress, 121);
    complete_at(&source, &egress, 130);
    EQ(on_free(&source), 0);
    struct net_device *destinations[] = { &egress, &branch, &egress, &branch, &ingress };
    for (int i = 0; i < 5; i++) {
        queue_at(&copies[i], destinations[i], 140 + i * 10);
        complete_at(&copies[i], destinations[i], 145 + i * 10);
        EQ(on_free(&copies[i]), 0);
    }
    struct stats *a = statistics(path_key(3, &ingress, &egress));
    struct stats *b = statistics(path_key(3, &ingress, &branch));
    struct stats *hairpin = statistics(path_key(3, &ingress, &ingress));
    EQ(counted(a, 0), 3); EQ(counted(a, 2), 3); EQ(counted(a, 5), 3);
    EQ(counted(b, 0), 2); EQ(counted(b, 2), 2); EQ(counted(b, 5), 2);
    EQ(counted(hairpin, 0), 1); EQ(counted(hairpin, 2), 1);
    EQ(counted(hairpin, 4), 0); EQ(counted(hairpin, 5), 0); EQ(counted(hairpin, 6), 1);
    EQ(global_stats()->counts[2], 6); EQ(global_stats()->counts[3], 768);
    EQ(global_stats()->counts[5], 5); EQ(global_stats()->counts[6], 1);
    EQ(a->pending + b->pending + hairpin->pending, 0);
    no_tracking(); no_errors();
}

static void queued_clone_inheritance(void) {
    reset();
    struct sk_buff source = { .dev = &ingress, .len = 128 }, copy = source;
    receive_at(&source, 100);
    EQ(on_bridge(&ns, NULL, &source), 0);
    queue_at(&source, &egress, 120);
    copy.dev = &egress;
    clock_ns = 130;
    EQ(on_clone(&source, 0, &copy), 0);
    struct path key = path_key(3, &ingress, &egress);
    struct stats *s = statistics(key);
    EQ(s->pending, 2); EQ(counted(s, 0), 1); EQ(gauge(), 4);
    struct tx_key child_key = transmit_key(&copy);
    struct tx *child = bpf_map_lookup_elem(&transmits, &child_key);
    CHECK(child);
    EQ(child->start_ns, 100); EQ(child->queue_ns, 120);
    complete_at(&source, &egress, 140);
    complete_at(&copy, &egress, 150);
    EQ(counted(s, 2), 2); EQ(counted(s, 3), 256); EQ(counted(s, 5), 2);
    EQ(s->pending, 0);
    latency(&s->stages[0], 2, 40, 20, 20);
    latency(&s->stages[1], 2, 50, 20, 30);
    latency(&s->stages[2], 2, 90, 40, 50);
    EQ(on_free(&source), 0); EQ(on_free(&copy), 0);
    no_tracking(); no_errors();
}

static void clone_namespace_isolation(void) {
    reset();
    struct sk_buff source = { .dev = &ingress, .len = 128 }, copy = source;
    receive_at(&source, 100);
    source.dev = &foreign;
    clock_ns = 110;
    EQ(on_clone(&source, 0, &copy), 0);
    EQ(on_copy(&source, 0, &copy), 0);
    EQ(on_expand(&source, 0, 0, 0, &copy), 0);
    EQ(on_pskb(&source, 0, 0, 0, &copy), 0);
    EQ(on_morph(&copy, &source, &copy), 0);
    CHECK(!origin(&copy)); EQ(gauge(), 1);
    EQ(mock_map_for(&transmits)->count, 0);
    source.dev = NULL;
    EQ(on_clone(&source, 0, &copy), 0);
    CHECK(!origin(&copy)); EQ(gauge(), 1);
    /* Clone scope follows the parent's namespace, without selecting its dev. */
    struct net_device unselected = { .ifindex = 40, .nd_net.net = &ns };
    source.dev = &unselected;
    copy.dev = &foreign;
    clock_ns = 120;
    EQ(on_clone(&source, 0, &copy), 0);
    CHECK(origin(&copy)); EQ(origin(&copy)->start_ns, 100);
    EQ(origin(&copy)->birth, 120); EQ(gauge(), 2);
    EQ(global_stats()->counts[0], 1);
    EQ(mock_map_for(&paths)->count, 0); no_errors();
    collect_at(100 + TIMEOUT_NS);
    EQ(error_count(5), 2); no_tracking();
}

static void completed_clone_has_no_phantom_pending(void) {
    reset();
    struct sk_buff source = { .dev = &ingress, .len = 128 }, copy = source;
    receive_at(&source, 100);
    EQ(on_bridge_branch(&egress, &source), 0);
    EQ(origin(&source)->flags, BRIDGE);
    queue_at(&source, &egress, 120);
    complete_at(&source, &egress, 140);
    struct path key = path_key(3, &ingress, &egress);
    struct stats *s = statistics(key), saved = *s;
    struct traffic saved_global = *global_stats();
    EQ(origin(&source)->queue_ns, 120); EQ(origin(&source)->egress, egress.ifindex);
    EQ(s->pending, 0); EQ(mock_map_for(&transmits)->count, 0); EQ(gauge(), 1);
    copy.dev = &egress;
    clock_ns = 150;
    EQ(on_clone(&source, 0, &copy), 0);
    CHECK(origin(&copy)); EQ(origin(&copy)->birth, 150);
    EQ(gauge(), 2); EQ(mock_map_for(&transmits)->count, 0); EQ(s->pending, 0);
    struct tx_key child = transmit_key(&copy);
    CHECK(!bpf_map_lookup_elem(&transmits, &child));
    CHECK(!memcmp(s, &saved, sizeof(saved)));
    CHECK(!memcmp(global_stats(), &saved_global, sizeof(saved_global)));
    EQ(on_release(&copy), 0);
    EQ(gauge(), 1); EQ(s->pending, 0);
    CHECK(!memcmp(s, &saved, sizeof(saved)));
    clock_ns = 160;
    EQ(on_copy(&source, 0, &copy), 0);
    EQ(mock_map_for(&transmits)->count, 0); EQ(s->pending, 0);
    queue_at(&copy, &egress, 165);
    EQ(mock_map_for(&transmits)->count, 1); EQ(s->pending, 1); EQ(gauge(), 3);
    complete_at(&copy, &egress, 170);
    EQ(counted(s, 0), 2); EQ(counted(s, 2), 2); EQ(counted(s, 5), 2);
    EQ(counted(s, 7), 0); EQ(s->pending, 0);
    EQ(global_stats()->counts[0], 1); EQ(global_stats()->counts[2], 2);
    latency(&s->stages[2], 2, 110, 40, 70);
    EQ(on_release(&copy), 0); EQ(on_release(&source), 0);
    no_tracking(); no_errors();
}

static void morph_after_release_gets_new_identity(void) {
    reset();
    struct sk_buff dest = { .dev = &ingress, .len = 64 };
    struct sk_buff source = { .dev = &branch, .len = 128 };
    receive_at(&dest, 100);
    receive_at(&source, 110);
    EQ(on_bridge_output(&source), 0); EQ(origin(&source)->flags, BRIDGE);
    queue_at(&dest, &egress, 120);
    struct tx_key retired = transmit_key(&dest);
    clock_ns = 130;
    EQ(on_release(&dest), 0);
    CHECK(!origin(&dest)); CHECK(!bpf_map_lookup_elem(&transmits, &retired));
    EQ(gauge(), 1);
    struct stats *old = statistics(path_key(3, &ingress, &egress));
    EQ(old->pending, 0); EQ(counted(old, 7), 1); EQ(counted(old, 2), 0);
    dest = source;
    clock_ns = 140;
    EQ(on_morph(&dest, &source, &dest), 0);
    CHECK(origin(&dest));
    EQ(origin(&dest)->birth, 140); EQ(origin(&source)->birth, 110);
    EQ(origin(&dest)->start_ns, 110); EQ(origin(&dest)->queue_ns, 0);
    EQ(origin(&dest)->ingress, branch.ifindex);
    EQ(origin(&dest)->ingress_generation, 300); EQ(origin(&dest)->input_len, 128);
    EQ(origin(&dest)->flags, BRIDGE); EQ(gauge(), 2);
    queue_at(&dest, &egress, 160);
    struct tx_key current = transmit_key(&dest);
    EQ(current.skb, retired.skb); CHECK(current.birth != retired.birth);
    EQ(current.birth, 140);
    complete_at(&dest, &egress, 180);
    struct stats *s = statistics(path_key(3, &branch, &egress));
    EQ(counted(s, 0), 1); EQ(counted(s, 1), 128);
    EQ(counted(s, 2), 1); EQ(counted(s, 3), 128); EQ(counted(s, 5), 1);
    EQ(s->pending, 0); EQ(counted(s, 7), 0);
    latency(&s->stages[2], 1, 70, 70, 70);
    EQ(on_release(&dest), 0);
    collect_at(110 + TIMEOUT_NS);
    EQ(global_stats()->counts[0], 2); EQ(global_stats()->counts[2], 1);
    EQ(global_stats()->counts[7], 1);
    EQ(error_count(6), 1); EQ(error_count(5), 1); EQ(error_count(15), 0);
    no_tracking();
}

static void gso_segments(void) {
    for (int after_queue = 0; after_queue < 2; after_queue++) {
        reset();
        struct sk_buff source = { .dev = &ingress, .len = 9000 };
        struct sk_buff pieces[3] = {0};
        for (int i = 0; i < 3; i++) {
            pieces[i].dev = after_queue ? &egress : &ingress;
            pieces[i].len = 3000;
            pieces[i].next = i < 2 ? &pieces[i + 1] : NULL;
        }
        receive_at(&source, 100);
        EQ(on_route4(&source), 0);
        if (after_queue) queue_at(&source, &egress, 120);
        clock_ns = 130;
        if (after_queue) EQ(on_segment(&source, 0, pieces), 0);
        else EQ(on_segment_list(&source, 0, 0, pieces), 0);
        EQ(origin(&source)->flags, ROUTE | REPLACED);
        EQ(on_free(&source), 0);
        for (int i = 0; i < 3; i++) {
            EQ(origin(&pieces[i])->start_ns, 100);
            if (!after_queue) queue_at(&pieces[i], &egress, 140 + i * 10);
            complete_at(&pieces[i], &egress, 150 + i * 10);
            EQ(on_free(&pieces[i]), 0);
        }
        struct stats *s = statistics(path_key(3, &ingress, &egress));
        EQ(counted(s, 0), after_queue ? 1 : 3);
        EQ(counted(s, 1), after_queue ? 9000 : 27000);
        EQ(counted(s, 2), 3); EQ(counted(s, 3), 9000); EQ(counted(s, 4), 3);
        EQ(counted(s, 7), 0); EQ(s->pending, 0);
        EQ(global_stats()->counts[0], 1); EQ(global_stats()->counts[1], 9000);
        EQ(global_stats()->counts[2], 3); EQ(global_stats()->counts[3], 9000);
        latency(&s->stages[2], 3, 180, 50, 70);
        no_tracking(); no_errors();
    }
}

static void bounded_segment_walk(void) {
    reset();
    struct sk_buff source = { .dev = &ingress, .len = 9000 };
    struct sk_buff pieces[129] = {0};
    for (int i = 0; i < 129; i++) {
        pieces[i].dev = &ingress;
        pieces[i].next = i < 128 ? &pieces[i + 1] : NULL;
    }
    receive_at(&source, 100);
    clock_ns = 110;
    EQ(on_segment(&source, 0, pieces), 0);
    EQ(mock_map_for(&origins)->count, 129);
    EQ(gauge(), 129);
    CHECK(origin(&pieces[127])); CHECK(!origin(&pieces[128]));
    EQ(error_count(7), 1);
    collect_at(100 + TIMEOUT_NS);
    EQ(error_count(5), 129);
    no_tracking();
}

static void invalid_clone_results(void) {
    reset();
    struct sk_buff source = { .dev = &ingress, .len = 64 }, dest = source;
    receive_at(&source, 100);
    EQ(on_clone(&source, 0, NULL), 0);
    EQ(on_copy(&source, 0, &source), 0);
    EQ(on_clone(&source, 0, (void *)(uintptr_t)-ENOMEM), 0);
    EQ(on_segment(&source, 0, NULL), 0);
    EQ(on_segment_list(&source, 0, 0, (void *)(uintptr_t)-ENOMEM), 0);
    EQ(origin(&source)->flags, 0); EQ(gauge(), 1);
    clock_ns = 110;
    EQ(on_clone(&source, 0, &dest), 0);
    EQ(on_clone(&source, 0, &dest), 0);
    EQ(gauge(), 2);
    collect_at(100 + TIMEOUT_NS);
    no_tracking(); EQ(error_count(5), 2);
}

static void driver_busy_retry(void) {
    reset();
    struct sk_buff skb = { .dev = &ingress, .len = 64 };
    receive_at(&skb, 100);
    EQ(on_route4(&skb), 0);
    queue_at(&skb, &egress, 120);
    struct path key = path_key(3, &ingress, &egress);
    struct stats *s = statistics(key);
    struct tx_key retry_key = transmit_key(&skb);
    struct tx *t = bpf_map_lookup_elem(&transmits, &retry_key);
    CHECK(t); EQ(t->attempting, 0); EQ(t->free_seen, 0);
    attempt_at(&skb, &egress, 130);
    EQ(t->attempting, 1);
    result_at(&skb, &egress, 16, 140);
    EQ(t->attempting, 0); EQ(t->free_seen, 0);
    EQ(s->pending, 1); EQ(counted(s, 2), 0); EQ(s->stages[2].samples, 0);
    EQ(global_stats()->counts[2], 0); EQ(gauge(), 2); EQ(error_count(9), 1);
    skb.len = 60;
    queue_at(&skb, &egress, 150);
    EQ(counted(s, 0), 1);
    attempt_at(&skb, &egress, 170);
    result_at(&skb, &egress, 0, 190);
    EQ(counted(s, 2), 1); EQ(counted(s, 3), 60); EQ(counted(s, 4), 1);
    EQ(s->pending, 0);
    latency(&s->stages[0], 1, 20, 20, 20);
    latency(&s->stages[1], 1, 50, 50, 50);
    latency(&s->stages[2], 1, 70, 70, 70);
    EQ(attempt_stack(cpu)->depth, 0);
    EQ(on_free(&skb), 0); no_tracking();
}

static void free_during_driver_pointer_reuse(void) {
    reset();
    struct sk_buff skb = { .dev = &ingress, .len = 64 };
    receive_routed_at(&skb, 100);
    cpu = 1;
    queue_at(&skb, &egress, 120);
    struct tx_key original_key = transmit_key(&skb);
    attempt_at(&skb, &egress, 130);
    clock_ns = 135;
    EQ(on_free(&skb), 0); EQ(on_free(&skb), 0);
    CHECK(!origin(&skb)); CHECK(bpf_map_lookup_elem(&transmits, &original_key));
    EQ(gauge(), 1); EQ(error_count(6), 0);
    EQ(attempt_stack(1)->frames[0].key.birth, 100);
    cpu = 0;
    skb = (struct sk_buff){ .dev = &ingress, .len = 256 };
    receive_routed_at(&skb, 140);
    queue_at(&skb, &egress, 150);
    struct tx_key replacement_key = transmit_key(&skb);
    EQ(replacement_key.birth, 140);
    struct stats *s = statistics(path_key(3, &ingress, &egress));
    EQ(s->pending, 2); EQ(gauge(), 3);
    cpu = 1;
    result_at(&skb, &egress, 0, 160);
    CHECK(!bpf_map_lookup_elem(&transmits, &original_key));
    CHECK(bpf_map_lookup_elem(&transmits, &replacement_key));
    EQ(origin(&skb)->birth, 140);
    EQ(counted(s, 2), 1); EQ(counted(s, 3), 64); EQ(s->pending, 1); EQ(gauge(), 2);
    cpu = 2;
    complete_at(&skb, &egress, 180);
    EQ(counted(s, 0), 2); EQ(counted(s, 1), 320);
    EQ(counted(s, 2), 2); EQ(counted(s, 3), 320); EQ(s->pending, 0);
    latency(&s->stages[2], 2, 70, 30, 40);
    EQ(on_free(&skb), 0);
    no_tracking(); no_errors();
}

static void nested_driver_attempts(void) {
    reset();
    struct sk_buff outer = { .dev = &ingress, .len = 64 }, inner = outer;
    receive_routed_at(&outer, 100); receive_routed_at(&inner, 101);
    queue_at(&outer, &egress, 120); queue_at(&inner, &egress, 121);
    attempt_at(&outer, &egress, 130); attempt_at(&inner, &egress, 131);
    EQ(attempt_stack(0)->depth, 2);
    EQ(on_free(&outer), 0);
    result_at(&inner, &egress, 0, 140);
    result_at(&outer, &egress, 0, 145);
    EQ(on_free(&inner), 0);
    struct stats *s = statistics(path_key(3, &ingress, &egress));
    EQ(counted(s, 2), 2); EQ(s->pending, 0);
    latency(&s->stages[2], 2, 60, 30, 30);
    EQ(attempt_stack(0)->depth, 0);
    no_tracking(); no_errors();
}

static void bounded_driver_stack(void) {
    reset();
    struct sk_buff skb = { .dev = &ingress, .len = 64 }, untracked = skb;
    receive_routed_at(&skb, 100); queue_at(&skb, &egress, 120);
    attempt_at(&skb, &egress, 130);
    for (int i = 0; i < 16; i++) attempt_at(&untracked, &egress, 131 + i);
    EQ(attempt_stack(0)->depth, 17); EQ(error_count(7), 1);
    EQ(on_free(&skb), 0);
    for (int i = 0; i < 16; i++) result_at(&untracked, &egress, 0, 150 + i);
    result_at(&skb, &egress, 0, 170);
    EQ(attempt_stack(0)->depth, 0);
    EQ(counted(statistics(path_key(3, &ingress, &egress)), 2), 1);
    no_tracking(); EQ(error_count(6), 0); EQ(error_count(14), 0);
}

static void free_drop_and_cas_ownership(void) {
    reset();
    struct sk_buff skb = { .dev = &ingress, .len = 64 };
    receive_at(&skb, 100); queue_at(&skb, &egress, 120);
    struct stats *s = statistics(path_key(3, &ingress, &egress));
    cas_failures = 1;
    EQ(on_free(&skb), 0);
    EQ(gauge(), 2); EQ(s->pending, 1); CHECK(origin(&skb));
    EQ(on_free(&skb), 0);
    EQ(counted(s, 7), 1); EQ(global_stats()->counts[7], 1);
    EQ(s->pending, 0); EQ(error_count(6), 1);
    EQ(on_free(&skb), 0);
    no_tracking();
    reset();
    skb.dev = &ingress;
    receive_at(&skb, 100);
    EQ(on_free(&skb), 0); EQ(on_free(&skb), 0);
    EQ(error_count(15), 1);
    no_tracking();
}

static void retire_with_hook(struct sk_buff *skb, int hook) {
    __u64 args[4] = { (__u64)skb, 0x1234, 7 };
    switch (hook) {
    case 0: EQ(on_free(skb), 0); break;
    case 1: EQ(on_release(skb), 0); break;
    case 2: EQ(on_consume((void *)args), 0); break;
    case 3: EQ(on_drop((void *)args), 0); break;
    default: CHECK(!"unknown retirement hook");
    }
}

static void alternate_free_hooks(void) {
    for (int hook = 0; hook < 4; hook++) {
        for (int state = 0; state < 4; state++) {
            reset();
            struct sk_buff skb = { .dev = &ingress, .len = 64 };
            receive_at(&skb, 100);
            struct stats *s = NULL;
            if (state == 0) {
                clock_ns = 110;
                EQ(on_input4(&ns, &skb), 0);
                s = statistics(path_key(1, &ingress, NULL));
            } else if (state < 3) {
                EQ(on_route4(&skb), 0);
                queue_at(&skb, &egress, 120);
                s = statistics(path_key(3, &ingress, &egress));
                if (state == 2) attempt_at(&skb, &egress, 130);
            }
            retire_with_hook(&skb, hook);
            CHECK(!origin(&skb));
            /* Multiple kernel free paths can observe the same retirement. */
            for (int duplicate = 0; duplicate < 4; duplicate++)
                retire_with_hook(&skb, duplicate);
            if (state == 2) {
                EQ(gauge(), 1); EQ(s->pending, 1);
                EQ(mock_map_for(&transmits)->count, 1);
                skb.len = 4096; skb.dev = &foreign;
                result_at(&skb, &egress, 0, 160);
                EQ(counted(s, 2), 1); EQ(counted(s, 3), 64); EQ(s->pending, 0);
                latency(&s->stages[2], 1, 30, 30, 30);
            }
            EQ(global_stats()->counts[0], 1); EQ(global_stats()->counts[1], 64);
            EQ(global_stats()->counts[2], state == 0 || state == 2 ? 1 : 0);
            EQ(global_stats()->counts[7], state == 1 ? 1 : 0);
            EQ(error_count(6), state == 1 ? 1 : 0);
            EQ(error_count(15), state == 3 ? 1 : 0);
            for (__u32 i = 0; i < ERROR_SLOTS; i++) if (i != 6 && i != 15) EQ(error_count(i), 0);
            if (s) EQ(s->pending, 0);
            no_tracking();
        }
    }
}

static void cross_cpu_free_and_pointer_reuse(void) {
    for (int hook = 0; hook < 4; hook++) {
        for (int busy = 0; busy < 2; busy++) {
            for (int reuse = 0; reuse < 2; reuse++) {
                reset();
                struct sk_buff skb = { .dev = &ingress, .len = 64 };
                receive_at(&skb, 100);
                EQ(on_route4(&skb), 0);
                queue_at(&skb, &egress, 120);
                struct tx_key original = transmit_key(&skb);
                struct tx *t = bpf_map_lookup_elem(&transmits, &original);
                CHECK(t); EQ(t->attempting, 0); EQ(t->free_seen, 0);
                attempt_at(&skb, &egress, 130);
                EQ(t->attempting, 1); EQ(attempt_stack(0)->depth, 1);
                cpu = 1;
                skb.dev = &foreign;
                clock_ns = 135;
                EQ(on_input4(&other_ns, &skb), 0);
                EQ(on_input6(&other_ns, &skb), 0);
                EQ(origin(&skb)->delivered, 0); EQ(global_stats()->counts[2], 0);
                EQ(mock_map_for(&paths)->count, 1);
                retire_with_hook(&skb, hook);
                for (int duplicate = 0; duplicate < 4; duplicate++)
                    retire_with_hook(&skb, duplicate);
                CHECK(!origin(&skb)); CHECK(bpf_map_lookup_elem(&transmits, &original));
                EQ(t->attempting, 1); EQ(t->free_seen, 1);
                EQ(attempt_stack(1)->depth, 0); EQ(gauge(), 1);
                struct stats *s = statistics(path_key(3, &ingress, &egress));
                EQ(s->pending, 1); EQ(counted(s, 7), 0);
                no_errors();
                struct tx_key replacement = {0};
                if (reuse) {
                    skb = (struct sk_buff){ .dev = &ingress, .len = 256 };
                    receive_routed_at(&skb, 140); queue_at(&skb, &egress, 150);
                    replacement = transmit_key(&skb);
                    EQ(replacement.skb, original.skb); EQ(replacement.birth, 140);
                    EQ(s->pending, 2); EQ(gauge(), 3);
                } else {
                    skb.len = 4096;
                }
                cpu = 0;
                result_at(&skb, &egress, busy ? 16 : 0, 160);
                CHECK(!bpf_map_lookup_elem(&transmits, &original));
                EQ(t->attempting, 0); EQ(attempt_stack(0)->depth, 0);
                EQ(s->pending, reuse ? 1 : 0); EQ(gauge(), reuse ? 2 : 0);
                EQ(counted(s, 0), reuse ? 2 : 1);
                EQ(counted(s, 2), busy ? 0 : 1); EQ(counted(s, 3), busy ? 0 : 64);
                EQ(counted(s, 4), busy ? 0 : 1); EQ(counted(s, 7), busy ? 1 : 0);
                EQ(errors_on(0, 6), busy ? 1 : 0); EQ(errors_on(1, 6), 0);
                EQ(errors_on(0, 9), busy ? 1 : 0); EQ(error_count(4), 0);
                if (reuse) {
                    struct tx *new_tx = bpf_map_lookup_elem(&transmits, &replacement);
                    CHECK(new_tx); EQ(new_tx->attempting, 0); EQ(new_tx->free_seen, 0);
                    EQ(origin(&skb)->birth, 140);
                    cpu = 2;
                    complete_at(&skb, &egress, 180);
                    cpu = 3;
                    retire_with_hook(&skb, hook);
                    EQ(counted(s, 2), busy ? 1 : 2); EQ(counted(s, 3), busy ? 256 : 320);
                    latency(&s->stages[2], busy ? 1 : 2, busy ? 40 : 70,
                            busy ? 40 : 30, 40);
                } else {
                    latency(&s->stages[2], busy ? 0 : 1, busy ? 0 : 30,
                            busy ? 0 : 30, busy ? 0 : 30);
                }
                EQ(global_stats()->counts[0], reuse ? 2 : 1);
                EQ(global_stats()->counts[1], reuse ? 320 : 64);
                EQ(global_stats()->counts[2], (busy ? 0 : 1) + reuse);
                EQ(global_stats()->counts[3], (busy ? 0 : 64) + (reuse ? 256 : 0));
                EQ(global_stats()->counts[7], busy ? 1 : 0);
                for (__u32 i = 0; i < ERROR_SLOTS; i++)
                    EQ(error_count(i), busy && (i == 6 || i == 9) ? 1 : 0);
                EQ(s->pending, 0); no_tracking();
            }
        }
    }
}

static void driver_frame_retirement(void) {
    for (int mode = 0; mode < 4; mode++) {
        for (int hook = 0; hook < 4; hook++) {
            for (int busy = 0; busy < 2; busy++) {
                for (int reuse = 0; reuse < 2; reuse++) {
                    reset();
                    struct sk_buff skb = { .dev = &ingress, .len = 64 }, inner = skb;
                    receive_routed_at(&skb, 100); queue_at(&skb, &egress, 120);
                    struct tx_key old = transmit_key(&skb);
                    struct tx *t = bpf_map_lookup_elem(&transmits, &old);
                    attempt_at(&skb, &egress, 130);
                    if (mode == 1) cpu = 1; // A different CPU has no matching frame.
                    if (mode == 2) {
                        receive_routed_at(&inner, 101); queue_at(&inner, &egress, 121);
                        attempt_at(&inner, &egress, 131); // The matching frame is not the top.
                    }
                    if (mode == 3) attempt_at(&inner, &egress, 131); // Inactive top frame.
                    unsigned long lookups = mock_map_for(&transmits)->lookups;
                    retire_with_hook(&skb, hook);
                    EQ(mock_map_for(&transmits)->lookups - lookups, 1);
                    CHECK(!origin(&skb)); EQ(t->attempting, 1);
                    EQ(t->free_seen, 1);
                    EQ(attempt_stack(0)->frames[0].active, 1);
                    for (int duplicate = 0; duplicate < 4; duplicate++)
                        retire_with_hook(&skb, duplicate);
                    struct tx_key replacement = {0};
                    if (reuse) {
                        cpu = 2;
                        skb = (struct sk_buff){ .dev = &ingress, .len = 256 };
                        receive_routed_at(&skb, 140); queue_at(&skb, &egress, 150);
                        replacement = transmit_key(&skb);
                    }
                    cpu = 0;
                    if (mode >= 2) result_at(&inner, &egress, 0, 141);
                    result_at(&skb, &egress, busy ? 16 : 0, 160);
                    EQ(attempt_stack(0)->depth, 0); EQ(t->attempting, 0);
                    CHECK(!bpf_map_lookup_elem(&transmits, &old));
                    if (mode == 2) retire_with_hook(&inner, hook);
                    if (reuse) {
                        CHECK(bpf_map_lookup_elem(&transmits, &replacement));
                        EQ(origin(&skb)->birth, replacement.birth);
                        cpu = 3;
                        complete_at(&skb, &egress, 180);
                        retire_with_hook(&skb, hook);
                    }
                    struct stats *s = statistics(path_key(3, &ingress, &egress));
                    EQ(counted(s, 0), 1 + reuse + (mode == 2));
                    EQ(counted(s, 2), !busy + reuse + (mode == 2));
                    EQ(counted(s, 3), (!busy + (mode == 2)) * 64 + reuse * 256);
                    EQ(counted(s, 7), busy); EQ(s->pending, 0);
                    latency(&s->stages[2], !busy + reuse + (mode == 2),
                        (!busy + (mode == 2)) * 30 + reuse * 40,
                        (!busy || mode == 2) ? 30 : reuse ? 40 : 0,
                        reuse ? 40 : (!busy || mode == 2) ? 30 : 0);
                    for (__u32 i = 0; i < ERROR_SLOTS; i++)
                        EQ(error_count(i), busy && (i == 6 || i == 9) ? 1 : 0);
                    no_tracking();
                }
            }
        }
    }
}

static void reject_unselected_transmit_before_association(void) {
    for (int mode = 0; mode < 3; mode++) {
        reset();
        struct sk_buff skb = { .dev = &ingress, .len = 64 };
        receive_routed_at(&skb, 100); queue_at(&skb, &egress, 120);
        attempt_at(&skb, &egress, 130);
        struct net_device replaced = egress;
        struct net_device *dev = mode == 0 ? &foreign : mode == 1 ? &branch : &replaced;
        if (mode == 1) {
            __u32 index = branch.ifindex;
            ((struct iface *)bpf_map_lookup_elem(&interfaces, &index))->enabled = 0;
        }
        struct sk_buff unrelated = { .dev = dev, .len = 256 };
        unsigned int origin_lookups = mock_map_for(&origins)->lookups;
        unsigned int transmit_lookups = mock_map_for(&transmits)->lookups;
        queue_at(&unrelated, dev, 135);
        attempt_at(&unrelated, dev, 136);
        EQ(attempt_stack(0)->depth, 2); EQ(attempt_stack(0)->frames[1].active, 0);
        EQ(mock_map_for(&origins)->lookups, origin_lookups);
        EQ(mock_map_for(&transmits)->lookups, transmit_lookups);
        result_at(&unrelated, dev, 0, 137);
        EQ(attempt_stack(0)->depth, 1); EQ(attempt_stack(0)->frames[0].active, 1);
        result_at(&skb, &egress, 0, 140);
        EQ(on_consume((void *)(__u64[]){(__u64)&skb}), 0);
        struct stats *s = statistics(path_key(3, &ingress, &egress));
        EQ(counted(s, 0), 1); EQ(counted(s, 2), 1); EQ(counted(s, 3), 64);
        latency(&s->stages[2], 1, 30, 30, 30);
        for (__u32 i = 0; i < ERROR_SLOTS; i++)
            EQ(error_count(i), mode == 2 && i == 11 ? 2 : 0);
        EQ(s->pending, 0); no_tracking();
    }
}

static void empty_cleanup_skips_walks(void) {
    reset();
    collect_at(100);
    EQ(mock_map_for(&origins)->walks, 0); EQ(mock_map_for(&transmits)->walks, 0);
    struct sk_buff skb = { .dev = &ingress, .len = 64 };
    receive_routed_at(&skb, 101); queue_at(&skb, &egress, 120);
    collect_at(101 + TIMEOUT_NS - 1);
    EQ(mock_map_for(&origins)->walks, 1); EQ(mock_map_for(&transmits)->walks, 1);
    EQ(gauge(), 2); EQ(error_count(5), 0);
    collect_at(101 + TIMEOUT_NS);
    EQ(mock_map_for(&origins)->walks, 2); EQ(mock_map_for(&transmits)->walks, 2);
    EQ(error_count(5), 2); no_tracking();
    collect_at(102 + TIMEOUT_NS);
    EQ(mock_map_for(&origins)->walks, 2); EQ(mock_map_for(&transmits)->walks, 2);
    EQ(error_count(5), 2); no_tracking();
}

static void ttl_cleanup(void) {
    reset();
    struct sk_buff skb = { .dev = &ingress, .len = 64 };
    receive_at(&skb, 100); queue_at(&skb, &egress, 120);
    struct stats *s = statistics(path_key(3, &ingress, &egress));
    collect_at(100 + TIMEOUT_NS - 1);
    EQ(gauge(), 2); EQ(s->pending, 1); EQ(error_count(5), 0);
    collect_at(100 + TIMEOUT_NS);
    EQ(s->pending, 0); EQ(error_count(5), 2); EQ(counted(s, 7), 0);
    no_tracking();
    collect_at(101 + TIMEOUT_NS);
    EQ(on_free(&skb), 0);
    EQ(error_count(5), 2); no_tracking();
}

static void cleanup_snapshot_predates_new_entries(void) {
    reset();
    struct sk_buff skb = { .dev = &ingress, .len = 64 };
    receive_routed_at(&skb, 101); queue_at(&skb, &egress, 121);
    __u64 address = (__u64)&skb, captured_now = 100;
    struct meta *m = origin(&skb);
    struct tx_key key = transmit_key(&skb);
    struct tx *t = bpf_map_lookup_elem(&transmits, &key);
    CHECK(t); EQ(m->start_ns, 101); EQ(t->start_ns, 101);
    struct meta saved_origin = *m;
    struct tx saved_tx = *t;
    struct stats *s = statistics(path_key(3, &ingress, &egress));
    struct stats saved_path = *s;
    struct traffic saved_global = *global_stats();
    /* Map iteration can observe an insertion after cleanup captured its clock. */
    EQ(origin_expire(&origins, &address, m, &captured_now), 0);
    EQ(tx_expire(&transmits, &key, t, &captured_now), 0);
    collect_at(captured_now);
    CHECK(origin(&skb)); CHECK(bpf_map_lookup_elem(&transmits, &key));
    CHECK(!memcmp(m, &saved_origin, sizeof(saved_origin)));
    CHECK(!memcmp(t, &saved_tx, sizeof(saved_tx)));
    CHECK(!memcmp(s, &saved_path, sizeof(saved_path)));
    CHECK(!memcmp(global_stats(), &saved_global, sizeof(saved_global)));
    EQ(gauge(), 2); EQ(s->pending, 1); no_errors();
    collect_at(101 + TIMEOUT_NS - 1);
    CHECK(origin(&skb)); CHECK(bpf_map_lookup_elem(&transmits, &key));
    EQ(gauge(), 2); EQ(s->pending, 1); no_errors();
    collect_at(101 + TIMEOUT_NS);
    EQ(s->pending, 0); EQ(counted(s, 2), 0); EQ(counted(s, 7), 0);
    EQ(global_stats()->counts[0], 1); EQ(global_stats()->counts[1], 64);
    EQ(global_stats()->counts[2], 0); EQ(global_stats()->counts[7], 0);
    latency(&s->stages[2], 0, 0, 0, 0);
    EQ(error_count(5), 2); no_tracking();
    collect_at(102 + TIMEOUT_NS); EQ(on_release(&skb), 0);
    for (__u32 index = 0; index < ERROR_SLOTS; index++)
        EQ(error_count(index), index == 5 ? 2 : 0);
    no_tracking();
}

static void consume_during_completion_claim(void) {
    reset();
    struct sk_buff skb = { .dev = &ingress, .len = 64 };
    receive_routed_at(&skb, 100); queue_at(&skb, &egress, 120);
    struct tx_key key = transmit_key(&skb);
    struct tx *t = bpf_map_lookup_elem(&transmits, &key);
    CHECK(t);
    attempt_at(&skb, &egress, 130);
    EQ(t->attempting, 1);
    consume_on_cas = &skb;
    consume_before_cas = &t->start_ns;
    result_at(&skb, &egress, 0, 140);
    CHECK(!consume_before_cas); CHECK(!origin(&skb));
    EQ(cpu, 0); EQ(attempt_stack(0)->depth, 0); EQ(attempt_stack(1)->depth, 0);
    struct stats *s = statistics(path_key(3, &ingress, &egress));
    EQ(counted(s, 7), 0); EQ(global_stats()->counts[7], 0);
    EQ(counted(s, 0), 1); EQ(counted(s, 2), 1); EQ(counted(s, 3), 64);
    EQ(s->pending, 0);
    EQ(global_stats()->counts[2], 1); EQ(global_stats()->counts[3], 64);
    latency(&s->stages[0], 1, 20, 20, 20);
    latency(&s->stages[1], 1, 10, 10, 10);
    latency(&s->stages[2], 1, 30, 30, 30);
    EQ(on_release(&skb), 0); no_tracking(); no_errors();
}

static void cleanup_cas_loser(void) {
    reset();
    struct sk_buff skb = { .dev = &ingress, .len = 64 };
    receive_at(&skb, 100); queue_at(&skb, &egress, 120);
    struct stats *s = statistics(path_key(3, &ingress, &egress));
    cas_failures = 1;
    collect_at(100 + TIMEOUT_NS);
    CHECK(origin(&skb)); EQ(origin(&skb)->birth, 100);
    EQ(gauge(), 1); EQ(s->pending, 0); EQ(error_count(5), 1);
    collect_at(100 + TIMEOUT_NS);
    EQ(error_count(5), 2); no_tracking();
    reset();
    skb.dev = &ingress;
    receive_at(&skb, 100); queue_at(&skb, &egress, 120);
    struct tx_key key = transmit_key(&skb);
    struct tx *t = bpf_map_lookup_elem(&transmits, &key);
    CHECK(t);
    t->start_ns = 0;
    collect_at(100 + TIMEOUT_NS);
    CHECK(bpf_map_lookup_elem(&transmits, &key));
    EQ(gauge(), 1); EQ(error_count(5), 1);
    EQ(statistics(path_key(3, &ingress, &egress))->pending, 1);
    t->start_ns = 100;
    collect_at(100 + TIMEOUT_NS);
    EQ(error_count(5), 2); no_tracking();
}

static void expiry_during_driver(void) {
    reset();
    struct sk_buff skb = { .dev = &ingress, .len = 64 };
    receive_at(&skb, 100); queue_at(&skb, &egress, 120);
    attempt_at(&skb, &egress, 130);
    collect_at(100 + TIMEOUT_NS);
    result_at(&skb, &egress, 0, 101 + TIMEOUT_NS);
    EQ(error_count(5), 2); EQ(error_count(4), 1);
    EQ(global_stats()->counts[2], 0);
    EQ(statistics(path_key(3, &ingress, &egress))->pending, 0);
    EQ(on_free(&skb), 0); no_tracking();
}

static void bounded_tracking_capacity(void) {
    reset();
    configuration()->capacity = 1;
    struct sk_buff skb = { .dev = &ingress, .len = 64 }, copy = skb;
    receive_at(&skb, 100); queue_at(&skb, &egress, 120);
    EQ(gauge(), 1); EQ(error_count(0), 1);
    EQ(mock_map_for(&transmits)->count, 0);
    EQ(statistics(path_key(3, &ingress, &egress))->pending, 0);
    EQ(on_clone(&skb, 0, &copy), 0);
    CHECK(!origin(&copy)); EQ(gauge(), 1); EQ(error_count(0), 2);
    collect_at(100 + TIMEOUT_NS); no_tracking();
    configuration()->capacity = 2;
    skb.dev = &ingress;
    receive_at(&skb, 101 + TIMEOUT_NS); queue_at(&skb, &egress, 120 + TIMEOUT_NS);
    EQ(gauge(), 2);
    EQ(on_clone(&skb, 0, &copy), 0);
    CHECK(!origin(&copy)); EQ(gauge(), 2);
    collect_at(101 + TIMEOUT_NS * 2); no_tracking();
}

static void bounded_racing_admission_and_stop(void) {
    reset();
    struct sk_buff first = { .dev = &ingress, .len = 64 }, second = first;
    configuration()->capacity = 1;
    receive_at(&first, 100);
    receive_at(&second, 101);
    CHECK(origin(&first)); CHECK(!origin(&second));
    EQ(gauge(), 1); EQ(error_count(0), 1);
    EQ(on_release(&first), 0); no_tracking();

    reset();
    first.dev = second.dev = &ingress;
    configuration()->capacity = 1;
    admission_racer = &second;
    receive_at(&first, 100);
    CHECK(!origin(&first)); CHECK(origin(&second));
    EQ(gauge(), 1); EQ(error_count(0), 1);
    EQ(mock_map_for(&origins)->count, 1);
    EQ(global_stats()->counts[0], 1);
    EQ(on_release(&second), 0); no_tracking();

    reset();
    first.dev = &ingress;
    stop_before_admission = true;
    receive_at(&first, 100);
    CHECK(!origin(&first)); EQ(configuration()->capacity, 0);
    EQ(error_count(0), 1); EQ(global_stats()->counts[0], 0);
    no_tracking();
}

static void map_failures_release_capacity(void) {
    reset();
    struct sk_buff skb = { .dev = &ingress, .len = 64 }, copy = skb;
    mock_map_for(&origins)->reject_updates = 1;
    receive_at(&skb, 100);
    CHECK(!origin(&skb)); EQ(global_stats()->counts[0], 0); no_tracking();
    receive_at(&skb, 101);
    mock_map_for(&transmits)->reject_updates = 1;
    queue_at(&skb, &egress, 120);
    EQ(gauge(), 1); EQ(error_count(8), 1);
    EQ(origin(&skb)->queue_ns, 0);
    mock_map_for(&origins)->reject_updates = 1;
    EQ(on_clone(&skb, 0, &copy), 0);
    CHECK(!origin(&copy)); EQ(gauge(), 1); EQ(error_count(10), 1);
    queue_at(&skb, &egress, 125);
    mock_map_for(&transmits)->reject_updates = 1;
    clock_ns = 130;
    EQ(on_clone(&skb, 0, &copy), 0);
    CHECK(origin(&copy)); EQ(gauge(), 3); EQ(error_count(10), 2);
    EQ(statistics(path_key(3, &ingress, &egress))->pending, 1);
    collect_at(101 + TIMEOUT_NS); no_tracking();
    reset();
    mock_map_for(&origins)->capacity = 1;
    skb.dev = &ingress;
    receive_at(&skb, 100); receive_at(&copy, 110);
    CHECK(origin(&skb)); CHECK(!origin(&copy)); EQ(gauge(), 1);
    collect_at(100 + TIMEOUT_NS); no_tracking();
    reset();
    mock_map_for(&transmits)->capacity = 1;
    skb.dev = &ingress; copy.dev = &ingress;
    receive_at(&skb, 100); receive_at(&copy, 110);
    queue_at(&skb, &egress, 120); queue_at(&copy, &egress, 121);
    EQ(gauge(), 3); EQ(error_count(8), 1);
    EQ(statistics(path_key(3, &ingress, &egress))->pending, 1);
    collect_at(110 + TIMEOUT_NS); no_tracking();
}

static void bounded_stats_maps(void) {
    reset();
    mock_map_for(&paths)->capacity = 1;
    struct sk_buff first = { .dev = &ingress, .len = 64 }, second = first;
    second.len = 128;
    receive_at(&first, 100); EQ(on_route4(&first), 0);
    queue_at(&first, &egress, 120);
    complete_at(&first, &egress, 140); EQ(on_free(&first), 0);
    struct path existing = path_key(3, &ingress, &egress);
    struct path missing = path_key(3, &ingress, &branch);
    struct stats saved = *statistics(existing);
    struct traffic saved_period = *period(existing, 0);
    CHECK(!path_stats(&missing)); EQ(error_count(1), 0);
    receive_at(&second, 150);
    EQ(on_route6(&second), 0); EQ(on_bridge(&ns, NULL, &second), 0);
    queue_at(&second, &branch, 160);
    EQ(error_count(1), 1); EQ(gauge(), 2);
    CHECK(origin(&second));
    struct tx_key second_key = transmit_key(&second);
    CHECK(bpf_map_lookup_elem(&transmits, &second_key));
    second.len = 120;
    complete_at(&second, &branch, 170); EQ(on_free(&second), 0);
    EQ(mock_map_for(&paths)->count, 1);
    EQ(mock_map_for(&periods)->count, 1);
    EQ(error_count(1), 2);
    for (__u32 i = 0; i < ERROR_SLOTS; i++) if (i != 1) EQ(error_count(i), 0);
    CHECK(!memcmp(statistics(existing), &saved, sizeof(saved)));
    CHECK(!memcmp(period(existing, 0), &saved_period, sizeof(saved_period)));
    CHECK(!bpf_map_lookup_elem(&paths, &missing));
    __u64 expected[] = {2, 192, 2, 184, 1, 0, 1, 0};
    for (int i = 0; i < 8; i++) EQ(global_stats()->counts[i], expected[i]);
    no_tracking();
    reset();
    mock_map_for(&periods)->capacity = 1;
    first.dev = &ingress; second.dev = &ingress;
    receive_routed_at(&first, 100); queue_at(&first, &egress, 120);
    complete_at(&first, &egress, 140); EQ(on_free(&first), 0);
    receive_routed_at(&second, 200); queue_at(&second, &egress, 220);
    complete_at(&second, &egress, 240); EQ(on_free(&second), 0);
    EQ(mock_map_for(&periods)->count, 1);
    CHECK(error_count(2) > 0);
    struct stats *s = statistics(path_key(3, &ingress, &egress));
    EQ(counted(s, 0), 2); EQ(counted(s, 2), 2); EQ(s->pending, 0);
    latency(&s->stages[2], 2, 80, 40, 40);
    EQ(error_count(16), 0);
    no_tracking();
}

static void unsupported_transformations(void) {
    for (int which = 0; which < 4; which++) {
        reset();
        struct sk_buff skb = { .dev = &ingress, .len = 128 }, copy = skb;
        receive_at(&skb, 100);
        if (which < 2) EQ(on_route4(&skb), 0);
        clock_ns = 110;
        if (which == 0) EQ(on_fragment4(&ns, NULL, &skb), 0);
        if (which == 1) EQ(on_fragment6(&ns, NULL, &skb), 0);
        if (which == 2) EQ(on_reassembly4(&ns, &skb), 0);
        if (which == 3) EQ(on_reassembly6(&skb), 0);
        EQ(error_count(12), which < 2 ? 1 : 0);
        EQ(error_count(13), which < 2 ? 0 : 1);
        CHECK(origin(&skb)->flags & UNSUPPORTED);
        struct path key;
        if (which < 2) {
            CHECK(origin(&skb)->flags & REPLACED);
            clock_ns = 115;
            EQ(on_clone(&skb, 0, &copy), 0);
            CHECK(origin(&copy)->flags & UNSUPPORTED);
            EQ(on_free(&skb), 0);
            queue_at(&copy, &egress, 120);
            copy.len = 96;
            complete_at(&copy, &egress, 140);
            EQ(on_free(&copy), 0);
            key = path_key(3, &ingress, &egress);
        } else {
            skb.len = 96;
            clock_ns = 120;
            EQ(on_input4(&ns, &skb), 0);
            EQ(on_free(&skb), 0);
            key = path_key(1, &ingress, NULL);
        }
        struct stats *s = statistics(key);
        EQ(counted(s, 0), 1); EQ(counted(s, 1), 128);
        EQ(counted(s, 2), 1); EQ(counted(s, 3), 96); EQ(s->pending, 0);
        EQ(global_stats()->counts[0], 1); EQ(global_stats()->counts[1], 128);
        EQ(global_stats()->counts[2], 1); EQ(global_stats()->counts[3], 96);
        EQ(global_stats()->counts[7], 0);
        for (int stage = 0; stage < 3; stage++) {
            latency(&s->stages[stage], 0, 0, 0, 0);
            latency_period(key, 0, stage, 0, 0, 0, 0);
        }
        EQ(on_fragment4(&ns, NULL, &skb), 0);
        EQ(on_reassembly6(&skb), 0);
        EQ(error_count(12) + error_count(13), 1);
        EQ(error_count(6), 0); EQ(error_count(15), 0);
        EQ(error_count(16), 0);
        no_tracking();
    }
}

static void zero_min_and_histogram(void) {
    reset();
    struct sk_buff first = { .dev = &ingress, .len = 64 }, second = first;
    receive_at(&first, 100);
    EQ(on_input4(&ns, &first), 0); EQ(on_free(&first), 0);
    receive_at(&second, 101);
    clock_ns = 111;
    EQ(on_input6(&ns, &second), 0); EQ(on_free(&second), 0);
    struct stats *s = statistics(path_key(1, &ingress, NULL));
    latency(&s->stages[0], 2, 10, 0, 10);
    latency(&s->stages[2], 2, 10, 0, 10);
    struct latency combined = combined_latency(&s->stages[2]);
    EQ(combined.bins[0], 1); EQ(combined.bins[13], 1);
    struct { __u64 ns; __u32 bin; } cases[] = {
        {0, 0}, {1, 1}, {2, 2}, {3, 3}, {4, 8}, {7, 11}, {8, 12}, {15, 15},
        {16, 16}, {31, 19}, {32, 20}, {63, 23}, {64, 24}, {127, 27}, {128, 28},
        {1ULL << 32, 128}, {1ULL << 63, 252}, {UINT64_MAX, 255},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        EQ(bucket(cases[i].ns), cases[i].bin);
    struct stats histogram = {0};
    __u64 sum = 0;
    for (size_t i = 0; i < 15; i++) {
        duration(&histogram, 2, cases[i].ns, i + 1);
        sum += cases[i].ns;
        EQ(histogram.stages[2].bins[cases[i].bin], 1);
    }
    latency(&histogram.stages[2], 15, sum, 0, 128);
    cas_failures = 31;
    __u64 value = 0;
    extremum(&value, 8, 1);
    EQ(value, 8); EQ(error_count(14), 0);
    cas_failures = 32;
    extremum(&value, 4, 1);
    EQ(value, 8); EQ(error_count(14), 1);
    no_tracking();
}

static void cross_cpu_and_interval(void) {
    reset();
    struct sk_buff skb = { .dev = &ingress, .len = 64 };
    receive_routed_at(&skb, 100);
    cpu = 1;
    queue_at(&skb, &egress, 190);
    EQ(attempt_stack(0)->depth, 0); EQ(attempt_stack(1)->depth, 0);
    cpu = 2;
    attempt_at(&skb, &egress, 205);
    EQ(attempt_stack(2)->depth, 1); EQ(attempt_stack(1)->depth, 0);
    result_at(&skb, &egress, 0, 210);
    struct path key = path_key(3, &ingress, &egress);
    struct stats *lifetime = statistics(key);
    struct traffic *before = period(key, 0), *after = period(key, 1);
    EQ(counted(lifetime, 0), 1); EQ(counted(lifetime, 2), 1); EQ(lifetime->pending, 0);
    EQ(counted(before, 0), 1); EQ(counted(before, 2), 0);
    latency_period(key, 0, 2, 0, 0, 0, 0);
    EQ(counted(after, 0), 0); EQ(counted(after, 2), 1);
    latency_period(key, 1, 0, 1, 90, 90, 90);
    latency_period(key, 1, 1, 1, 15, 15, 15);
    latency_period(key, 1, 2, 1, 105, 105, 105);
    latency(&lifetime->stages[2], 1, 105, 105, 105);
    EQ(on_free(&skb), 0); no_tracking(); no_errors();
    cpu = 3;
    queue_at(&skb, &egress, 220);
    EQ(errors_on(3, 3), 1); EQ(errors_on(0, 3), 0); EQ(errors_on(2, 3), 0);
    for (unsigned int i = 0; i < CPUS; i++) {
        cpu = i;
        __u32 zero = 0;
        struct stats *initial = bpf_map_lookup_elem(&empty, &zero);
        EQ(counted(initial, 0), 0); EQ(counted(initial, 2), 0);
    }
}

static void completion_interval_uses_result_clock(void) {
    reset();
    struct sk_buff skb = { .dev = &ingress, .len = 64 };
    receive_routed_at(&skb, 100); queue_at(&skb, &egress, 120);
    attempt_at(&skb, &egress, 199);
    result_at(&skb, &egress, 0, 201);
    struct path key = path_key(3, &ingress, &egress);
    EQ(period(key, 0)->counts[2], 0); EQ(period(key, 1)->counts[2], 1);
    latency_period(key, 1, 2, 1, 99, 99, 99);
    EQ(on_free(&skb), 0); no_tracking(); no_errors();
}

static void hook_entry_timestamps(void) {
    reset();
    lookup_cost_ns = 1;
    struct sk_buff skb = { .dev = &ingress, .len = 64 };
    receive_routed_at(&skb, 100);
    EQ(origin(&skb)->birth, 100); EQ(origin(&skb)->start_ns, 100);
    queue_at(&skb, &egress, 200);
    EQ(origin(&skb)->queue_ns, 200);
    attempt_at(&skb, &egress, 300);
    EQ(attempt_stack(0)->frames[0].time_ns, 300);
    lookup_cost_ns = 0;
    result_at(&skb, &egress, 0, 310);
    struct stats *s = statistics(path_key(3, &ingress, &egress));
    latency(&s->stages[0], 1, 100, 100, 100);
    latency(&s->stages[1], 1, 100, 100, 100);
    latency(&s->stages[2], 1, 200, 200, 200);
    EQ(on_free(&skb), 0); no_tracking(); no_errors();
    reset();
    lookup_cost_ns = 1;
    skb.dev = &ingress;
    receive_at(&skb, 100);
    clock_ns = 199;
    EQ(on_input4(&ns, &skb), 0);
    CHECK(clock_ns > 200);
    lookup_cost_ns = 0;
    struct path key = path_key(1, &ingress, NULL);
    /* The wrapper's namespace lookup precedes deliver's entry timestamp. */
    latency(&statistics(key)->stages[2], 1, 100, 100, 100);
    latency_period(key, 1, 2, 1, 100, 100, 100);
    EQ(mock_map_for(&periods)->count, 1);
    EQ(on_free(&skb), 0); no_tracking(); no_errors();
}

static void disabled_interval(void) {
    reset();
    configuration()->interval_ns = 0;
    struct sk_buff skb = { .dev = &ingress, .len = 64 };
    receive_routed_at(&skb, 100); queue_at(&skb, &egress, 120);
    complete_at(&skb, &egress, 140);
    EQ(mock_map_for(&periods)->count, 0);
    latency(&statistics(path_key(3, &ingress, &egress))->stages[2], 1, 40, 40, 40);
    EQ(on_free(&skb), 0); no_tracking(); no_errors();
}

static void disabled_namespace_and_capacity(void) {
    for (int stopped_by_capacity = 0; stopped_by_capacity < 2; stopped_by_capacity++) {
        for (int tracked = 0; tracked < 2; tracked++) {
            reset();
            struct sk_buff skb = { .dev = &ingress, .len = 64 }, copy = skb;
            struct stats *s = NULL, saved = {0};
            if (tracked) {
                receive_at(&skb, 100); queue_at(&skb, &egress, 120);
                s = statistics(path_key(3, &ingress, &egress));
                saved = *s;
            }
            struct traffic saved_global = *global_stats();
            if (stopped_by_capacity) configuration()->capacity = 0;
            else configuration()->netns = 0;
            EQ(enabled(), 0);
            receive_at(&copy, 130);
            EQ(on_output4(&ns, NULL, &copy), 0);
            EQ(on_output6(&ns, NULL, &copy), 0);
            EQ(on_input4(&ns, &skb), 0); EQ(on_input6(&ns, &skb), 0);
            EQ(on_route4(&skb), 0); EQ(on_route6(&skb), 0);
            EQ(on_bridge(&ns, NULL, &skb), 0);
            EQ(on_bridge_transmit(&ns, NULL, &skb), 0);
            EQ(on_bridge_receive(&ns, NULL, &skb), 0);
            EQ(on_bridge_branch(&egress, &skb), 0);
            EQ(on_bridge_flood(NULL, &skb), 0); EQ(on_bridge_output(&skb), 0);
            EQ(on_clone(&skb, 0, &copy), 0);
            queue_at(&skb, &egress, 140); queue_at(&copy, &egress, 145);
            attempt_at(&skb, &egress, 150);
            result_at(&skb, &egress, 0, 160);
            for (int hook = 0; hook < 4; hook++) retire_with_hook(&skb, hook);
            CHECK(!origin(&copy));
            CHECK(!memcmp(global_stats(), &saved_global, sizeof(saved_global)));
            EQ(mock_map_for(&paths)->count, tracked ? 1 : 0);
            EQ(mock_map_for(&origins)->count, tracked ? 1 : 0);
            EQ(mock_map_for(&transmits)->count, tracked ? 1 : 0);
            EQ(gauge(), tracked ? 2 : 0); EQ(attempt_stack(0)->depth, 0);
            if (tracked) {
                CHECK(!memcmp(s, &saved, sizeof(saved)));
                EQ(origin(&skb)->flags, 0); EQ(origin(&skb)->delivered, 0);
            }
            no_errors();
            collect_at(100 + TIMEOUT_NS);
            EQ(error_count(5), tracked ? 2 : 0);
            no_tracking();
        }
    }
}

static void invalid_driver_result(void) {
    reset();
    struct sk_buff skb = { .dev = &ingress, .len = 64 };
    receive_routed_at(&skb, 100); queue_at(&skb, &egress, 120);
    attempt_at(&skb, &egress, 130);
    result_at(&skb, &branch, 0, 140);
    EQ(error_count(14), 1); EQ(global_stats()->counts[2], 0);
    EQ(statistics(path_key(3, &ingress, &egress))->pending, 1);
    complete_at(&skb, &egress, 150);
    EQ(on_free(&skb), 0); no_tracking();
    result_at(&skb, &egress, 0, 160);
    EQ(error_count(14), 2);
}

static void newest_completion_order_and_contention(void) {
    reset();
    struct stats s = {0};
    duration(&s, 2, 50, 100);
    duration(&s, 2, 20, 300);
    duration(&s, 2, 90, 200);
    latency(&s.stages[2], 3, 160, 20, 90);
    EQ(s.stages[2].newest_at, 300);
    EQ(s.stages[2].newest_ns, 20);
    EQ(s.stages[2].newest_seq & 1, 0);
    s.stages[2].newest_seq++;
    duration(&s, 2, 80, 400);
    EQ(s.stages[2].newest_at, 300);
    EQ(s.stages[2].newest_missed_at, 400);
    EQ(error_count(17), 1);
    s.stages[2].newest_seq++;
    duration(&s, 2, 0, 500);
    EQ(s.stages[2].newest_at, 500);
    EQ(s.stages[2].newest_ns, 0);
    latency(&s.stages[2], 5, 240, 0, 90);
}

static void single_histogram_and_capacity_fallback(void) {
    reset();
    struct sk_buff skb = { .dev = &ingress, .len = 64 };
    receive_routed_at(&skb, 100); queue_at(&skb, &egress, 120);
    complete_at(&skb, &egress, 140);
    struct path path = path_key(3, &ingress, &egress);
    struct stats *total = statistics(path);
    for (int stage = 0; stage < 3; stage++) {
        EQ(total->stages[stage].samples, 0);
        EQ(combined_latency(&total->stages[stage]).samples, 1);
    }
    EQ(on_release(&skb), 0); no_tracking(); no_errors();

    mock_map_for(&periods)->capacity = 1;
    skb.dev = &ingress;
    receive_routed_at(&skb, 200); queue_at(&skb, &egress, 220);
    complete_at(&skb, &egress, 240);
    for (int stage = 0; stage < 3; stage++) EQ(total->stages[stage].samples, 1);
    EQ(combined_latency(&total->stages[2]).samples, 2);
    CHECK(error_count(2) > 0);
    EQ(on_release(&skb), 0); no_tracking();
}

static void interval_guard_clock_nested_and_failure(void) {
    reset();
    struct path key = path_key(3, &ingress, &egress);
    struct interval_write outer = {};
    clock_ns = 199;
    lookup_cost_ns = 1;
    struct traffic *value = period_stats(&key, 199, &outer, configuration());
    CHECK(value);
    lookup_cost_ns = 0;
    EQ(outer.writer->depth, 1); EQ(outer.writer->epoch, 1);
    CHECK(value == period(key, 1));

    clock_ns = 310;
    struct interval_write nested = {};
    CHECK(period_stats(&key, 310, &nested, configuration()));
    EQ(nested.writer->depth, 2);
    EQ(nested.writer->epoch, 1);
    period_done(&nested);
    EQ(outer.writer->depth, 1);
    period_done(&outer);
    EQ(outer.writer->depth, 0);

    clock_ns = 400;
    mock_map_for(&periods)->capacity = 2;
    struct interval_write failed = {};
    CHECK(!period_stats(&key, 400, &failed, configuration()));
    EQ(failed.writer->depth, 1); EQ(failed.writer->epoch, 3);
    period_done(&failed);
    EQ(error_count(2), 1);
    no_tracking();
}

static void global_percpu_and_typed_reads(void) {
    reset();
    struct sk_buff skb = { .dev = &ingress, .len = 64 };
    receive_routed_at(&skb, 100);
    EQ(probe_reads, 0);
    cpu = 1;
    queue_at(&skb, &egress, 120);
    cpu = 2;
    complete_at(&skb, &egress, 140);
    __u32 zero = 0;
    struct traffic *cpu2 = bpf_map_lookup_elem(&global, &zero);
    EQ(cpu2->counts[0], 0); EQ(cpu2->counts[2], 1);
    cpu = 0;
    struct traffic *cpu0 = bpf_map_lookup_elem(&global, &zero);
    EQ(cpu0->counts[0], 1); EQ(cpu0->counts[2], 0);
    EQ(global_stats()->counts[0], 1); EQ(global_stats()->counts[2], 1);
    EQ(sizeof(struct traffic), 64);
    EQ(on_release(&skb), 0); no_tracking(); no_errors();
}

static void compact_period_and_grouped_timings(void) {
    reset();
    struct sk_buff skb = { .dev = &ingress, .len = 64 };
    struct path path = path_key(3, &ingress, &egress);
    receive_routed_at(&skb, 100); queue_at(&skb, &egress, 110);
    complete_at(&skb, &egress, 120); EQ(on_release(&skb), 0);
    // One grouped allocation, followed by one lookup for all three stages.
    EQ(mock_map_for(&interval_latency)->count, 1);
    __u64 lookups = mock_map_for(&interval_latency)->lookups;
    cpu = 1;
    skb.dev = &ingress;
    receive_routed_at(&skb, 130); queue_at(&skb, &egress, 140);
    complete_at(&skb, &egress, 150); EQ(on_release(&skb), 0);
    EQ(mock_map_for(&interval_latency)->lookups - lookups, 1);
    struct stats *fallback = statistics(path);
    for (int i = 0; i < 8; i++) EQ(fallback->counts[i], 0);
    EQ(counted(fallback, 2), 2);
    struct traffic *shard = period(path, 0);
    EQ(shard->counts[2], 1);
    cpu = 2;
    EQ(period(path, 0)->counts[2], 0);
    latency_period(path, 0, 0, 2, 20, 10, 10);
    latency_period(path, 0, 1, 2, 20, 10, 10);
    latency_period(path, 0, 2, 2, 40, 20, 20);
    no_tracking(); no_errors();

    // Latency capacity is independent of traffic capacity: all stages fall
    // back together, while traffic is still counted once in its CPU period.
    mock_map_for(&interval_latency)->capacity = 1;
    skb.dev = &ingress;
    receive_routed_at(&skb, 200); queue_at(&skb, &egress, 210);
    complete_at(&skb, &egress, 220); EQ(on_release(&skb), 0);
    EQ(error_count(2), 1);
    EQ(fallback->counts[2], 0); EQ(counted(fallback, 2), 3);
    for (int stage = 0; stage < 3; stage++) EQ(fallback->stages[stage].samples, 1);
    latency(&fallback->stages[2], 3, 60, 20, 20);
    no_tracking();
}

static void segmented_cached_parent_respects_stop(void) {
    reset();
    struct sk_buff parent = { .dev = &ingress, .len = 128 };
    struct sk_buff first = { .dev = &ingress, .len = 64 };
    struct sk_buff second = first;
    first.next = &second;
    receive_routed_at(&parent, 100);
    stop_after_origin = &first;
    EQ(on_segment(&parent, 0, &first), 0);
    CHECK(origin(&first)); CHECK(!origin(&second));
    EQ(configuration()->capacity, 0);
    configuration()->capacity = 512;
    EQ(on_release(&parent), 0); EQ(on_release(&first), 0);
    no_tracking();
}

static void segmented_cached_parent_respects_retirement(void) {
    reset();
    struct sk_buff parent = { .dev = &ingress, .len = 128 };
    struct sk_buff first = { .dev = &egress, .len = 64 };
    struct sk_buff second = first;
    first.next = &second;
    receive_routed_at(&parent, 100); queue_at(&parent, &egress, 120);
    struct tx_key parent_key = transmit_key(&parent);
    parent_to_expire = bpf_map_lookup_elem(&transmits, &parent_key);
    CHECK(parent_to_expire);
    expire_parent_after_origin = &first;
    EQ(on_segment(&parent, 0, &first), 0);
    CHECK(origin(&first)); CHECK(origin(&second));
    struct tx_key first_key = transmit_key(&first), second_key = transmit_key(&second);
    CHECK(!bpf_map_lookup_elem(&transmits, &first_key));
    CHECK(!bpf_map_lookup_elem(&transmits, &second_key));
    EQ(mock_map_for(&transmits)->count, 1);
    EQ(statistics(path_key(3, &ingress, &egress))->pending, 1);
    // Finish the GC that claimed the parent between cached lookup and insertion.
    pending(&parent_to_expire->path, 0);
    CHECK(!bpf_map_delete_elem(&transmits, &parent_key));
    release();
    EQ(on_release(&first), 0); EQ(on_release(&second), 0);
    EQ(on_release(&parent), 0); no_tracking(); no_errors();
}

static void receive_deduplication_at_capacity(void) {
    reset();
    configuration()->capacity = 1;
    struct sk_buff skb = { .dev = &ingress, .len = 64 };
    struct sk_buff other = { .dev = &ingress, .len = 128 };
    receive_at(&skb, 100);
    for (cpu = 0; cpu < CPUS; cpu++) receive_at(&skb, 110 + cpu);
    cpu = 0;
    EQ(gauge(), 1); EQ(origin(&skb)->birth, 100);
    EQ(global_stats()->counts[0], 1); EQ(global_stats()->counts[1], 64);
    no_errors();
    receive_at(&other, 120);
    CHECK(!origin(&other)); EQ(gauge(), 1); EQ(error_count(0), 1);
    EQ(on_input4(&ns, &skb), 0);
    EQ(on_release(&skb), 0); no_tracking();
    for (__u32 i = 1; i < ERROR_SLOTS; i++) EQ(error_count(i), 0);
}

static void simultaneous_egress_generations(void) {
    reset();
    struct sk_buff skb = { .dev = &ingress, .len = 64 };
    receive_routed_at(&skb, 100);
    queue_at(&skb, &egress, 120);
    struct tx_key first = transmit_key(&skb);
    queue_at(&skb, &branch, 125);
    struct tx_key second = transmit_key(&skb);
    EQ(first.skb, second.skb); EQ(first.birth, second.birth);
    CHECK(first.egress_generation != second.egress_generation);
    CHECK(bpf_map_lookup_elem(&transmits, &first));
    CHECK(bpf_map_lookup_elem(&transmits, &second)); EQ(gauge(), 3);
    complete_at(&skb, &egress, 130);
    complete_at(&skb, &branch, 150);
    struct stats *one = statistics(path_key(3, &ingress, &egress));
    struct stats *two = statistics(path_key(3, &ingress, &branch));
    EQ(counted(one, 0), 1); EQ(counted(one, 2), 1); EQ(one->pending, 0);
    EQ(counted(two, 0), 1); EQ(counted(two, 2), 1); EQ(two->pending, 0);
    latency(&one->stages[2], 1, 30, 30, 30);
    latency(&two->stages[2], 1, 50, 50, 50);
    EQ(on_release(&skb), 0); no_tracking(); no_errors();
}

int main(void) {
    struct { const char *name; void (*run)(void); } cases[] = {
        {"mock map and per-CPU semantics", mock_map_semantics},
        {"one histogram write and capacity fallback", single_histogram_and_capacity_fallback},
        {"interval writer registration, nesting and capacity failure", interval_guard_clock_nested_and_failure},
        {"per-CPU global totals and typed field reads", global_percpu_and_typed_reads},
        {"compact CPU periods, one S/Q/T lookup and independent fallback", compact_period_and_grouped_timings},
        {"cached GSO parent respects concurrent stop", segmented_cached_parent_respects_stop},
        {"cached GSO parent respects concurrent retirement", segmented_cached_parent_respects_retirement},
        {"newest completion ordering, bounded contention and zero duration", newest_completion_order_and_contention},
        {"receive and IPv4/IPv6 INPUT", receive_input},
        {"receive deduplication preserves full-capacity accounting", receive_deduplication_at_capacity},
        {"one skb retains separate simultaneous egress lifetimes", simultaneous_egress_generations},
        {"foreign namespace delivery cannot count as INPUT", input_namespace_isolation},
        {"namespace selection and interface generations", selection_and_generations},
        {"IPv4/IPv6 local OUTPUT dst selection", local_output_dst},
        {"unregister, ifindex reuse, deletion and new generation", unregister_and_ifindex_reuse},
        {"egress recreation isolates queued and cached attempt generations", egress_generation_isolation},
        {"FORWARD identity survives NAT", forward_nat_identity},
        {"unclassified FORWARD diagnoses once and retains flow and latency", unclassified_forward_keeps_counts_and_latency},
        {"bridge CB fallback classifies unicast without bridge hooks", bridge_cb_fallback_without_hooks},
        {"bridge CB rejects routed, foreign, absent and unreadable metadata", bridge_cb_rejects_route_metadata},
        {"bridge CB receive and INPUT alone do not mark forwarding", bridge_cb_receive_is_not_forwarding},
        {"routing from the actual bridge master is combined", routing_from_bridge_master_is_combined},
        {"bridge receive survives overwritten CB without misclassifying INPUT", bridge_receive_survives_overwritten_cb},
        {"bridge transmit callback classifies plain and overwritten CB before queue", bridge_transmit_callback_before_queue},
        {"bridge clone branches and hairpin", bridge_clone_branches},
        {"clone after queue preserves transmit state", queued_clone_inheritance},
        {"clone inheritance follows parent namespace", clone_namespace_isolation},
        {"completed clone has no phantom pending and bridge branch hook", completed_clone_has_no_phantom_pending},
        {"morph after release creates new birth and inherits source generation", morph_after_release_gets_new_identity},
        {"GSO segments before and after queue", gso_segments},
        {"bounded GSO segment walk", bounded_segment_walk},
        {"invalid and duplicate clone results", invalid_clone_results},
        {"driver BUSY retry uses successful attempt", driver_busy_retry},
        {"free during driver and skb pointer reuse", free_during_driver_pointer_reuse},
        {"nested driver attempts", nested_driver_attempts},
        {"bounded driver attempt stack", bounded_driver_stack},
        {"free/drop CAS ownership", free_drop_and_cas_ownership},
        {"release/consume/drop hooks retire once and preserve driver completion", alternate_free_hooks},
        {"cross CPU free/consume, BUSY and cached pointer reuse", cross_cpu_free_and_pointer_reuse},
        {"same/cross CPU retirement, nested attempts, BUSY and reuse", driver_frame_retirement},
        {"unselected sends skip association lookup without unbalancing attempts", reject_unselected_transmit_before_association},
        {"empty cleanup skips hash walks; live records retain exact TTL", empty_cleanup_skips_walks},
        {"exact TTL cleanup and repeated retirement", ttl_cleanup},
        {"GC snapshot predating new entries preserves both until their TTL", cleanup_snapshot_predates_new_entries},
        {"cleanup CAS loser and claimed transmit", cleanup_cas_loser},
        {"expiry during an active driver attempt", expiry_during_driver},
        {"bounded tracking capacity", bounded_tracking_capacity},
        {"racing admission and concurrent stop preserve the global bound", bounded_racing_admission_and_stop},
        {"map insertion failure releases reservations", map_failures_release_capacity},
        {"bounded path and period maps", bounded_stats_maps},
        {"unsupported fragmentation and reassembly exclude latencies", unsupported_transformations},
        {"zero minimum, histogram boundaries, CAS bounds", zero_min_and_histogram},
        {"cross CPU and cross interval accounting", cross_cpu_and_interval},
        {"completion interval follows return clock", completion_interval_uses_result_clock},
        {"entry timestamps exclude hook bookkeeping", hook_entry_timestamps},
        {"disabled interval preserves lifetime stats", disabled_interval},
        {"zero namespace or capacity disables new and existing observations", disabled_namespace_and_capacity},
        {"driver result mismatch and underflow", invalid_driver_result},
        {"CPU1 consume at CPU0 completion claim preserves accepted result", consume_during_completion_claim},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        cases[i].run();
        printf("ok %zu - %s\n", i + 1, cases[i].name);
    }
    dispose();
    printf("%zu production BPF scenarios passed\n", sizeof(cases) / sizeof(cases[0]));
    return EXIT_SUCCESS;
}
