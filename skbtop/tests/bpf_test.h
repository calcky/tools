/* SPDX-License-Identifier: GPL-2.0 */
#ifndef SKBTOP_BPF_TEST_H
#define SKBTOP_BPF_TEST_H

#include <linux/bpf.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Keep the production map declarations and probe arguments visible to C. */
#define SEC(section)
#define __uint(name, value) int (*name)[value]
#define __type(name, type) type *name
#define BPF_PROG(name, ...) name(__VA_ARGS__)
#define BPF_CORE_READ(source, field) ({ \
    __typeof__((source)->field) read_value = {0}; \
    bpf_core_read(&read_value, sizeof(read_value), &(source)->field); \
    read_value; \
})
#define BPF_CORE_READ_BITFIELD_PROBED(source, field) ((__u64)BPF_CORE_READ(source, field))
#define bpf_core_field_size(field) sizeof(field)
static unsigned int probe_reads;
static inline int bpf_core_read(void *destination, size_t size, const void *source) {
    probe_reads++;
    /* Fixtures use low unmapped addresses to model failed kernel reads. */
    if ((uintptr_t)source < 4096) return -EFAULT;
    memcpy(destination, source, size);
    return 0;
}
#define preserve_access_index unused

struct mock_entry {
    struct mock_entry *next;
    void *key, *values;
    bool live;
};

struct mock_map {
    void *identity;
    size_t key_size, value_size, capacity, count;
    bool array, percpu;
    struct mock_entry *entries;
    void *values;
    unsigned int reject_updates;
    unsigned int lookups;
    unsigned int walks;
};

static void *bpf_map_lookup_elem(void *map, const void *key);
static long bpf_map_update_elem(void *map, const void *key, const void *value, __u64 flags);
static long bpf_map_delete_elem(void *map, const void *key);
static __u64 bpf_ktime_get_ns(void);
static struct mock_map *mock_map_for(void *identity);
static __u64 mock_compare_swap(__u64 *field, __u64 old, __u64 next);
static void mock_before_add(void *field);
static inline long bpf_loop(__u32 loops, long (*callback)(__u32, void *),
        void *context, __u64 flags) {
    if (flags) return -EINVAL;
    for (__u32 i = 0; i < loops; i++) {
        long stop = callback(i, context);
        if (stop) return i + 1;
    }
    return loops;
}

/* Invoke callbacks with their declared types, including deletion during GC. */
#define bpf_for_each_map_elem(map, callback, context, flags) ({ \
    struct mock_map *mock = mock_map_for(map); \
    mock->walks++; \
    __u64 visited = 0; \
    (void)(flags); \
    for (struct mock_entry *entry = mock->entries; entry; entry = entry->next) { \
        if (!entry->live) continue; \
        visited++; \
        if (callback((map), (__typeof__((map)->key))entry->key, \
                     (__typeof__((map)->value))entry->values, (context))) break; \
    } \
    visited; \
})

/* Failure injection leaves native atomic success semantics intact. */
#define __sync_val_compare_and_swap(field, old, next) \
    mock_compare_swap((field), (old), (next))
#define __sync_fetch_and_add(field, amount) ({ \
    __typeof__(field) atomic_field = (field); \
    mock_before_add(atomic_field); \
    __atomic_fetch_add(atomic_field, (amount), __ATOMIC_SEQ_CST); \
})

#endif
