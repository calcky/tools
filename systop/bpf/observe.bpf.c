// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define MAX_SYSCALL 1024
#define PROC_CAPACITY 65536
#define LATENCY_BUCKETS 32

struct task_struct {
    unsigned long long start_time;
    struct task_struct *group_leader;
    char comm[16];
} __attribute__((preserve_access_index));

struct proc_key {
    __u64 start;
    __u32 tgid;
    __u32 id;
};

struct thread_key {
    __u64 start;
    __u32 tid;
    __u32 id;
};

struct proc_value {
    __u64 count;
    char comm[16];
    __u64 completed;
    __u64 total_ns;
};

struct syscall_start {
    __u64 at;
    struct proc_key key;
    struct thread_key thread;
};

struct latency_value {
    __u64 completed;
    __u64 total_ns;
    __u64 buckets[LATENCY_BUCKETS];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_SYSCALL);
    __type(key, __u32);
    __type(value, __u64);
} syscall_counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, PROC_CAPACITY);
    __type(key, struct proc_key);
    __type(value, struct proc_value);
} proc_calls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, PROC_CAPACITY);
    __type(key, struct thread_key);
    __type(value, struct proc_value);
} thread_calls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PROC_CAPACITY);
    __type(key, __u64);
    __type(value, struct syscall_start);
} syscall_starts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, MAX_SYSCALL);
    __type(key, __u32);
    __type(value, struct latency_value);
} syscall_latency SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} errors SEC(".maps");

static __always_inline void error(__u32 index) {
    __u64 *count = bpf_map_lookup_elem(&errors, &index);
    if (count) (*count)++;
}

static __always_inline __u32 log2_us(__u64 value) {
    __u32 bucket = 0;
    if (value >> 32) { value >>= 32; bucket += 32; }
    if (value >> 16) { value >>= 16; bucket += 16; }
    if (value >> 8) { value >>= 8; bucket += 8; }
    if (value >> 4) { value >>= 4; bucket += 4; }
    if (value >> 2) { value >>= 2; bucket += 2; }
    if (value >> 1) bucket++;
    return bucket >= LATENCY_BUCKETS ? LATENCY_BUCKETS - 1 : bucket;
}

SEC("raw_tp/sys_enter")
int on_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
    __u32 id = (__u32)ctx->args[1];
    if (id >= MAX_SYSCALL) {
        error(0);
        return 0;
    }
    __u64 *total = bpf_map_lookup_elem(&syscall_counts, &id);
    if (total) (*total)++;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct task_struct *leader = BPF_CORE_READ(task, group_leader);
    if (!leader) {
        error(1);
        return 0;
    }
    struct proc_key key = {
        .start = BPF_CORE_READ(leader, start_time),
        .tgid = bpf_get_current_pid_tgid() >> 32,
        .id = id,
    };
    struct proc_value *value = bpf_map_lookup_elem(&proc_calls, &key);
    if (!value) {
        struct proc_value initial = {};
        bpf_core_read_str(initial.comm, sizeof(initial.comm), &leader->comm);
        bpf_map_update_elem(&proc_calls, &key, &initial, BPF_NOEXIST);
        value = bpf_map_lookup_elem(&proc_calls, &key);
    }
    if (value) __sync_fetch_and_add(&value->count, 1);
    else error(1);
    return 0;
}

SEC("raw_tp/sys_enter")
int on_thread_enter(struct bpf_raw_tracepoint_args *ctx) {
    __u32 id = (__u32)ctx->args[1];
    if (id >= MAX_SYSCALL) return 0;
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    __u32 zero = 0;
    __u32 *target = bpf_map_lookup_elem(&target_pid, &zero);
    if (!target || *target != tgid) return 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct thread_key thread = {
        .start = BPF_CORE_READ(task, start_time),
        .tid = (__u32)bpf_get_current_pid_tgid(),
        .id = id,
    };
    struct proc_value *thread_value = bpf_map_lookup_elem(&thread_calls, &thread);
    if (!thread_value) {
        struct proc_value initial = {};
        bpf_core_read_str(initial.comm, sizeof(initial.comm), &task->comm);
        bpf_map_update_elem(&thread_calls, &thread, &initial, BPF_NOEXIST);
        thread_value = bpf_map_lookup_elem(&thread_calls, &thread);
    }
    if (thread_value) __sync_fetch_and_add(&thread_value->count, 1);
    else error(7);
    return 0;
}

SEC("raw_tp/sys_enter")
int on_latency_enter(struct bpf_raw_tracepoint_args *ctx) {
    __u32 id = (__u32)ctx->args[1];
    if (id >= MAX_SYSCALL) return 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct task_struct *leader = BPF_CORE_READ(task, group_leader);
    if (!leader) return 0;
    struct syscall_start start = {
        .at = bpf_ktime_get_ns(),
        .key = {
            .start = BPF_CORE_READ(leader, start_time),
            .tgid = bpf_get_current_pid_tgid() >> 32,
            .id = id,
        },
    };
    __u32 zero = 0;
    __u32 *target = bpf_map_lookup_elem(&target_pid, &zero);
    if (target && *target == start.key.tgid) {
        start.thread.start = BPF_CORE_READ(task, start_time);
        start.thread.tid = (__u32)bpf_get_current_pid_tgid();
        start.thread.id = id;
    }
    __u64 thread = bpf_get_current_pid_tgid();
    if (bpf_map_update_elem(&syscall_starts, &thread, &start, BPF_ANY)) error(3);
    return 0;
}

SEC("raw_tp/sys_exit")
int on_latency_exit(struct bpf_raw_tracepoint_args *ctx) {
    (void)ctx;
    __u64 thread = bpf_get_current_pid_tgid();
    struct syscall_start *entry = bpf_map_lookup_elem(&syscall_starts, &thread);
    if (!entry) {
        error(4); // Also expected for calls already in progress when tracing began.
        return 0;
    }
    struct syscall_start start = *entry;
    bpf_map_delete_elem(&syscall_starts, &thread);
    __u64 ns = bpf_ktime_get_ns() - start.at;
    __u32 id = start.key.id;
    struct latency_value *latency = bpf_map_lookup_elem(&syscall_latency, &id);
    if (!latency) {
        struct latency_value initial = {};
        bpf_map_update_elem(&syscall_latency, &id, &initial, BPF_NOEXIST);
        latency = bpf_map_lookup_elem(&syscall_latency, &id);
    }
    if (latency) {
        latency->completed++;
        latency->total_ns += ns;
        __u64 us = ns / 1000;
        __u32 bucket = log2_us(us);
        latency->buckets[bucket]++;
    } else {
        error(2);
    }
    struct proc_value *process = bpf_map_lookup_elem(&proc_calls, &start.key);
    if (process) {
        __sync_fetch_and_add(&process->completed, 1);
        __sync_fetch_and_add(&process->total_ns, ns);
    } else error(5);
    if (start.thread.tid) {
        struct proc_value *thread_value = bpf_map_lookup_elem(&thread_calls, &start.thread);
        if (thread_value) {
            __sync_fetch_and_add(&thread_value->completed, 1);
            __sync_fetch_and_add(&thread_value->total_ns, ns);
        } else error(7);
    }
    return 0;
}

SEC("raw_tp/sched_process_exit")
int on_thread_exit(struct bpf_raw_tracepoint_args *ctx) {
    (void)ctx;
    __u64 thread = bpf_get_current_pid_tgid();
    if (bpf_map_delete_elem(&syscall_starts, &thread) == 0) error(6);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
