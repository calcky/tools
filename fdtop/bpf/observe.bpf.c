// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef FDTOP_LATENCY
#define FDTOP_LATENCY 1
#endif

#define CORE __attribute__((preserve_access_index))
struct super_block { unsigned long s_magic; unsigned int s_dev; } CORE;
struct inode { unsigned short i_mode; unsigned long i_ino; struct super_block *i_sb; } CORE;
struct qstr { const unsigned char *name; } CORE;
struct dentry { struct qstr d_name; } CORE;
struct path { struct dentry *dentry; } CORE;
struct file { struct inode *f_inode; struct path f_path; void *private_data; } CORE;
struct fdtable { unsigned int max_fds; struct file **fd; } CORE;
struct files_struct { struct fdtable *fdt; } CORE;
struct thread_info { unsigned long flags; unsigned int status; } CORE;
struct task_struct {
    struct thread_info thread_info;
    struct files_struct *files;
    struct task_struct *group_leader;
    __u64 start_boottime;
    char comm[16];
} CORE;
struct sock_common {
    unsigned short skc_family;
    unsigned short skc_num;
    unsigned short skc_dport;
    unsigned int skc_rcv_saddr;
    unsigned int skc_daddr;
    struct { unsigned char bytes[16]; } skc_v6_rcv_saddr, skc_v6_daddr;
} CORE;
struct sock { struct sock_common __sk_common; unsigned short sk_protocol; } CORE;
struct socket { struct sock *sk; } CORE;

struct key { __u64 start, object; __u32 pid; __s32 fd; };
struct identity {
    struct key key;
    __u64 ino;
    __u32 dev, kind;
    char comm[16], name[64];
    __u32 family, protocol;
    __u16 sport, dport;
    unsigned char src[16], dst[16];
    __u32 pad;
};
struct metrics { __u64 bytes, ops, errors, again, restarts, ns, max_ns, hist[32]; };
struct record { struct identity id; struct metrics rd, wr; __u64 calls, last_ns; };
struct pending {
    struct key first, second;
    __u64 since, addr, requested;
    __u32 op, two;
};
struct config { __u32 pid, own; __s32 fd; __u32 pad; };
struct enter_ctx { __u64 unused; __s64 id; __u64 args[6]; };
struct exit_ctx { __u64 unused; __s64 id, ret; };

#define HASH(name, k, v, size) struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, size); __type(key, k); __type(value, v); } name SEC(".maps")
#define ARRAY(name, v, size) struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, size); __type(key, __u32); __type(value, v); } name SEC(".maps")
#define SCRATCH(name, v) struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, v); } name SEC(".maps")
HASH(records, struct key, struct record, 16384);
HASH(inflight, __u64, struct pending, 16384);
HASH(objects, __u64, __u64, 65536);
HASH(retired, __u64, __u8, 65536);
ARRAY(operations, __u32, 512);
ARRAY(settings, struct config, 1);
ARRAY(sequence, __u64, 1);
// Capacity, metadata/read failure, batch-read failure, compat calls, restarts.
ARRAY(gaps, __u64, 5);
SCRATCH(record_scratch, struct record);
SCRATCH(pending_scratch, struct pending);

static __always_inline void gap(__u32 reason) {
    __u64 *n = bpf_map_lookup_elem(&gaps, &reason);
    if (n) __sync_fetch_and_add(n, 1);
}

static __always_inline int identify(struct task_struct *task, __s32 fd, struct key *key) {
    __u32 zero = 0;
    key->pid = bpf_get_current_pid_tgid() >> 32;
    // current_task_btf supplies typed pointers: CO-RE loads avoid a helper call
    // for each pointer hop. The variable FD lookup still uses a checked read.
    struct task_struct *leader = task->group_leader;
    struct files_struct *files = task->files;
    if (!leader || !files) { gap(1); return -1; }
    key->start = leader->start_boottime;
    key->fd = fd;
    struct fdtable *fdt = files->fdt;
    if (!fdt) { gap(1); return -1; }
    struct file **fds = fdt->fd;
    struct file *file = 0;
    if (fd >= 0 && (__u32)fd < fdt->max_fds) {
        if (bpf_probe_read_kernel(&file, sizeof(file), &fds[fd])) gap(1);
    }
    if (file) {
        __u64 ptr = (__u64)file;
        __u64 *object = bpf_map_lookup_elem(&objects, &ptr);
        if (!object) {
            __u64 *seq = bpf_map_lookup_elem(&sequence, &zero);
            if (!seq) return -1;
            __u64 value = __sync_fetch_and_add(seq, 1) + 1;
            bpf_map_update_elem(&objects, &ptr, &value, BPF_NOEXIST);
            object = bpf_map_lookup_elem(&objects, &ptr);
        }
        if (!object) { gap(0); return -1; }
        key->object = *object;
    }
    struct record *existing = bpf_map_lookup_elem(&records, key);
    if (existing) {
        BPF_CORE_READ_INTO(&existing->id.comm, leader, comm);
        return 0;
    }
    // Most calls reuse an existing record; initialize metadata only on a miss.
    struct record *r = bpf_map_lookup_elem(&record_scratch, &zero);
    if (!r) return -1;
    __builtin_memset(r, 0, sizeof(*r));
    r->id.key = *key;
    BPF_CORE_READ_INTO(&r->id.comm, leader, comm);
    if (file) {
        struct inode *inode = BPF_CORE_READ(file, f_inode);
        __u16 mode = BPF_CORE_READ(inode, i_mode) & 0170000;
        unsigned long magic = BPF_CORE_READ(inode, i_sb, s_magic);
        r->id.ino = BPF_CORE_READ(inode, i_ino);
        r->id.dev = BPF_CORE_READ(inode, i_sb, s_dev);
        r->id.kind = mode == 0100000 ? 1 : mode == 0140000 ? 2 :
                     mode == 0010000 ? 3 : mode == 0020000 ? 4 : mode == 0060000 ? 5 : 0;
        if (magic == 0x19800202) r->id.kind = 6;
        if (magic == 0x09041934) r->id.kind = 7;
        const unsigned char *name = BPF_CORE_READ(file, f_path.dentry, d_name.name);
        if (bpf_probe_read_kernel_str(r->id.name, sizeof(r->id.name), name) < 0) gap(1);
        if (r->id.kind == 2) {
            struct socket *sock = BPF_CORE_READ(file, private_data);
            struct sock *sk = BPF_CORE_READ(sock, sk);
            r->id.family = BPF_CORE_READ(sk, __sk_common.skc_family);
            r->id.protocol = BPF_CORE_READ(sk, sk_protocol);
            r->id.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
            r->id.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
            if (r->id.family == 2) {
                __u32 src = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
                __u32 dst = BPF_CORE_READ(sk, __sk_common.skc_daddr);
                __builtin_memcpy(r->id.src, &src, 4);
                __builtin_memcpy(r->id.dst, &dst, 4);
            } else if (r->id.family == 10) {
                bpf_core_read(r->id.src, 16, &sk->__sk_common.skc_v6_rcv_saddr);
                bpf_core_read(r->id.dst, 16, &sk->__sk_common.skc_v6_daddr);
            }
        }
    }
    if (bpf_map_update_elem(&records, key, r, BPF_NOEXIST) &&
        !bpf_map_lookup_elem(&records, key)) { gap(0); return -1; }
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter(struct enter_ctx *ctx) {
    __u32 zero = 0, nr = ctx->id;
    struct config *cfg = bpf_map_lookup_elem(&settings, &zero);
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;
    if (!cfg || pid == cfg->own || (cfg->pid && cfg->pid != pid)) return 0;
    struct task_struct *task = (void *)bpf_get_current_task_btf();
#ifdef __TARGET_ARCH_x86
    if ((nr & 0x40000000) || (task->thread_info.status & 2)) { gap(3); return 0; }
#else
    if (task->thread_info.flags & (1UL << 22)) { gap(3); return 0; }
#endif
    __u32 *op = bpf_map_lookup_elem(&operations, &nr);
    if (!op || !*op) return 0;
    struct pending *p = bpf_map_lookup_elem(&pending_scratch, &zero);
    if (!p) return 0;
    __builtin_memset(p, 0, sizeof(*p));
    if (FDTOP_LATENCY) p->since = bpf_ktime_get_ns();
    p->op = *op;
    p->addr = ctx->args[1];
    p->requested = ctx->args[2];
    __s32 first = ctx->args[0], second = -1;
    if (p->op == 6) { first = ctx->args[1]; second = ctx->args[0]; p->two = 1; }
    if (p->op == 7 || p->op == 8) { second = ctx->args[2]; p->two = 1; }
    if (p->op == 9) { second = ctx->args[1]; p->two = 1; }
    if (cfg->fd >= 0 && first != cfg->fd && (!p->two || second != cfg->fd)) return 0;
    if (identify(task, first, &p->first)) return 0;
    if (p->two && identify(task, second, &p->second)) return 0;
    if (bpf_map_update_elem(&inflight, &tid, p, BPF_ANY)) gap(0);
    return 0;
}

struct batch { __u64 addr, total; __u32 failed; };
static long sum_message(__u32 i, struct batch *b) {
    __u32 len = 0;
    // Native 64-bit mmsghdr: 56-byte msghdr + msg_len + padding.
    if (bpf_probe_read_user(&len, sizeof(len), (void *)(b->addr + (__u64)i * 64 + 56))) {
        b->failed = 1;
        return 1;
    }
    b->total += len;
    return 0;
}

static __always_inline void account(struct key *key, int write, __s64 ret,
                                     __u64 bytes, __u64 ns, __u64 at, int credit) {
    struct record *r = bpf_map_lookup_elem(&records, key);
    if (!r) { gap(0); return; }
    struct metrics *m = write ? &r->wr : &r->rd;
    __sync_fetch_and_add(&m->ops, 1);
    __sync_fetch_and_add(&m->bytes, bytes);
    if (FDTOP_LATENCY) __sync_fetch_and_add(&m->ns, ns);
    if (ret == -11) __sync_fetch_and_add(&m->again, 1);
    else if (ret <= -512 && ret >= -516) __sync_fetch_and_add(&m->restarts, 1);
    else if (ret < 0) __sync_fetch_and_add(&m->errors, 1);
    if (FDTOP_LATENCY) {
        // Bounded compare-and-swap keeps the maximum under concurrent I/O.
        __u64 old = m->max_ns;
        for (int i = 0; i < 8 && ns > old; i++) {
            __u64 seen = __sync_val_compare_and_swap(&m->max_ns, old, ns);
            if (seen == old) break;
            old = seen;
        }
        __u64 us = ns / 1000;
        __u32 bucket = 0;
        for (int i = 0; i < 31; i++) {
            if (us <= 1) break;
            us >>= 1;
            bucket++;
        }
        __sync_fetch_and_add(&m->hist[bucket], 1);
    }
    if (credit) __sync_fetch_and_add(&r->calls, 1);
    r->last_ns = at;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int leave(struct exit_ctx *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    struct pending *p = bpf_map_lookup_elem(&inflight, &tid);
    if (!p) return 0;
    __u64 at = FDTOP_LATENCY ? bpf_ktime_get_ns() : 0;
    __u64 ns = FDTOP_LATENCY ? at - p->since : 0;
    __u64 bytes = ctx->ret > 0 ? ctx->ret : 0;
    if (p->op == 5 && ctx->ret == 0) bytes = p->requested;
    if ((p->op == 3 || p->op == 4) && ctx->ret > 0) {
        struct batch b = { .addr = p->addr };
        __u32 count = ctx->ret > 1024 ? 1024 : ctx->ret;
        bpf_loop(count, sum_message, &b, 0);
        if (b.failed || ctx->ret > 1024) gap(2);
        bytes = b.failed ? 0 : b.total;
    }
    if (ctx->ret <= -512 && ctx->ret >= -516) gap(4);
    account(&p->first, p->op == 2 || p->op == 3 || p->op == 5,
            ctx->ret, bytes, ns, at, 1);
    if (p->two) account(&p->second, 1, ctx->ret, bytes, ns, at, 0);
    bpf_map_delete_elem(&inflight, &tid);
    return 0;
}

SEC("fentry/__fput")
int BPF_PROG(release_file, struct file *file) {
    __u64 ptr = (__u64)file;
    __u64 *id = bpf_map_lookup_elem(&objects, &ptr);
    if (id) {
        __u64 object = *id;
        __u8 one = 1;
        if (bpf_map_update_elem(&retired, &object, &one, BPF_ANY)) gap(0);
        bpf_map_delete_elem(&objects, &ptr);
    }
    return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(exit_task, struct task_struct *task) {
    __u64 tid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&inflight, &tid);
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
