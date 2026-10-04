// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define CORE __attribute__((preserve_access_index))
struct super_block { unsigned long s_magic; unsigned int s_dev; } CORE;
struct inode { unsigned short i_mode; unsigned long i_ino; struct super_block *i_sb; } CORE;
struct qstr { const unsigned char *name; } CORE;
struct dentry { struct qstr d_name; } CORE;
struct path { struct dentry *dentry; } CORE;
struct file { struct inode *f_inode; struct path f_path; void *private_data; } CORE;
struct fdtable { unsigned int max_fds; struct file **fd; unsigned long *close_on_exec; } CORE;
struct atomic_t { int counter; } CORE;
struct files_struct { struct atomic_t count; struct fdtable *fdt; } CORE;
struct thread_info { unsigned long flags; unsigned int status; } CORE;
struct task_struct { struct thread_info thread_info; struct files_struct *files; struct task_struct *group_leader; __u64 start_boottime; int pid, tgid; char comm[16]; } CORE;
struct sock_common { unsigned short skc_family, skc_num, skc_dport; } CORE;
struct sock { struct sock_common __sk_common; unsigned short sk_protocol; } CORE;
struct socket { struct sock *sk; } CORE;
struct net_device { char name[16]; int ifindex; } CORE;
struct xdp_sock { struct net_device *dev; unsigned int queue_id; } CORE;
struct key { __u64 start, object; __u32 pid; __s32 fd; };
struct identity {
    struct key key; __u64 ino; __u32 dev, kind; char comm[16], name[64];
    __u32 family, protocol; __u16 sport, dport; unsigned char src[16], dst[16]; __u32 pad;
};
struct event { struct identity id; __u64 ns; __u32 type, reason; __s32 source; __u32 tid, ifindex, queue; };
struct config { __u32 pid, own; __s32 fd; __u32 enabled; };
struct call { __u32 op; __s32 source; };
struct enter_ctx { __u64 unused; __s64 id; __u64 args[6]; };
struct exit_ctx { __u64 unused; __s64 id, ret; };
struct pair { struct event old, new; __u32 has_old; };
#define HASH(n,k,v,s) struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,s); __type(key,k); __type(value,v); } n SEC(".maps")
#define ARRAY(n,v,s) struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,s); __type(key,__u32); __type(value,v); } n SEC(".maps")
#define SCRATCH(n,v) struct { __uint(type,BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,v); } n SEC(".maps")
struct { __uint(type,BPF_MAP_TYPE_RINGBUF); __uint(max_entries,1<<22); } events SEC(".maps");
HASH(objects,__u64,__u64,65536);
HASH(calls,__u64,struct call,16384);
HASH(dups,__u64,struct pair,4096);
HASH(exiting,__u64,__u64,16384);
ARRAY(settings,struct config,1);
ARRAY(operations,__u32,512);
ARRAY(sequence,__u64,1);
ARRAY(losses,__u64,4); // ring full, read error, map capacity, scan truncated
SCRATCH(scratch,struct pair);

static __always_inline void loss(__u32 n) {
    __u64 *v=bpf_map_lookup_elem(&losses,&n); if(v) __sync_fetch_and_add(v,1);
}
static __always_inline int selected(struct task_struct *task) {
    __u32 zero=0; struct config *c=bpf_map_lookup_elem(&settings,&zero);
    __u32 pid=BPF_CORE_READ(task,tgid);
    return c && c->enabled && pid!=c->own && (!c->pid || c->pid==pid);
}
static __always_inline struct file *lookup(struct files_struct *files,__u32 fd) {
    struct fdtable *table=BPF_CORE_READ(files,fdt);
    if(!table || fd>=BPF_CORE_READ(table,max_fds)) return 0;
    struct file **fds=BPF_CORE_READ(table,fd), *file=0;
    if(bpf_probe_read_kernel(&file,sizeof(file),&fds[fd])) loss(1);
    return file;
}
static __always_inline void fill(struct event *e,struct task_struct *task,struct file *file,__u32 fd,__u32 type,__u32 reason) {
    __builtin_memset(e,0,sizeof(*e));
    e->ns=bpf_ktime_get_ns(); e->type=type; e->reason=reason; e->source=-1;
    e->tid=BPF_CORE_READ(task,pid); e->id.key.pid=BPF_CORE_READ(task,tgid); e->id.key.fd=fd;
    struct task_struct *leader=BPF_CORE_READ(task,group_leader);
    e->id.key.start=BPF_CORE_READ(leader,start_boottime);
    BPF_CORE_READ_INTO(&e->id.comm,leader,comm);
    __u64 ptr=(__u64)file; __u32 zero=0;
    __u64 *cookie=bpf_map_lookup_elem(&objects,&ptr);
    if(!cookie) {
        __u64 *seq=bpf_map_lookup_elem(&sequence,&zero);
        if(seq) { __u64 value=__sync_fetch_and_add(seq,1)+1; bpf_map_update_elem(&objects,&ptr,&value,BPF_NOEXIST); }
        cookie=bpf_map_lookup_elem(&objects,&ptr);
    }
    if(cookie) e->id.key.object=*cookie; else loss(2);
    struct inode *inode=BPF_CORE_READ(file,f_inode);
    __u16 mode=BPF_CORE_READ(inode,i_mode)&0170000;
    unsigned long magic=BPF_CORE_READ(inode,i_sb,s_magic);
    e->id.ino=BPF_CORE_READ(inode,i_ino); e->id.dev=BPF_CORE_READ(inode,i_sb,s_dev);
    e->id.kind=mode==0100000?1:mode==0140000?2:mode==0010000?3:mode==0020000?4:mode==0060000?5:0;
    if(magic==0x19800202) e->id.kind=6;
    if(magic==0x09041934) e->id.kind=7;
    const unsigned char *name=BPF_CORE_READ(file,f_path.dentry,d_name.name);
    if(bpf_probe_read_kernel_str(e->id.name,sizeof(e->id.name),name)<0) loss(1);
    if(e->id.kind==2) {
        struct socket *s=BPF_CORE_READ(file,private_data); struct sock *sk=BPF_CORE_READ(s,sk);
        e->id.family=BPF_CORE_READ(sk,__sk_common.skc_family); e->id.protocol=BPF_CORE_READ(sk,sk_protocol);
        if(e->id.family==44 && bpf_core_type_exists(struct xdp_sock)) {
            struct xdp_sock *xsk=(void*)sk; struct net_device *dev=BPF_CORE_READ(xsk,dev);
            if(dev) { e->ifindex=BPF_CORE_READ(dev,ifindex); e->queue=BPF_CORE_READ(xsk,queue_id); bpf_core_read(e->id.name,16,&dev->name); }
        }
    }
}
static __always_inline void send(struct event *e) {
    __u32 zero=0; struct config *cfg=bpf_map_lookup_elem(&settings,&zero);
    if(!cfg || (cfg->fd>=0 && cfg->fd!=e->id.key.fd)) return;
    if(bpf_ringbuf_output(&events,e,sizeof(*e),0)) loss(0);
}
static __always_inline void emit(struct task_struct *task,struct file *file,__u32 fd,__u32 type,__u32 reason) {
    __u32 zero=0; struct pair *s=bpf_map_lookup_elem(&scratch,&zero);
    if(!s || !file) return;
    fill(&s->new,task,file,fd,type,reason);
    __u64 tid=bpf_get_current_pid_tgid(); struct call *c=bpf_map_lookup_elem(&calls,&tid);
    if(type==1 && c && c->op==1) { s->new.type=2; s->new.source=c->source; }
    send(&s->new);
}
SEC("fentry/fd_install")
int BPF_PROG(install,unsigned int fd,struct file *file) {
    struct task_struct *task=(void*)bpf_get_current_task_btf();
    if(selected(task)) emit(task,file,fd,1,0); return 0;
}
SEC("fexit/file_close_fd_locked")
int BPF_PROG(remove_fd,struct files_struct *files,unsigned int fd,struct file *ret) {
    struct task_struct *task=(void*)bpf_get_current_task_btf();
    if(ret && selected(task)) emit(task,ret,fd,3,0); return 0;
}
SEC("fentry/do_dup2")
int BPF_PROG(dup_enter,struct files_struct *files,struct file *file,unsigned int fd,unsigned int flags) {
    struct task_struct *task=(void*)bpf_get_current_task_btf(); if(!selected(task)) return 0;
    __u32 zero=0; __u64 tid=bpf_get_current_pid_tgid(); struct pair *s=bpf_map_lookup_elem(&scratch,&zero);
    if(!s) return 0; __builtin_memset(s,0,sizeof(*s));
    struct file *old=lookup(files,fd); s->has_old=old!=0;
    if(old) fill(&s->old,task,old,fd,3,1);
    fill(&s->new,task,file,fd,2,1);
    struct call *c=bpf_map_lookup_elem(&calls,&tid); if(c && c->op==1) s->new.source=c->source;
    if(bpf_map_update_elem(&dups,&tid,s,BPF_ANY)) loss(2); return 0;
}
SEC("fexit/do_dup2")
int BPF_PROG(dup_exit,struct files_struct *files,struct file *file,unsigned int fd,unsigned int flags,int ret) {
    __u64 tid=bpf_get_current_pid_tgid(); struct pair *s=bpf_map_lookup_elem(&dups,&tid);
    if(!s) return 0;
    if(ret>=0) { if(s->has_old) send(&s->old); send(&s->new); }
    bpf_map_delete_elem(&dups,&tid); return 0;
}
struct scan { __u64 files, task; __u32 type, reason; };
static long visit(__u32 fd,struct scan *ctx) {
    struct files_struct *files=(void*)ctx->files;
    struct task_struct *task=(void*)ctx->task;
    struct fdtable *table=BPF_CORE_READ(files,fdt);
    if(ctx->reason==2) {
        unsigned long *bits=BPF_CORE_READ(table,close_on_exec), word=0;
        if(bpf_probe_read_kernel(&word,sizeof(word),&bits[fd/64])) { loss(1); return 0; }
        if(!(word&(1UL<<(fd%64)))) return 0;
    }
    struct file *file=lookup(files,fd);
    if(file) emit(task,file,fd,ctx->type,ctx->reason);
    return 0;
}
static __always_inline void scan_files(struct task_struct *task,struct files_struct *files,__u32 type,__u32 reason) {
    if(!files || !selected(task)) return;
    __u32 count=BPF_CORE_READ(files,fdt,max_fds);
    if(count>65536) { count=65536; loss(3); }
    struct scan ctx={.task=(__u64)task,.files=(__u64)files,.type=type,.reason=reason};
    bpf_loop(count,visit,&ctx,0);
}
SEC("fentry/do_close_on_exec")
int BPF_PROG(exec_close,struct files_struct *files) {
    scan_files((void*)bpf_get_current_task_btf(),files,3,2); return 0;
}
SEC("fentry/put_files_struct")
int BPF_PROG(table_release,struct files_struct *files) {
    struct task_struct *task=(void*)bpf_get_current_task_btf();
    __u64 tid=bpf_get_current_pid_tgid(), *exit_files=bpf_map_lookup_elem(&exiting,&tid);
    // Ignore cleanup of a newly allocated table on failed fork/unshare. It was
    // never this task's live table and must not look like its FDs were closed.
    if((BPF_CORE_READ(task,files)==files || (exit_files && *exit_files==(__u64)files)) && BPF_CORE_READ(files,count.counter)==1)
        scan_files(task,files,3,3);
    return 0;
}
SEC("fentry/exit_files")
int BPF_PROG(detach_enter,struct task_struct *task) {
    if(!selected(task)) return 0;
    __u64 tid=bpf_get_current_pid_tgid(), files=(__u64)BPF_CORE_READ(task,files);
    if(bpf_map_update_elem(&exiting,&tid,&files,BPF_ANY)) loss(2); return 0;
}
SEC("fexit/exit_files")
int BPF_PROG(detach_exit,struct task_struct *task) {
    __u64 tid=bpf_get_current_pid_tgid(); bpf_map_delete_elem(&exiting,&tid); return 0;
}
SEC("tp_btf/sched_process_fork")
int BPF_PROG(inherit,struct task_struct *parent,struct task_struct *child) {
    if(BPF_CORE_READ(parent,tgid)!=BPF_CORE_READ(child,tgid)) scan_files(child,BPF_CORE_READ(child,files),4,4);
    return 0;
}
SEC("fentry/__fput")
int BPF_PROG(retire,struct file *file) { __u64 ptr=(__u64)file; bpf_map_delete_elem(&objects,&ptr); return 0; }
SEC("tracepoint/raw_syscalls/sys_enter")
int event_enter(struct enter_ctx *ctx) {
    struct task_struct *task=(void*)bpf_get_current_task_btf(); if(!selected(task)) return 0;
    // Core install/remove hooks are ABI-independent. Skip native syscall
    // decoding for compat tasks rather than mislabeling DUP or UPDATE.
#ifdef __TARGET_ARCH_x86
    if((ctx->id&0x40000000) || (BPF_CORE_READ(task,thread_info.status)&2)) return 0;
#else
    if(BPF_CORE_READ(task,thread_info.flags)&(1UL<<22)) return 0;
#endif
    __u32 nr=ctx->id; __u32 *op=bpf_map_lookup_elem(&operations,&nr);
    if(!op || !*op) return 0;
    // fcntl is classified separately: only F_DUPFD/F_DUPFD_CLOEXEC duplicate.
    if(*op==3 && ctx->args[1]!=0 && ctx->args[1]!=1030) return 0;
    struct call c={.op=*op==3?1:*op,.source=ctx->args[0]}; __u64 tid=bpf_get_current_pid_tgid();
    if(bpf_map_update_elem(&calls,&tid,&c,BPF_ANY)) loss(2); return 0;
}
SEC("tracepoint/raw_syscalls/sys_exit")
int event_exit(struct exit_ctx *ctx) {
    __u64 tid=bpf_get_current_pid_tgid(); struct call *c=bpf_map_lookup_elem(&calls,&tid);
    if(!c) return 0;
    if(c->op==2 && (ctx->ret==0 || ctx->ret==-115)) {
        struct task_struct *task=(void*)bpf_get_current_task_btf();
        struct file *file=lookup(BPF_CORE_READ(task,files),c->source);
        if(file) emit(task,file,c->source,5,5);
    }
    bpf_map_delete_elem(&calls,&tid); return 0;
}
SEC("tp_btf/sched_process_exit")
int BPF_PROG(task_exit,struct task_struct *task) {
    __u64 tid=bpf_get_current_pid_tgid(); bpf_map_delete_elem(&calls,&tid); bpf_map_delete_elem(&dups,&tid); bpf_map_delete_elem(&exiting,&tid); return 0;
}
char LICENSE[] SEC("license")="GPL";
