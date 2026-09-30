// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} dev_targets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CPUMAP);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct bpf_cpumap_val);
} cpu_targets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target_cpu SEC(".maps");

SEC("xdp")
int dev_redirect(struct xdp_md *ctx)
{
    __u32 key = 0;
    return bpf_redirect_map(&dev_targets, key, XDP_PASS);
}

SEC("xdp")
int cpu_redirect(struct xdp_md *ctx)
{
    __u32 key = 0;
    __u32 *cpu = bpf_map_lookup_elem(&target_cpu, &key);
    if (!cpu)
        return XDP_PASS;
    return bpf_redirect_map(&cpu_targets, *cpu, XDP_PASS);
}

char LICENSE[] SEC("license") = "GPL";
