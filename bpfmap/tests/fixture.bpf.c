#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} records SEC(".maps");

SEC("socket")
int pulse(void *ctx)
{
    char payload[32] = {0};
    bpf_ringbuf_output(&records, payload, sizeof(payload), 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
