#ifndef XPCAP_CAPTURE_H
#define XPCAP_CAPTURE_H

#define XPCAP_MAX_IFACES 16
#define XPCAP_MAX_SNAPLEN 9216
#define XPCAP_SCRATCH_BYTES 16384
#define XPCAP_MAX_BATCH 64
#define XPCAP_MAX_FILTER_INSNS 128

#define STAGE_XDP_ENTRY 1
#define STAGE_XDP_EXIT 2
#define STAGE_REDIRECT 3
#define STAGE_XSK_RX 4
#define STAGE_XSK_TX 5
#define FLAG_PARTIAL 1
#define FLAG_REDIRECT_META 2
#define FLAG_XDP_FRAGS 4

struct capture_config {
    __u32 stage_mask;
    __u32 snaplen;
    __u32 ifindexes[XPCAP_MAX_IFACES];
    __u32 ifcount;
    __u32 queue;
    __u32 has_queue;
    __u32 prog_id;
    __u32 sample;
};

struct event_meta {
    __u64 ts_ns;
    __u32 ifindex;
    __u32 queue;
    __u32 prog_id;
    __u32 map_id;
    __u32 map_index;
    __u32 to_ifindex;
    __u32 packet_len;
    __u32 cap_len;
    __s32 result;
    __u8 stage;
    __u8 action;
    __u8 proto;
    __u8 flags;
};

#endif
