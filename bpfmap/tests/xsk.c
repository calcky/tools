#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

struct count_reader;
struct xsk_record {
    uint32_t kind, key, ifindex, netns, queue, state, mode, flags;
    char iface[16];
};
_Static_assert(sizeof(struct xsk_record) == 48, "XSK record ABI");
extern struct count_reader *bpfmap_xsk_open(const void *, size_t, uint32_t, uint32_t);
extern void bpfmap_count_close(struct count_reader *);
extern int bpfmap_xsk_read(struct count_reader *, void *, size_t);

static void *object;
static size_t object_len;

static unsigned read_map(uint32_t id, unsigned limit, struct xsk_record *out)
{
    struct count_reader *reader = bpfmap_xsk_open(object, object_len, id, limit);
    if (!reader) {
        fprintf(stderr, "XSK iterator load failed\n");
        exit(1);
    }
    int n = bpfmap_xsk_read(reader, out, limit + 1);
    bpfmap_count_close(reader);
    if (n < 0) {
        fprintf(stderr, "XSK iterator read failed: %d\n", n);
        exit(1);
    }
    return n;
}

static uint32_t map_id(int fd)
{
    struct bpf_map_info info = {0};
    uint32_t len = sizeof(info);
    if (fd < 0 || bpf_obj_get_info_by_fd(fd, &info, &len)) {
        perror("fixture map");
        exit(1);
    }
    return info.id;
}

static void require(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "FAIL %s\n", message);
        exit(1);
    }
    printf("PASS %s\n", message);
}

static void put(int fd, uint32_t key, int socket_fd)
{
    uint32_t value = socket_fd;
    if (bpf_map_update_elem(fd, &key, &value, BPF_ANY)) {
        perror("fixture XSK slot");
        exit(1);
    }
}

static void bound_fixture(void)
{
    /* A private namespace avoids touching any production device or XDP setup. */
    require(unshare(CLONE_NEWNET) == 0, "private socket namespace");
    int config = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    struct ifreq lo = {.ifr_name = "lo", .ifr_flags = IFF_UP};
    require(config >= 0 && ioctl(config, SIOCSIFFLAGS, &lo) == 0, "private loopback up");
    close(config);
    void *memory = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    require(memory != MAP_FAILED, "private UMEM allocation");
    int socket_fd = socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0);
    struct xdp_umem_reg umem = {.addr = (uintptr_t)memory, .len = 4096, .chunk_size = 2048};
    uint32_t ring = 64;
    require(socket_fd >= 0 &&
            setsockopt(socket_fd, SOL_XDP, XDP_UMEM_REG, &umem, sizeof(umem)) == 0 &&
            setsockopt(socket_fd, SOL_XDP, XDP_UMEM_FILL_RING, &ring, sizeof(ring)) == 0 &&
            setsockopt(socket_fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &ring, sizeof(ring)) == 0 &&
            setsockopt(socket_fd, SOL_XDP, XDP_RX_RING, &ring, sizeof(ring)) == 0,
            "private socket ring configuration");
    struct sockaddr_xdp address = {.sxdp_family = AF_XDP, .sxdp_flags = XDP_COPY,
                                   .sxdp_ifindex = if_nametoindex("lo"), .sxdp_queue_id = 0};
    require(bind(socket_fd, (void *)&address, sizeof(address)) == 0, "private copy-mode binding");
    int fd = bpf_map_create(BPF_MAP_TYPE_XSKMAP, "bpfmap_xsk_test", 4, 4, 128, NULL);
    put(fd, 7, socket_fd);
    struct xsk_record rows[65] = {0};
    unsigned n = read_map(map_id(fd), 64, rows);
    struct stat ns;
    require(stat("/proc/self/ns/net", &ns) == 0, "private namespace identity");
    require(n == 2 && rows[0].key == 7 && rows[0].queue == 0 && rows[0].state == 1 &&
            rows[0].mode == 1 && rows[0].ifindex == address.sxdp_ifindex &&
            rows[0].netns == ns.st_ino && rows[0].flags == 0,
            "actual binding: key 7, queue 0, Bound, Copy, private device namespace");
    close(fd);
    close(socket_fd);
    munmap(memory, 4096);
}

int main(int argc, char **argv)
{
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: xsk OBJECT [MAP_ID]\n");
        return 1;
    }
    FILE *file = fopen(argv[1], "rb");
    if (!file || fseek(file, 0, SEEK_END))
        return 1;
    long size = ftell(file);
    if (size <= 0)
        return 1;
    object_len = size;
    object = malloc(object_len);
    rewind(file);
    if (!object || fread(object, 1, object_len, file) != object_len)
        return 1;
    fclose(file);
    struct xsk_record rows[257] = {0};
    if (argc == 3) {
        unsigned n = read_map(strtoul(argv[2], NULL, 10), 256, rows);
        for (unsigned i = 0; i < n; i++) {
            struct xsk_record *r = &rows[i];
            printf("kind=%u key=%u ifindex=%u netns=%u queue=%u state=%u mode=%u flags=%u iface=%.16s\n",
                   r->kind, r->key, r->ifindex, r->netns, r->queue, r->state, r->mode, r->flags, r->iface);
        }
        free(object);
        return 0;
    }
    int fd = bpf_map_create(BPF_MAP_TYPE_XSKMAP, "bpfmap_xsk_test", 4, 4, 128, NULL);
    uint32_t id = map_id(fd);
    unsigned n = read_map(id, 64, rows);
    require(n == 1 && rows[0].kind == 0 && rows[0].key == 128 && rows[0].flags == 0,
            "empty map has complete coverage, not an error");
    int socket_fd = socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0);
    if (socket_fd < 0) {
        perror("AF_XDP fixture");
        return 1;
    }
    put(fd, 7, socket_fd);
    put(fd, 99, socket_fd);
    n = read_map(id, 64, rows);
    require(n == 3 && rows[0].key == 7 && rows[1].key == 99 && rows[2].flags == 0,
            "sparse slots are actual map keys");
    require(rows[0].ifindex == 0 && rows[0].queue == UINT32_MAX && rows[0].mode == 0 && rows[0].state == 0,
            "ready socket has unknown binding, not queue zero or copy mode");
    n = read_map(id, 1, rows);
    require(n == 2 && rows[0].key == 7 && rows[1].queue == 1 && rows[1].flags == 4,
            "entry limit reports additional occupied sockets");
    uint32_t key = 7;
    require(bpf_map_delete_elem(fd, &key) == 0, "fixture deletion");
    n = read_map(id, 1, rows);
    require(n == 2 && rows[0].key == 99 && rows[1].flags == 0,
            "entry removal refreshes keys and complete coverage");
    int large = bpf_map_create(BPF_MAP_TYPE_XSKMAP, "bpfmap_xsk_test", 4, 4, 32768, NULL);
    put(large, 20000, socket_fd);
    n = read_map(map_id(large), 64, rows);
    require(n == 1 && rows[0].key == 16384 && rows[0].flags == 2,
            "slot budget reports partial rather than claiming an empty map");
    close(large);
    int array = bpf_map_create(BPF_MAP_TYPE_ARRAY, "bpfmap_xsk_test", 4, 4, 1, NULL);
    n = read_map(map_id(array), 64, rows);
    require(n == 1 && rows[0].flags == 1, "wrong map type is explicitly unsupported");
    close(array);
    close(fd);
    n = read_map(UINT32_MAX, 64, rows);
    require(n == 0, "missing map does not return unrelated bindings");
    int dense = bpf_map_create(BPF_MAP_TYPE_XSKMAP, "bpfmap_xsk_test", 4, 4, 300, NULL);
    for (uint32_t slot = 0; slot < 300; slot++)
        put(dense, slot, socket_fd);
    n = read_map(map_id(dense), 256, rows);
    require(n == 257 && rows[0].key == 0 && rows[255].key == 255 &&
            rows[256].kind == 0 && rows[256].queue == 256 && rows[256].flags == 4,
            "maximum preview survives seq-file buffer growth without duplicate rows");
    close(dense);
    close(socket_fd);
    bound_fixture();
    free(object);
    return 0;
}
