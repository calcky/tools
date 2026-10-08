#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <netinet/in.h>

struct count_reader;
struct count_record { uint32_t id, type, capacity, kind; int64_t count; uint32_t scanned, reserved; };
extern struct count_reader *bpfmap_count_open(const void *, size_t);
extern void bpfmap_count_close(struct count_reader *);
extern int bpfmap_count_read(struct count_reader *, struct count_record *, size_t);

struct test_map { int fd; uint32_t id; const char *name; int kind; int64_t count; };
static struct test_map maps[64];
static unsigned nr_maps;

static int remember(int fd, const char *name, int kind, int64_t count)
{
    if (fd < 0) {
        perror(name);
        exit(1);
    }
    struct bpf_map_info info = {0};
    uint32_t size = sizeof(info);
    if (bpf_obj_get_info_by_fd(fd, &info, &size)) {
        perror("map info");
        exit(1);
    }
    maps[nr_maps++] = (struct test_map){fd, info.id, name, kind, count};
    return fd;
}

static int create(enum bpf_map_type type, const char *name, uint32_t key,
                  uint32_t value, uint32_t capacity, uint32_t flags,
                  int inner, int kind, int64_t count)
{
    struct bpf_map_create_opts opts = {.sz = sizeof(opts), .map_flags = flags,
                                       .inner_map_fd = inner};
    return remember(bpf_map_create(type, "bpfmap_test", key, value, capacity, &opts),
                    name, kind, count);
}

static void put(int fd, uint32_t key, uint64_t value)
{
    if (bpf_map_update_elem(fd, &key, &value, BPF_ANY)) {
        perror("put test entry");
        exit(1);
    }
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: counts COUNT_OBJECT FIXTURE_OBJECT (root, Linux 6.6+)\n");
        return 1;
    }
    struct bpf_object *fixture = bpf_object__open_file(argv[2], NULL);
    if (!fixture || bpf_object__load(fixture))
        return 1;
    int prog = bpf_program__fd(bpf_object__find_program_by_name(fixture, "pulse"));
    unsigned char packet[64] = {0};
    struct bpf_test_run_opts run = {.sz = sizeof(run), .data_in = packet,
                                    .data_size_in = sizeof(packet), .repeat = 1};
    if (bpf_prog_test_run_opts(prog, &run)) {
        perror("emit private ringbuf record");
        return 1;
    }
    remember(dup(bpf_map__fd(bpf_object__find_map_by_name(fixture, "records"))), "Ringbuf", 5, 40);
    create(BPF_MAP_TYPE_USER_RINGBUF, "UserRingbuf", 0, 0, 4096, 0, 0, 5, 0);
    int inner = create(BPF_MAP_TYPE_ARRAY, "Array", 4, 8, 8, 0, 0, 2, 8);
    create(BPF_MAP_TYPE_PERCPU_ARRAY, "PerCpuArray", 4, 8, 8, 0, 0, 2, 8);
    int hash = create(BPF_MAP_TYPE_HASH, "Hash", 4, 8, 8, 0, 0, 1, 2);
    put(hash, 1, 7); put(hash, 2, 8);
    int percpu = create(BPF_MAP_TYPE_PERCPU_HASH, "PerCpuHash", 4, 8, 8, 0, 0, 1, 1);
    int cpus = libbpf_num_possible_cpus();
    uint64_t *values = calloc(cpus, sizeof(*values));
    uint32_t key = 1;
    if (!values || bpf_map_update_elem(percpu, &key, values, BPF_ANY))
        return 1;
    free(values);
    int lru = create(BPF_MAP_TYPE_LRU_HASH, "LruHash", 4, 8, 8, 0, 0, 1, 2);
    put(lru, 1, 0); put(lru, 2, 0);
    int hom = create(BPF_MAP_TYPE_HASH_OF_MAPS, "HashOfMaps", 4, 4, 8, 0, inner, 1, 2);
    put(hom, 0, inner); put(hom, 3, inner);
    int aom = create(BPF_MAP_TYPE_ARRAY_OF_MAPS, "ArrayOfMaps", 4, 4, 8, 0, inner, 3, 2);
    put(aom, 0, inner); put(aom, 3, inner);
    int pa = create(BPF_MAP_TYPE_PROG_ARRAY, "ProgArray", 4, 4, 8, 0, 0, 3, 2);
    put(pa, 0, prog); put(pa, 3, prog);
    int partial = create(BPF_MAP_TYPE_PROG_ARRAY, "PartialProgArray", 4, 4, 32768, 0, 0, 4, 1);
    put(partial, 0, prog); put(partial, 20000, prog);
    int dev = create(BPF_MAP_TYPE_DEVMAP, "DevMap", 4, 4, 8, 0, 0, 3, 2);
    put(dev, 0, 1); put(dev, 3, 1);
    int devhash = create(BPF_MAP_TYPE_DEVMAP_HASH, "DevMapHash", 4, 4, 8, 0, 0, 1, 2);
    put(devhash, 1, 1); put(devhash, 3, 1);
    create(BPF_MAP_TYPE_CPUMAP, "CpuMap", 4, 4, cpus, 0, 0, 3, 0);
    create(BPF_MAP_TYPE_STACK_TRACE, "StackTrace", 4, 128, 8, 0, 0, 3, 0);
    int lpm = create(BPF_MAP_TYPE_LPM_TRIE, "LpmTrie", 8, 8, 8, BPF_F_NO_PREALLOC, 0, 1, 2);
    uint32_t prefix1[2] = {32, 1}, prefix2[2] = {32, 2};
    uint64_t value = 0;
    if (bpf_map_update_elem(lpm, prefix1, &value, BPF_ANY) ||
        bpf_map_update_elem(lpm, prefix2, &value, BPF_ANY))
        return 1;
    int queue = create(BPF_MAP_TYPE_QUEUE, "Queue", 0, 8, 8, 0, 0, 1, 3);
    int stack = create(BPF_MAP_TYPE_STACK, "Stack", 0, 8, 8, 0, 0, 1, 3);
    for (value = 1; value <= 3; value++) {
        if (bpf_map_update_elem(queue, NULL, &value, BPF_ANY) ||
            bpf_map_update_elem(stack, NULL, &value, BPF_ANY))
            return 1;
    }
    int bloom = create(BPF_MAP_TYPE_BLOOM_FILTER, "BloomFilterUnknown", 0, 8, 8, 0, 0, 0, 0);
    value = 42;
    if (bpf_map_update_elem(bloom, NULL, &value, BPF_ANY))
        return 1;
    int socket_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int reuse = 1;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (socket_fd < 0 || setsockopt(socket_fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) ||
        bind(socket_fd, (void *)&address, sizeof(address)) || listen(socket_fd, 1))
        return 1;
    int sockmap = create(BPF_MAP_TYPE_SOCKMAP, "SockMap", 4, 4, 8, 0, 0, 3, 2);
    int sockhash = create(BPF_MAP_TYPE_SOCKHASH, "SockHash", 4, 4, 8, 0, 0, 1, 2);
    int reusemap = create(BPF_MAP_TYPE_REUSEPORT_SOCKARRAY, "ReuseportSockarray", 4, 8, 8, 0, 0, 3, 2);
    put(sockmap, 0, socket_fd); put(sockmap, 3, socket_fd);
    put(sockhash, 0, socket_fd); put(sockhash, 3, socket_fd);
    int reuse_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (reuse_fd < 0 || setsockopt(reuse_fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) ||
        bind(reuse_fd, (void *)&address, sizeof(address)) || listen(reuse_fd, 1))
        return 1;
    put(reusemap, 0, reuse_fd);
    /* One socket belongs to one reuseport-array slot. */
    maps[nr_maps - 1].count = 1;
    struct perf_event_attr attr = {.size = sizeof(attr), .type = PERF_TYPE_SOFTWARE,
        .config = PERF_COUNT_SW_BPF_OUTPUT, .sample_type = PERF_SAMPLE_RAW,
        .sample_period = 1, .disabled = 1};
    int perf = syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
    int events = create(BPF_MAP_TYPE_PERF_EVENT_ARRAY, "PerfEventArray", 4, 4, cpus, 0, 0, 3, perf >= 0);
    if (perf >= 0)
        put(events, 0, perf);
    int group = open("/sys/fs/cgroup", O_RDONLY | O_DIRECTORY);
    int cgroups = create(BPF_MAP_TYPE_CGROUP_ARRAY, "CgroupArray", 4, 4, 8, 0, 0, 3, group >= 0);
    if (group >= 0)
        put(cgroups, 0, group);
    struct btf *storage_btf = btf__new_empty();
    int storage_key = btf__add_int(storage_btf, "u32", 4, 0);
    int storage_value = btf__add_int(storage_btf, "u64", 8, 0);
    int storage_struct = btf__add_struct(storage_btf, "storage_value", 8);
    if (btf__add_field(storage_btf, "count", storage_value, 0, 0) || btf__load_into_kernel(storage_btf))
        return 1;
    struct bpf_map_create_opts storage_opts = {.sz = sizeof(storage_opts),
        .map_flags = BPF_F_NO_PREALLOC, .btf_fd = btf__fd(storage_btf),
        .btf_key_type_id = storage_key, .btf_value_type_id = storage_struct};
    remember(bpf_map_create(BPF_MAP_TYPE_SK_STORAGE, "bpfmap_test", 4, 8, 0, &storage_opts),
             "SkStorageUnknown", 0, 0);

    FILE *file = fopen(argv[1], "rb");
    if (!file)
        return 1;
    fseek(file, 0, SEEK_END);
    long len = ftell(file);
    rewind(file);
    void *object = malloc(len);
    if (!object || fread(object, 1, len, file) != (size_t)len)
        return 1;
    fclose(file);
    struct count_reader *reader = bpfmap_count_open(object, len);
    free(object);
    if (!reader) {
        fprintf(stderr, "Count iterator could not load\n");
        return 1;
    }
    struct count_record *records = calloc(8192, sizeof(*records));
    int count = bpfmap_count_read(reader, records, 8192);
    int failed = count < 0;
    for (unsigned i = 0; i < nr_maps; i++) {
        struct test_map *map = &maps[i];
        struct count_record *found = NULL;
        for (int j = 0; j < count; j++)
            if (records[j].id == map->id)
                found = &records[j];
        int ok = found && found->kind == (uint32_t)map->kind && found->count == map->count;
        printf("%s %-22s expected=%d/%" PRId64 " actual=%u/%" PRId64 "\n",
               ok ? "PASS" : "FAIL", map->name, map->kind, map->count,
               found ? found->kind : UINT32_MAX, found ? found->count : -1);
        failed |= !ok;
    }
    uint64_t first = 0, last = 0;
    if (bpf_map_lookup_elem(queue, NULL, &first) || first != 1 ||
        bpf_map_lookup_elem(stack, NULL, &last) || last != 3) {
        fprintf(stderr, "Queue/Stack were consumed\n");
        failed = 1;
    }
    bpfmap_count_close(reader);
    free(records);
    for (unsigned i = 0; i < nr_maps; i++)
        close(maps[i].fd);
    close(socket_fd);
    close(reuse_fd);
    if (perf >= 0) close(perf);
    if (group >= 0) close(group);
    bpf_object__close(fixture);
    btf__free(storage_btf);
    return failed;
}
