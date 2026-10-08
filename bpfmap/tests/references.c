#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <errno.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

/* Privileged, isolated fixture. No pins, attachments, or existing map access.
 * cc -O2 -Wall -Wextra -Werror references.c -lbpf -o references
 * references --hold prints IDs and keeps objects alive until stdin closes.
 */
static int handles[80];
static unsigned nr_handles;

static void cleanup(void)
{
    while (nr_handles)
        close(handles[--nr_handles]);
}

static void require(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s: %s\n", message, strerror(errno));
        exit(1);
    }
}

static int remember(int fd, const char *message)
{
    require(fd >= 0, message);
    require(nr_handles < sizeof(handles) / sizeof(handles[0]), "fixture handle budget");
    handles[nr_handles++] = fd;
    return fd;
}

static int map(enum bpf_map_type type, const char *name, unsigned key_size,
               unsigned capacity, int inner, unsigned flags)
{
    struct bpf_map_create_opts opts = {
        .sz = sizeof(opts), .inner_map_fd = inner, .map_flags = flags,
    };
    return remember(bpf_map_create(type, name, key_size, 4, capacity, &opts), name);
}

static uint32_t map_id(int fd)
{
    struct bpf_map_info info = {0};
    uint32_t size = sizeof(info);
    require(bpf_obj_get_info_by_fd(fd, &info, &size) == 0, "fixture map metadata");
    return info.id;
}

static uint32_t program_id(int fd)
{
    struct bpf_prog_info info = {0};
    uint32_t size = sizeof(info);
    require(bpf_obj_get_info_by_fd(fd, &info, &size) == 0, "zero-buffer program metadata");
    require(info.nr_map_ids == 64, "program references 64 private maps");
    uint32_t ids[64] = {0};
    struct bpf_prog_info maps = {.nr_map_ids = 64, .map_ids = (uintptr_t)ids};
    size = sizeof(maps);
    require(bpf_obj_get_info_by_fd(fd, &maps, &size) == 0,
            "fresh map-ID-only program metadata");
    require(maps.nr_map_ids == 64, "complete 64-map ID coverage");
    for (unsigned i = 0; i < 64; i++)
        require(ids[i] != 0, "referenced map ID is nonzero");
    return info.id;
}

static void put(int fd, const void *key, int target)
{
    uint32_t value = target;
    require(bpf_map_update_elem(fd, key, &value, BPF_ANY) == 0, "private reference update");
}

static void expect_id(int fd, const void *key, uint32_t expected)
{
    uint32_t id = 0;
    require(bpf_map_lookup_elem(fd, key, &id) == 0 && id == expected,
            "lookup returns target object ID, not inserted FD");
}

static void expect_empty(int fd, const void *key)
{
    uint32_t id = 0;
    require(bpf_map_lookup_elem(fd, key, &id) != 0 && errno == ENOENT,
            "empty sparse slot returns ENOENT");
}

static int program(void)
{
    struct bpf_insn insns[130] = {0};
    for (unsigned i = 0; i < 64; i++) {
        int fd = map(BPF_MAP_TYPE_ARRAY, "refs_used", 4, 1, 0, 0);
        insns[2 * i] = (struct bpf_insn) {
            .code = BPF_LD | BPF_DW | BPF_IMM,
            .dst_reg = BPF_REG_1, .src_reg = BPF_PSEUDO_MAP_FD, .imm = fd,
        };
    }
    insns[128] = (struct bpf_insn) {
        .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0,
    };
    insns[129] = (struct bpf_insn) {.code = BPF_JMP | BPF_EXIT};
    char log[65536] = {0};
    struct bpf_prog_load_opts opts = {
        .sz = sizeof(opts), .log_buf = log, .log_size = sizeof(log), .log_level = 1,
    };
    int fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, "refs_program", "GPL",
                           insns, sizeof(insns) / sizeof(insns[0]), &opts);
    if (fd < 0)
        fprintf(stderr, "%s\n", log);
    return remember(fd, "load unattached private program");
}

int main(int argc, char **argv)
{
    if (argc > 2 || (argc == 2 && strcmp(argv[1], "--hold") != 0)) {
        fprintf(stderr, "usage: references [--hold]\n");
        return 1;
    }
    atexit(cleanup);
    struct rlimit memlock = {RLIM_INFINITY, RLIM_INFINITY};
    (void)setrlimit(RLIMIT_MEMLOCK, &memlock);
    int inner = map(BPF_MAP_TYPE_ARRAY, "refs_inner", 4, 8, 0, 0);
    int prog = program();
    uint32_t inner_id = map_id(inner), prog_id = program_id(prog);
    int pa = map(BPF_MAP_TYPE_PROG_ARRAY, "refs_programs", 4, 8, 0, 0);
    int aom = map(BPF_MAP_TYPE_ARRAY_OF_MAPS, "refs_maps", 4, 8, inner, 0);
    int hom = map(BPF_MAP_TYPE_HASH_OF_MAPS, "refs_hash", 8, 8, inner, 0);
    int empty = map(BPF_MAP_TYPE_PROG_ARRAY, "refs_empty", 4, 8, 0, 0);
    int large = map(BPF_MAP_TYPE_PROG_ARRAY, "refs_limited", 4, 32768, 0, 0);
    int denied = map(BPF_MAP_TYPE_ARRAY_OF_MAPS, "refs_writeonly", 4, 8,
                     inner, BPF_F_WRONLY);
    uint32_t hole = 0, first = 2, last = 7;
    uint64_t hash_key = UINT64_C(0x0123456789abcdef);
    expect_empty(pa, &hole);
    expect_empty(aom, &hole);
    expect_empty(hom, &hash_key);
    put(pa, &first, prog);
    put(pa, &last, prog);
    put(aom, &first, inner);
    put(aom, &last, inner);
    put(hom, &hash_key, inner);
    expect_id(pa, &first, prog_id);
    expect_id(pa, &last, prog_id);
    expect_id(aom, &first, inner_id);
    expect_id(hom, &hash_key, inner_id);
    uint32_t far = 20000;
    put(large, &far, prog);
    put(denied, &first, inner);
    uint32_t ignored = 0;
    require(bpf_map_lookup_elem(denied, &first, &ignored) != 0 &&
            (errno == EPERM || errno == EACCES), "write-only source is a read failure");
    require(bpf_map_delete_elem(pa, &first) == 0, "delete isolated reference");
    expect_empty(pa, &first);
    put(pa, &first, prog);
    printf("ProgArray=%u ArrayOfMaps=%u HashOfMaps=%u Empty=%u Limited=%u WriteOnly=%u\n",
           map_id(pa), map_id(aom), map_id(hom), map_id(empty), map_id(large), map_id(denied));
    printf("Program=%u InnerMap=%u SparseKeys=2,7 HashKey=0x0123456789abcdef FarKey=20000\n",
           prog_id, inner_id);
    puts("PASS: isolated reference ID and fresh program metadata checks");
    fflush(stdout);
    if (argc == 2) {
        puts("Holding unpinned objects until stdin closes.");
        fflush(stdout);
        while (getchar() != EOF) {}
    }
    return 0;
}
