#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct count_reader {
    struct bpf_object *object;
    struct bpf_link *link;
};
struct count_record {
    uint32_t id, type, capacity, kind;
    int64_t count;
    uint32_t scanned, reserved;
};

void bpfmap_count_close(struct count_reader *reader)
{
    if (!reader)
        return;
    bpf_link__destroy(reader->link);
    bpf_object__close(reader->object);
    free(reader);
}

static struct count_reader *reader_open(const void *data, size_t len,
                                        const char *name, const uint32_t *request)
{
    struct count_reader *reader = calloc(1, sizeof(*reader));
    struct bpf_program *program;
    libbpf_print_fn_t previous = libbpf_set_print(NULL);

    if (!reader) {
        libbpf_set_print(previous);
        return NULL;
    }
    reader->object = bpf_object__open_mem(data, len, NULL);
    if (!reader->object)
        goto fail;
    bpf_object__for_each_program(program, reader->object) {
        bpf_program__set_autoload(program, !strcmp(bpf_program__name(program), name));
    }
    if (request) {
        struct bpf_map *config = bpf_object__find_map_by_name(reader->object, ".data.xsk");
        if (!config || bpf_map__set_initial_value(config, request, 2 * sizeof(*request)))
            goto fail;
    }
    if (bpf_object__load(reader->object))
        goto fail;
    program = bpf_object__find_program_by_name(reader->object, name);
    if (!program)
        goto fail;
    reader->link = bpf_program__attach_iter(program, NULL);
    if (!reader->link)
        goto fail;
    libbpf_set_print(previous);
    return reader;
fail:
    bpfmap_count_close(reader);
    libbpf_set_print(previous);
    return NULL;
}

struct count_reader *bpfmap_count_open(const void *data, size_t len)
{
    return reader_open(data, len, "count_maps", NULL);
}

struct count_reader *bpfmap_xsk_open(const void *data, size_t len, uint32_t id, uint32_t limit)
{
    uint32_t request[2] = {id, limit};
    return reader_open(data, len, "xsk_entries", request);
}

static int reader_read(struct count_reader *reader, void *out, size_t capacity, size_t record_size)
{
    int fd = bpf_iter_create(bpf_link__fd(reader->link));
    size_t used = 0, limit = capacity * record_size;
    unsigned char extra;

    if (fd < 0)
        return -errno;
    while (used < limit) {
        ssize_t n = read(fd, (unsigned char *)out + used, limit - used);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            int error = errno;
            close(fd);
            return -error;
        }
        if (!n)
            break;
        used += n;
    }
    if (used == limit) {
        ssize_t n;
        do {
            n = read(fd, &extra, 1);
        } while (n < 0 && errno == EINTR);
        if (n != 0) {
            int error = n < 0 ? errno : E2BIG;
            close(fd);
            return -error;
        }
    }
    close(fd);
    if (used % record_size)
        return -EIO;
    return used / record_size;
}

int bpfmap_count_read(struct count_reader *reader, struct count_record *out, size_t capacity)
{
    return reader_read(reader, out, capacity, sizeof(*out));
}

int bpfmap_xsk_read(struct count_reader *reader, void *out, size_t capacity)
{
    return reader_read(reader, out, capacity, 48);
}

size_t bpfmap_count_map_ids(struct count_reader *reader, uint32_t *ids, size_t capacity)
{
    struct bpf_map *map;
    size_t count = 0;
    bpf_object__for_each_map(map, reader->object) {
        struct bpf_map_info info = {0};
        uint32_t size = sizeof(info);
        if (count < capacity && !bpf_obj_get_info_by_fd(bpf_map__fd(map), &info, &size))
            ids[count++] = info.id;
    }
    return count;
}
