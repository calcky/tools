#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct format_buffer {
    char *data;
    size_t capacity;
    size_t used;
};

static void append(void *ctx, const char *fmt, va_list args)
{
    struct format_buffer *out = ctx;
    int written;

    if (out->used >= out->capacity)
        return;
    written = vsnprintf(out->data + out->used, out->capacity - out->used, fmt, args);
    if (written < 0)
        return;
    if ((size_t)written >= out->capacity - out->used)
        out->used = out->capacity;
    else
        out->used += (size_t)written;
}

struct btf *bpfmap_btf_open(uint32_t id)
{
    struct btf *btf = btf__load_from_kernel_by_id(id);
    if (libbpf_get_error(btf))
        return NULL;
    return btf;
}

void bpfmap_btf_close(struct btf *btf)
{
    btf__free(btf);
}

int bpfmap_btf_format(struct btf *btf, uint32_t type_id, const void *data,
                      size_t data_size, char *out, size_t out_size)
{
    struct format_buffer buffer = { .data = out, .capacity = out_size };
    struct btf_dump_type_data_opts opts = { .sz = sizeof(opts), .compact = true,
                                            .emit_zeroes = true };
    struct btf_dump *dump;
    int result;

    if (!btf || !type_id || !data || out_size < 2)
        return -EINVAL;
    out[0] = '\0';
    dump = btf_dump__new(btf, append, &buffer, NULL);
    if (libbpf_get_error(dump))
        return -EINVAL;
    result = btf_dump__dump_type_data(dump, type_id, data, data_size, &opts);
    btf_dump__free(dump);
    if (result < 0 || buffer.used >= out_size) {
        out[0] = '\0';
        return result < 0 ? result : -ENOSPC;
    }
    return 0;
}

int bpfmap_btf_unsigned_size(struct btf *btf, uint32_t type_id)
{
    const struct btf_type *type;
    int resolved;

    if (!btf || !type_id)
        return 0;
    resolved = btf__resolve_type(btf, type_id);
    if (resolved < 0)
        return 0;
    type = btf__type_by_id(btf, (uint32_t)resolved);
    if (!type || !btf_is_int(type) || btf_int_encoding(type) != 0)
        return 0;
    switch (type->size) {
    case 1: case 2: case 4: case 8:
        return (int)type->size;
    default:
        return 0;
    }
}

static uint64_t read_unsigned(const unsigned char *data, size_t size)
{
    uint64_t value = 0;

    if (size == 1) {
        uint8_t v;
        memcpy(&v, data, sizeof(v));
        value = v;
    } else if (size == 2) {
        uint16_t v;
        memcpy(&v, data, sizeof(v));
        value = v;
    } else if (size == 4) {
        uint32_t v;
        memcpy(&v, data, sizeof(v));
        value = v;
    } else if (size == 8) {
        memcpy(&value, data, sizeof(value));
    }
    return value;
}

int bpfmap_btf_struct_delta(struct btf *btf, uint32_t type_id,
                            const void *before, const void *after, size_t data_size,
                            char *out, size_t out_size)
{
    const struct btf_type *type;
    int resolved;
    size_t used = 0;
    unsigned int changes = 0;

    if (!btf || !type_id || !before || !after || out_size < 2)
        return -EINVAL;
    out[0] = '\0';
    resolved = btf__resolve_type(btf, type_id);
    if (resolved < 0)
        return -ENOTSUP;
    type = btf__type_by_id(btf, (uint32_t)resolved);
    if (!type || !btf_is_struct(type) || type->size > data_size || btf_vlen(type) > 32)
        return -ENOTSUP;

    for (unsigned int i = 0; i < btf_vlen(type); i++) {
        const struct btf_member *member = btf_members(type) + i;
        const struct btf_type *field;
        const char *name;
        uint32_t bit_offset = btf_member_bit_offset(type, i);
        uint64_t old_value, new_value;
        size_t offset;
        int field_id, written;

        if (btf_member_bitfield_size(type, i) || bit_offset % 8)
            continue;
        field_id = btf__resolve_type(btf, member->type);
        if (field_id < 0)
            continue;
        field = btf__type_by_id(btf, (uint32_t)field_id);
        if (!field || !btf_is_int(field) || btf_int_encoding(field) != 0 ||
            btf_int_offset(field) != 0 || btf_int_bits(field) != field->size * 8 ||
            (field->size != 1 && field->size != 2 && field->size != 4 && field->size != 8))
            continue;
        offset = bit_offset / 8;
        if (offset > data_size || field->size > data_size - offset)
            continue;
        name = btf__name_by_offset(btf, member->name_off);
        if (!name || !*name)
            continue;
        old_value = read_unsigned((const unsigned char *)before + offset, field->size);
        new_value = read_unsigned((const unsigned char *)after + offset, field->size);
        if (old_value == new_value)
            continue;
        if (++changes > 8) {
            if (used + 4 >= out_size)
                return -ENOSPC;
            memcpy(out + used, " ...", 5);
            return 0;
        }
        if (new_value >= old_value)
            written = snprintf(out + used, out_size - used, "%s%s +%llu",
                               used ? ", " : "", name,
                               (unsigned long long)(new_value - old_value));
        else
            written = snprintf(out + used, out_size - used, "%s%s reset/-",
                               used ? ", " : "", name);
        if (written < 0 || (size_t)written >= out_size - used)
            return -ENOSPC;
        used += (size_t)written;
    }
    if (!changes) {
        if (memcmp(before, after, data_size) != 0)
            return -ENOTSUP;
        memcpy(out, "=", 2);
    }
    return 0;
}
