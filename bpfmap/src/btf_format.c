#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
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

static int map_uint(struct btf *btf, uint32_t id, uint32_t *value)
{
    int resolved = btf__resolve_type(btf, id);
    const struct btf_type *type;

    if (resolved < 0 || !(type = btf__type_by_id(btf, resolved)) || !btf_is_ptr(type))
        return -EINVAL;
    resolved = btf__resolve_type(btf, type->type);
    if (resolved < 0 || !(type = btf__type_by_id(btf, resolved)) || !btf_is_array(type))
        return -EINVAL;
    *value = btf_array(type)->nelems;
    return 0;
}

static int map_type_matches(struct btf *btf, uint32_t id, uint32_t expected)
{
    int resolved = btf__resolve_type(btf, id);
    const struct btf_type *type;

    if (!expected)
        return 1;
    if (resolved < 0 || !(type = btf__type_by_id(btf, resolved)) || !btf_is_ptr(type))
        return 0;
    return btf__resolve_type(btf, type->type) == btf__resolve_type(btf, expected);
}

int bpfmap_btf_map_name(struct btf *btf, const char *kernel_name,
                       uint32_t map_type, uint32_t max_entries,
                       uint32_t key_type, uint32_t value_type,
                       char *out, size_t out_size)
{
    const char *matched = NULL;
    size_t prefix = strlen(kernel_name);

    out[0] = '\0';
    for (uint32_t i = 1; i < btf__type_cnt(btf); i++) {
        const struct btf_type *section = btf__type_by_id(btf, i);
        const char *section_name;

        if (!section || !btf_is_datasec(section))
            continue;
        section_name = btf__name_by_offset(btf, section->name_off);
        if (!section_name || strcmp(section_name, ".maps"))
            continue;
        for (unsigned int j = 0; j < btf_vlen(section); j++) {
            const struct btf_type *var = btf__type_by_id(btf, btf_var_secinfos(section)[j].type);
            const struct btf_type *definition;
            const char *name;
            int resolved, type_ok = 0, capacity_ok = 0, key_ok = !key_type, value_ok = !value_type;

            if (!var || !btf_is_var(var))
                continue;
            name = btf__name_by_offset(btf, var->name_off);
            if (!name || strncmp(name, kernel_name, prefix) ||
                (prefix < BPF_OBJ_NAME_LEN - 1 && strlen(name) != prefix))
                continue;
            resolved = btf__resolve_type(btf, var->type);
            if (resolved < 0 || !(definition = btf__type_by_id(btf, resolved)) ||
                !btf_is_struct(definition))
                continue;
            for (unsigned int k = 0; k < btf_vlen(definition); k++) {
                const struct btf_member *member = btf_members(definition) + k;
                const char *field = btf__name_by_offset(btf, member->name_off);
                uint32_t number;

                if (!field)
                    continue;
                if (!strcmp(field, "type"))
                    type_ok = !map_uint(btf, member->type, &number) && number == map_type;
                else if (!strcmp(field, "max_entries"))
                    capacity_ok = !map_uint(btf, member->type, &number) && number == max_entries;
                else if (!strcmp(field, "key"))
                    key_ok = map_type_matches(btf, member->type, key_type);
                else if (!strcmp(field, "value"))
                    value_ok = map_type_matches(btf, member->type, value_type);
            }
            if (!type_ok || !capacity_ok || !key_ok || !value_ok)
                continue;
            if (matched && strcmp(matched, name))
                return -EEXIST;
            matched = name;
        }
    }
    if (!matched)
        return -ENOENT;
    if (strlen(matched) >= out_size)
        return -ENOSPC;
    memcpy(out, matched, strlen(matched) + 1);
    return 0;
}

static int format_data(struct btf *btf, uint32_t type_id, const void *data,
                       size_t data_size, char *out, size_t out_size, int compact,
                       int skip_names)
{
    struct format_buffer buffer = { .data = out, .capacity = out_size };
    struct btf_dump_type_data_opts opts = { .sz = sizeof(opts), .compact = compact,
        .skip_names = skip_names, .indent_str = "    ", .emit_zeroes = true };
    struct btf_dump *dump;
    int result;

    if (!btf || !type_id || !btf__type_by_id(btf, type_id) || !data || out_size < 2)
        return -EINVAL;
    out[0] = '\0';
    dump = btf_dump__new(btf, append, &buffer, NULL);
    if (!dump || libbpf_get_error(dump))
        return -EINVAL;
    result = btf_dump__dump_type_data(dump, type_id, data, data_size, &opts);
    btf_dump__free(dump);
    if (result < 0 || buffer.used >= out_size) {
        out[0] = '\0';
        return result < 0 ? result : -ENOSPC;
    }
    return 0;
}

int bpfmap_btf_format_expanded(struct btf *btf, uint32_t type_id, const void *data,
                              size_t data_size, char *out, size_t out_size)
{
    return format_data(btf, type_id, data, data_size, out, out_size, 0, 0);
}

static void append_text(struct format_buffer *out, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    append(out, fmt, args);
    va_end(args);
}

static int named_alias(struct btf *btf, uint32_t id, const char *name)
{
    for (unsigned int depth = 0; id && depth < 16; depth++) {
        const struct btf_type *type = btf__type_by_id(btf, id);
        const char *current;

        if (!type)
            break;
        current = btf__name_by_offset(btf, type->name_off);
        if (current && !strcmp(current, name))
            return 1;
        if (!btf_is_mod(type) && !btf_is_typedef(type) && !btf_is_type_tag(type))
            break;
        id = type->type;
    }
    return 0;
}

static int byte_array(struct btf *btf, uint32_t id, uint32_t length)
{
    int resolved = btf__resolve_type(btf, id);
    const struct btf_type *type, *element;

    if (resolved < 0 || !(type = btf__type_by_id(btf, resolved)) || !btf_is_array(type)
        || btf_array(type)->nelems != length)
        return 0;
    resolved = btf__resolve_type(btf, btf_array(type)->type);
    element = resolved < 0 ? NULL : btf__type_by_id(btf, resolved);
    return element && btf_is_int(element) && element->size == 1;
}

static int member_offset(struct btf *btf, const struct btf_type *type,
                         const char *name, size_t size, size_t *offset)
{
    for (unsigned int i = 0; i < btf_vlen(type) && i < 128; i++) {
        const struct btf_member *member = btf_members(type) + i;
        const char *field = btf__name_by_offset(btf, member->name_off);
        uint32_t bits = btf_member_bit_offset(type, i);

        if (!field || strcmp(field, name) || btf_member_bitfield_size(type, i)
            || bits % 8 || bits / 8 > type->size || size > type->size - bits / 8
            || btf__resolve_size(btf, member->type) != (int64_t)size)
            continue;
        if (size == 16 && !byte_array(btf, member->type, 16))
            continue;
        *offset = bits / 8;
        return 1;
    }
    return 0;
}

static int ip_field_name(const char *name)
{
    return !strcmp(name, "saddr") || !strcmp(name, "daddr")
        || !strcmp(name, "src_ip") || !strcmp(name, "dst_ip")
        || !strcmp(name, "source_ip") || !strcmp(name, "destination_ip")
        || !strcmp(name, "ipv4_addr");
}

static void address_text(struct format_buffer *out, const char *path,
                         const unsigned char *data, int family)
{
    char text[INET6_ADDRSTRLEN];

    if (inet_ntop(family, data, text, sizeof(text)))
        append_text(out, "%s%s%s%s", out->used ? "; " : "", path,
                    *path ? "=" : "", text);
}

static void addresses(struct btf *btf, uint32_t id, const unsigned char *data,
                      size_t size, const char *path, unsigned int depth,
                      unsigned int *budget, struct format_buffer *out)
{
    int resolved;
    const struct btf_type *type;
    const char *name;

    if (depth >= 8 || !*budget || out->used >= out->capacity)
        return;
    --*budget;
    resolved = btf__resolve_type(btf, id);
    type = resolved < 0 ? NULL : btf__type_by_id(btf, resolved);
    if (!type || !btf_is_struct(type) || type->size > size)
        return;
    name = btf__name_by_offset(btf, type->name_off);
    if (!name)
        return;
    if (!strcmp(name, "in_addr") && type->size == 4) {
        address_text(out, path, data, AF_INET);
        return;
    }
    if (!strcmp(name, "in6_addr") && type->size == 16) {
        address_text(out, path, data, AF_INET6);
        return;
    }
    if (!strcmp(name, "aiwan_xdp_bpf_ipv6_key") && type->size == 16) {
        size_t offset;

        if (member_offset(btf, type, "bytes", 16, &offset))
            address_text(out, path, data + offset, AF_INET6);
        return;
    }
    // This schema stores IPv4 in the first four bytes, with family values 4/6.
    if (!strcmp(name, "aiwan_xdp_bpf_flow_key")) {
        size_t family, source, destination;

        if (member_offset(btf, type, "address_family", 1, &family)
            && member_offset(btf, type, "source_address", 16, &source)
            && member_offset(btf, type, "destination_address", 16, &destination)
            && (data[family] == 4 || data[family] == 6)) {
            int af = data[family] == 4 ? AF_INET : AF_INET6;
            char field[256];

            snprintf(field, sizeof(field), "%s%ssource_address", path, *path ? "." : "");
            address_text(out, field, data + source, af);
            snprintf(field, sizeof(field), "%s%sdestination_address", path, *path ? "." : "");
            address_text(out, field, data + destination, af);
        }
        return;
    }
    for (unsigned int i = 0; i < btf_vlen(type) && i < 128 && *budget; i++) {
        const struct btf_member *member = btf_members(type) + i;
        const char *field = btf__name_by_offset(btf, member->name_off);
        uint32_t bits = btf_member_bit_offset(type, i);
        int64_t field_size = btf__resolve_size(btf, member->type);
        char full[256];
        int written;

        if (!field || btf_member_bitfield_size(type, i) || bits % 8
            || bits / 8 > type->size || field_size <= 0
            || (uint64_t)field_size > type->size - bits / 8)
            continue;
        written = snprintf(full, sizeof(full), "%s%s%s", path,
                           *path && *field ? "." : "", field);
        if (written < 0 || (size_t)written >= sizeof(full))
            continue;
        // A big-endian integer is an address only when the field says so.
        if (field_size == 4 && named_alias(btf, member->type, "__be32")
            && ip_field_name(field)) {
            --*budget;
            address_text(out, full, data + bits / 8, AF_INET);
        } else {
            addresses(btf, member->type, data + bits / 8, (size_t)field_size,
                      full, depth + 1, budget, out);
        }
    }
}

int bpfmap_btf_addresses(struct btf *btf, uint32_t type_id, const void *data,
                        size_t data_size, char *out, size_t out_size)
{
    struct format_buffer buffer = { .data = out, .capacity = out_size };
    unsigned int budget = 128;

    if (!btf || !type_id || !data || !out || out_size < 2)
        return -EINVAL;
    out[0] = '\0';
    addresses(btf, type_id, data, data_size, "", 0, &budget, &buffer);
    if (buffer.used >= out_size) {
        out[0] = '\0';
        return -ENOSPC;
    }
    return buffer.used ? 0 : -ENOENT;
}

static int flow_summary(struct btf *btf, const struct btf_type *type,
                        const unsigned char *data, struct format_buffer *out)
{
    size_t family, source, destination, sport, dport, protocol, reserved;
    char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
    uint16_t src_port, dst_port;
    int af;
    const char *name = btf__name_by_offset(btf, type->name_off);

    if (!name || strcmp(name, "aiwan_xdp_bpf_flow_key")
        || !member_offset(btf, type, "source_address", 16, &source)
        || !member_offset(btf, type, "destination_address", 16, &destination)
        || !member_offset(btf, type, "address_family", 1, &family)
        || !member_offset(btf, type, "src_port", 2, &sport)
        || !member_offset(btf, type, "dst_port", 2, &dport)
        || !member_offset(btf, type, "protocol", 1, &protocol)
        || (data[family] != 4 && data[family] != 6))
        return -ENOTSUP;
    af = data[family] == 4 ? AF_INET : AF_INET6;
    if (!inet_ntop(af, data + source, src, sizeof(src))
        || !inet_ntop(af, data + destination, dst, sizeof(dst)))
        return -EINVAL;
    memcpy(&src_port, data + sport, 2);
    memcpy(&dst_port, data + dport, 2);
    if (data[protocol] == 6 || data[protocol] == 17) {
        const char *left = af == AF_INET6 ? "[" : "";
        const char *right = af == AF_INET6 ? "]" : "";

        append_text(out, "%s%s%s:%u -> %s%s%s:%u %s", left, src, right,
                    ntohs(src_port), left, dst, right, ntohs(dst_port),
                    data[protocol] == 6 ? "TCP" : "UDP");
    } else if (data[protocol] == 1 || data[protocol] == 58) {
        append_text(out, "%s -> %s %s id=%u", src, dst,
                    data[protocol] == 1 ? "ICMP" : "ICMPv6", ntohs(src_port));
    } else {
        append_text(out, "%s -> %s proto=%u", src, dst, data[protocol]);
    }
    if (member_offset(btf, type, "reserved", 2, &reserved)
        && (data[reserved] || data[reserved + 1]))
        append_text(out, " reserved=0x%02x%02x", data[reserved], data[reserved + 1]);
    return out->used >= out->capacity ? -ENOSPC : 0;
}

int bpfmap_btf_format(struct btf *btf, uint32_t type_id, const void *data,
                     size_t data_size, char *out, size_t out_size)
{
    const struct btf_type *type;
    struct format_buffer buffer = { .data = out, .capacity = out_size };
    int resolved;

    if (!btf || !type_id || !data || !out || out_size < 2)
        return -EINVAL;
    out[0] = '\0';
    resolved = btf__resolve_type(btf, type_id);
    type = resolved < 0 ? NULL : btf__type_by_id(btf, resolved);
    if (!type)
        return -EINVAL;
    if (!btf_is_struct(type) || btf_vlen(type) > 32)
        return format_data(btf, type_id, data, data_size, out, out_size, 1, 1);
    if (type->size > data_size)
        return -EINVAL;
    const char *type_name = btf__name_by_offset(btf, type->name_off);
    if (type_name && (!strcmp(type_name, "in_addr") || !strcmp(type_name, "in6_addr")
        || !strcmp(type_name, "aiwan_xdp_bpf_ipv6_key"))
        && !bpfmap_btf_addresses(btf, type_id, data, data_size, out, out_size))
        return 0;
    if (!flow_summary(btf, type, data, &buffer))
        return 0;
    buffer.used = 0;
    out[0] = '\0';
    for (unsigned int i = 0; i < btf_vlen(type); i++) {
        const struct btf_member *member = btf_members(type) + i;
        const char *name = btf__name_by_offset(btf, member->name_off);
        uint32_t bits = btf_member_bit_offset(type, i);
        int64_t size = btf__resolve_size(btf, member->type);
        char field[512];

        if (!name || !*name || btf_member_bitfield_size(type, i) || bits % 8
            || size <= 0 || bits / 8 > type->size
            || (uint64_t)size > type->size - bits / 8)
            return format_data(btf, type_id, data, data_size, out, out_size, 1, 0);
        // Keep padding available in expanded details, without crowding the list.
        if (!strncmp(name, "reserved", 8)) {
            size_t j;
            for (j = 0; j < (size_t)size && !((const unsigned char *)data)[bits / 8 + j]; j++) {}
            if (j == (size_t)size)
                continue;
        }
        const unsigned char *field_data = (const unsigned char *)data + bits / 8;
        if (size == 4 && named_alias(btf, member->type, "__be32") && ip_field_name(name)) {
            if (!inet_ntop(AF_INET, field_data, field, sizeof(field)))
                return -EINVAL;
        } else if (bpfmap_btf_addresses(btf, member->type, field_data,
                                       (size_t)size, field, sizeof(field))
                   && format_data(btf, member->type, field_data,
                                  (size_t)size, field, sizeof(field), 1, 1)) {
            return -ENOSPC;
        }
        append_text(&buffer, "%s%s=%s", buffer.used ? " " : "", name, field);
        if (buffer.used >= buffer.capacity)
            return -ENOSPC;
    }
    return buffer.used ? 0 : format_data(btf, type_id, data, data_size, out, out_size, 1, 1);
}

int bpfmap_btf_type_name(struct btf *btf, uint32_t type_id, char *out, size_t out_size)
{
    struct format_buffer buffer = { .data = out, .capacity = out_size };
    struct btf_dump_emit_type_decl_opts opts = { .sz = sizeof(opts), .field_name = "" };
    struct btf_dump *dump;
    int result;

    if (!btf || !type_id || !btf__type_by_id(btf, type_id) || out_size < 2)
        return -EINVAL;
    out[0] = '\0';
    dump = btf_dump__new(btf, append, &buffer, NULL);
    if (!dump || libbpf_get_error(dump))
        return -EINVAL;
    result = btf_dump__emit_type_decl(dump, type_id, &opts);
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
