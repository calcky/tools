#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* Private fixture; closing stdin releases all objects, without pins or attachments. */
int main(void)
{
    int fd = bpf_map_create(BPF_MAP_TYPE_HASH, "browse_fixture", 4, 8, 256, NULL);
    if (fd < 0) { perror("create private hash"); return 1; }
    for (uint32_t key = 0; key < 200; key++) {
        uint64_t value = (uint64_t)key * 10;
        if (bpf_map_update_elem(fd, &key, &value, BPF_ANY)) {
            perror("populate private hash"); close(fd); return 1;
        }
    }
    struct bpf_map_info info = {0};
    uint32_t size = sizeof(info);
    if (bpf_obj_get_info_by_fd(fd, &info, &size)) {
        perror("hash metadata"); close(fd); return 1;
    }
    printf("Hash=%u\n", info.id);
    fflush(stdout);
    while (getchar() != EOF) {}
    close(fd);
    return 0;
}
