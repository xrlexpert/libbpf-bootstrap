// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <stdint.h> 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include "nfs.skel.h"

int main(int argc, char **argv)
{
    struct nfs_bpf *skel;
    int err;
    
    // 设置 libbpf 调试信息
    libbpf_set_print(NULL);

    // 打开并加载 BPF 程序
    skel = nfs_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // 附加 BPF 程序
    err = nfs_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Successfully started! Ctrl+C to stop.\n");
    int fd = bpf_map__fd(skel->maps.link_begin);
    // 主循环：每秒读取并打印统计信息
    while (1) {
        __u64 key = 0, next_key;
        __u64 timestamp;

        // 遍历映射中的所有键值对
        while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
            // 读取当前键对应的值
            err = bpf_map_lookup_elem(fd, &next_key, &timestamp);
            if (err == 0) {
                printf("PID=%llu, timestamp=%llu\n", next_key, timestamp);
            }

            // 移动到下一个键
            key = next_key;
        }

        sleep(1);
        printf("\033[2J");  // 清屏
        printf("\033[H");   // 光标移到开头
    }

cleanup:
    nfs_bpf__destroy(skel);
    return err != 0;
}
