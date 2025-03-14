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
#include "tcprtt.h"
#include "tcprtt.skel.h"

// 打印直方图的函数
static void print_hist(unsigned int *slots, __u32 addr)
{
    int i;
    char ip[16];

    // 将IP地址转换为字符串
    inet_ntop(AF_INET, &addr, ip, sizeof(ip));
    
    printf("\nRTT histogram for IP %s:\n", ip);
    printf("     RTT(us)        : count\n");
    
    // 打印直方图
    for (i = 0; i < MAX_SLOTS; i++) {
        if (slots[i] > 0) {
            printf("%10lu - %-10lu: %u\n", 
                   (1UL << (i)), (1UL << (i + 1)) - 1, 
                   slots[i]);
        }
    }
}

int main(int argc, char **argv)
{
    struct tcprtt_bpf *skel;
    int err;
    
    // 设置 libbpf 调试信息
    libbpf_set_print(NULL);

    // 打开并加载 BPF 程序
    skel = tcprtt_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // 附加 BPF 程序
    err = tcprtt_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Successfully started! Ctrl+C to stop.\n");

    // 主循环：每秒读取并打印统计信息
    while (1) {
        struct hist hist;
        __u64 key = 0;
        int fd = bpf_map__fd(skel->maps.hists);

        // 从 map 中读取数据
        err = bpf_map_lookup_elem(fd, &key, &hist);
        if (err == 0) {
            // 打印直方图
            print_hist(hist.slots, key);
            
            // 如果启用了扩展信息，打印平均 RTT
            if (skel->rodata->targ_show_ext && hist.cnt > 0) {
                printf("\nAverage RTT: %.2f us\n", 
                       (double)hist.latency / hist.cnt);
            }
        }
        
        sleep(1);
        printf("\033[2J");  // 清屏
        printf("\033[H");   // 光标移到开头
    }

cleanup:
    tcprtt_bpf__destroy(skel);
    return err != 0;
}
