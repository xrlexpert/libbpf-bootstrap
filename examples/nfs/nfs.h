#ifndef __NFS_H
#define __NFS_H

#include <vmlinux.h>

struct io_metrics_key {
    u64 fileid;      // 文件 inode 号
    dev_t dev;       // 设备号
};

struct raw_metrics_read {
    u64 read_count;  // 读取操作次数
    u64 read_size;   // 读取的总字节数
    u64 read_lat;    // 读取操作的总延迟
};

struct raw_metrics_write {
    u64 write_count;  // 写入操作次数
    u64 write_size;   // 写入的总字节数
    u64 write_lat;    // 写入操作的总延迟
};


struct trace_event_raw_rpc_task_begin {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    unsigned int task_id;
    unsigned int client_id;
    const void *action;
    unsigned long runstate;
    int status;
    unsigned short flags;
};

struct trace_event_raw_rpc_task_end {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    unsigned int task_id;
    unsigned int client_id;
    const void *action;
    unsigned long runstate;
    int status;
    unsigned short flags;
};

struct trace_event_raw_nfs_readpage_done {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    dev_t dev;
    u32 fhandle;
    u64 fileid;
    loff_t offset;
    u32 arg_count;
    u32 res_count;
    bool eof;
    int error;
};

struct trace_event_raw_nfs_writeback_done {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    dev_t dev;
    u32 fhandle;
    u64 fileid;
    loff_t offset;
    u32 arg_count;
    u32 res_count;
    int error;
    unsigned long stable;
    char verifier[8];
};

#endif