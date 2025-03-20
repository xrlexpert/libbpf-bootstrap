// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Wenbo Zhang
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "maps.bpf.h"
#include "nfs.h"
#define MAX_ENTRIES	1024

/// @sample {"interval": 1000, "type" : "log2_hist"}
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, u64);
}link_begin SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, struct rpc_task_info);
}waiting_rpc SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, u64);
}link_end SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct io_metrics_key);
    __type(value, struct raw_metrics_read);
} io_metrics_read SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct io_metrics_key);
    __type(value, struct raw_metrics_write);
} io_metrics_write SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

SEC("tracepoint/nfs/nfs_initiate_read")
int handle_nfs_read(void *ctx){
    u64 key = bpf_get_current_pid_tgid() >> 32;
    u64 timestamp = bpf_ktime_get_ns();
    bpf_printk("read_pid:%lld\n", key);
    bpf_map_lookup_or_try_init(&link_begin, &key, &timestamp);
    return 0;
}

SEC("tracepoint/nfs/nfs_initiate_write")
int handle_nfs_write(void *ctx){
    u64 key = bpf_get_current_pid_tgid() >> 32;
    u64 timestamp = bpf_ktime_get_ns();
    bpf_map_lookup_or_try_init(&link_begin, &key, &timestamp);
    bpf_printk("wirte_pid:%lld\n", key);
    return 0;
}

SEC("tracepoint/sunrpc/rpc_task_begin")
int handle_rpc_task_begin(struct trace_event_raw_rpc_task_begin *ctx){
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    void *val = bpf_map_lookup_elem(&link_begin, &pid);
    // bpf_printk("rpc_task_begin_pid:%lld\n", pid);
    if(val){
        u64 task_id = ctx->task_id;
        u64 start_time = *((u64 *)val);
        struct rpc_task_info info = {
            .timestamp = start_time,
            .pid = pid
        };
        // bpf_printk("task_begin_id:%lld\n", task_id);
        bpf_map_lookup_or_try_init(&waiting_rpc, &task_id, &info);
    }
    return 0;
}

SEC("tracepoint/sunrpc/rpc_task_end")
int handle_rpc_task_end(struct trace_event_raw_rpc_task_end *ctx){
    u64 task_id = ctx->task_id;
    void *val = bpf_map_lookup_elem(&waiting_rpc, &task_id);
    // bpf_printk("task_end_id:%lld\n", task_id);
    if(val){
        struct rpc_task_info info = *((struct rpc_task_info *)val);
        // bpf_printk("rpc_task_end_pid:%lld\n", info.pid);
        bpf_map_lookup_or_try_init(&link_end, &info.pid, &info.timestamp);
    }
    return 0;
}

SEC("kprobe/nfs_readpage_done")
int kb_nfs_read_d(struct pt_regs *regs)
{   
    struct rpc_task* task = (struct rpc_task *)PT_REGS_PARM1(regs);
    u64 pid = BPF_CORE_READ(task, tk_owner);
    struct nfs_pgio_header *hdr = (struct nfs_pgio_header *)PT_REGS_PARM2(regs);
    struct inode *inode = BPF_CORE_READ(hdr, inode);
    u64 fileid = BPF_CORE_READ(inode, i_ino);
    u64 dev = BPF_CORE_READ(inode, i_sb, s_dev);
    u32 res_count = BPF_CORE_READ(hdr, res.count);
    u64 timestamp = bpf_ktime_get_ns();
    struct io_metrics_key key = {
        .fileid = fileid,
        .dev = dev,
    };
    struct raw_metrics_read *metrics_read = bpf_map_lookup_elem(&io_metrics_read, &key);
    if (!metrics_read) {
        struct raw_metrics_read new_metrics = {
            .read_count = 0,
            .read_size = 0,
            .read_lat = 0,
        };
        bpf_map_update_elem(&io_metrics_read, &key, &new_metrics, BPF_ANY);
        metrics_read = bpf_map_lookup_elem(&io_metrics_read, &key);
        if (!metrics_read) {
            return 0;
        }
    }
    bpf_printk("read_done_pid:%lld\n", pid);
    u64 *start_time = bpf_map_lookup_elem(&link_end, &pid);
    if (start_time) {
        u64 latency = timestamp - *start_time;
        __sync_fetch_and_add(&metrics_read->read_count, 1);
        __sync_fetch_and_add(&metrics_read->read_size, res_count);
        __sync_fetch_and_add(&metrics_read->read_lat, latency);
        bpf_printk("pid:%lld, read_count: %lld, read_size: %lld, read_lat: %lld\n", pid, metrics_read->read_count, metrics_read->read_size, metrics_read->read_lat);
    }
    return 0;
}
    

SEC("kprobe/nfs_writeback_done")
int kb_nfs_write_d(struct pt_regs *regs)
{
    // ... 其他代码 ...
    struct rpc_task* task = (struct rpc_task *)PT_REGS_PARM1(regs);
    if(!task){
        return 0;
    }
    u64 pid = BPF_CORE_READ(task, tk_owner);
    struct nfs_pgio_header *hdr = (struct nfs_pgio_header *)PT_REGS_PARM2(regs);
    if(!hdr){
        return 0;
    }
    struct inode *inode = BPF_CORE_READ(hdr, inode);
    u64 fileid = BPF_CORE_READ(inode, i_ino);
    u64 dev = BPF_CORE_READ(inode, i_sb, s_dev);
    // 获取写入字节数
    u32 res_count = BPF_CORE_READ(hdr, res.count);
    u64 timestamp = bpf_ktime_get_ns();
    struct io_metrics_key key = {
        .fileid = fileid,
        .dev = dev,
    };
    struct raw_metrics_write *metrics_write = bpf_map_lookup_elem(&io_metrics_write, &key);
    if (!metrics_write) {
        struct raw_metrics_write new_metrics = {
            .write_count = 0,
            .write_size = 0,
            .write_lat = 0,
        };
        bpf_map_update_elem(&io_metrics_write, &key, &new_metrics, BPF_ANY);
        metrics_write = bpf_map_lookup_elem(&io_metrics_write, &key);
        if (!metrics_write) {
            return 0;
        }
    }
    bpf_printk("write_done_pid:%lld\n", pid);
    u64 *start_time = bpf_map_lookup_elem(&link_end, &pid);
    if (start_time) {
        u64 latency = timestamp - *start_time;
        __sync_fetch_and_add(&metrics_write->write_count, 1);
        __sync_fetch_and_add(&metrics_write->write_size, res_count);
        __sync_fetch_and_add(&metrics_write->write_lat, latency);
        bpf_printk("pid:%lld, write_count: %lld, write_size: %lld, write_lat: %lld\n", pid, metrics_write->write_count, metrics_write->write_size, metrics_write->write_lat);
    }
    return 0;
}