// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Wenbo Zhang
#include <vmlinux.h>
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
	__type(value, u64);
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
    bpf_map_lookup_or_try_init(&link_begin, &key, &timestamp);
    return 0;
}

SEC("tracepoint/nfs/nfs_initiate_write")
int handle_nfs_write(void *ctx){
    u64 key = bpf_get_current_pid_tgid() >> 32;
    u64 timestamp = bpf_ktime_get_ns();
    bpf_map_lookup_or_try_init(&link_begin, &key, &timestamp);
    return 0;
}

SEC("tracepoint/sunrpc/rpc_task_begin")
int handle_rpc_task_begin(struct trace_event_raw_rpc_task_begin *ctx){
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    u64 timestamp = bpf_ktime_get_ns();
    void *val = bpf_map_lookup_elem(&link_begin, &pid);
    if(val){
        u64 task_id = ctx->task_id;
        u64 start_time = *((u64 *)val);
        bpf_map_lookup_or_try_init(&waiting_rpc, &task_id, &start_time);
    }
    return 0;
}

SEC("tracepoint/sunrpc/rpc_task_end")
int handle_rpc_task_end(struct trace_event_raw_rpc_task_end *ctx){
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    u64 timestamp = bpf_ktime_get_ns();
    u64 task_id = ctx->task_id;
    void *val = bpf_map_lookup_elem(&waiting_rpc, &task_id);
    if(val){
        u64 start_time = *((u64 *)val);
        bpf_map_lookup_or_try_init(&link_end, &pid, &start_time);
    }
    return 0;
}

SEC("tracepoint/nfs/nfs_readpage_done")
int handle_nfs_readpage_done(struct trace_event_raw_nfs_readpage_done *ctx){
    // 获取当前时间戳
    u64 timestamp = bpf_ktime_get_ns();

    // 获取文件 inode 号和设备号作为键
    struct io_metrics_key key = {
        .fileid = ctx->fileid,
        .dev = ctx->dev,
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
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    // 获取请求的开始时间戳
    u64 *start_time = bpf_map_lookup_elem(&link_end, &pid);
    if (start_time) {
        // 计算延迟
        u64 latency = timestamp - *start_time;

        // 更新指标数据
        __sync_fetch_and_add(&metrics_read->read_count, 1);
        __sync_fetch_and_add(&metrics_read->read_size, ctx->res_count);
        __sync_fetch_and_add(&metrics_read->read_lat, latency);
        bpf_printk("read_count: %lld, read_size: %lld, read_lat: %lld\n", metrics_read->read_count, metrics_read->read_size, metrics_read->read_lat);
    }
    return 0;
}

SEC("tracepoint/nfs/nfs_writeback_done")
int handle_nfs_writeback_done(struct trace_event_raw_nfs_writeback_done *ctx){
    u64 timestamp = bpf_ktime_get_ns();
    struct io_metrics_key key = {
        .fileid = ctx->fileid,
        .dev = ctx->dev,
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
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *start_time = bpf_map_lookup_elem(&link_end, &pid);
    if (start_time) {
        u64 latency = timestamp - *start_time;
        __sync_fetch_and_add(&metrics_write->write_count, 1);
        __sync_fetch_and_add(&metrics_write->write_size, ctx->res_count);
        __sync_fetch_and_add(&metrics_write->write_lat, latency);
        bpf_printk("write_count: %lld, write_size: %lld, write_lat: %lld\n", metrics_write->write_count, metrics_write->write_size, metrics_write->write_lat);
    }
    return 0;
}