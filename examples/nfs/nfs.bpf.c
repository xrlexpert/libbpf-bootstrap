// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "maps.bpf.h"
#define MAX_ENTRIES	10240

/// @sample {"interval": 1000, "type" : "log2_hist"}
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, u64);
}link_begin SEC(".maps");

SEC("tracepoint/nfs/nfs_initiate_read")
int handle_nfs_read(struct trace_event_raw_nfs_read *ctx){
    u64 key = bpf_get_current_pid_tgid() >> 32;
    u64 timestamp = bpf_ktime_get_ns();
    bpf_map_lookup_or_try_init(&link_begin, &key, &timestamp);
    return 0;
}

