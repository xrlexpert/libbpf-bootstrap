// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "tcprtt.h"
#include "bits.bpf.h"
#include "maps.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile bool targ_laddr_hist = false; // 是否记录源IP地址的RTT
const volatile bool targ_raddr_hist = false; // 是否记录目标IP地址的RTT
const volatile bool targ_show_ext = false; // 是否显示扩展信息
const volatile __u16 targ_sport = 0; // 源端口号过滤（0表示所有端口号）
const volatile __u16 targ_dport = 0; // 目标端口号过滤（0表示所有端口号）
const volatile __u32 targ_saddr = 0;  // 源IP地址过滤（0表示所有地址）
const volatile __u32 targ_daddr = 0; // 目标IP地址过滤（0表示所有地址）
const volatile bool targ_ms = false; // 是否显示毫秒单位

#define MAX_ENTRIES	10240

/// @sample {"interval": 1000, "type" : "log2_hist"}
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, struct hist);
} hists SEC(".maps");

static struct hist zero;

SEC("fentry/tcp_rcv_established")
int BPF_PROG(tcp_rcv, struct sock *sk)
{
	const struct inet_sock *inet = (struct inet_sock *)(sk);
	struct tcp_sock *ts;
	struct hist *histp;
	u64 key, slot;
	u32 srtt;

	if (targ_sport && targ_sport != inet->inet_sport) // 如果设置了源端口号过滤，并且源端口号不匹配，则返回0
		return 0;
	if (targ_dport && targ_dport != sk->__sk_common.skc_dport) // 如果设置了目标端口号过滤，并且目标端口号不匹配，则返回0
		return 0;
	if (targ_saddr && targ_saddr != inet->inet_saddr) // 如果设置了源IP地址过滤，并且源IP地址不匹配，则返回0
		return 0;
	if (targ_daddr && targ_daddr != sk->__sk_common.skc_daddr) // 如果设置了目标IP地址过滤，并且目标IP地址不匹配，则返回0
		return 0;

	if (targ_laddr_hist)
		key = inet->inet_saddr;
	else if (targ_raddr_hist)
		key = inet->sk.__sk_common.skc_daddr;
	else
		key = 0;
	histp = bpf_map_lookup_or_try_init(&hists, &key, &zero);
	if (!histp)
		return 0;
	ts = (struct tcp_sock *)(sk);
	srtt = BPF_CORE_READ(ts, srtt_us) >> 3; // get the smoothed RTT value, however the kernel stores the 8 times of the actual value
	if (targ_ms)
		srtt /= 1000U;
	slot = log2l(srtt);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&histp->slots[slot], 1);
	if (targ_show_ext) {
		__sync_fetch_and_add(&histp->latency, srtt);
		__sync_fetch_and_add(&histp->cnt, 1);
	}
	return 0;
}