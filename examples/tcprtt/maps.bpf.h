// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Wenbo Zhang

#ifndef __MAPS_BPF_H
#define __MAPS_BPF_H

#include<bpf/bpf_helpers.h>
#include<asm-generic/errno.h>

static __always_inline void *
bpf_map_lookup_or_try_init(void *map, const void *key, const void *value){
    void *val;
    long err;
    val = bpf_map_lookup_elem(map, key);
    if(val){
        return val;
    }
    //try to insert the key-value pair into the map
    err = bpf_map_update_elem(map, key, value, BPF_NOEXIST);
    //if the key already exists or the map is full, return 0
    if(err && err != -EEXIST){
        return 0;
    }
    //if the key is newly inserted, return the value
    return bpf_map_lookup_elem(map, key);
}

#endif /* __MAPS_BPF_H */
