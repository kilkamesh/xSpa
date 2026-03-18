// +build ignore

#ifndef __MAPS_H
#define __MAPS_H

#include "common.h"

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 4096);
  __type(key, __u32);
  __type(value, __u64);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} whitelist_lru SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 10000);
  __type(key, __u8);
  __type(value, __u8);
} seen_nonces SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} spa_ringbuf SEC(".maps");

#endif