// +build ignore

#pragma once

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#define ROTL64(x, b) (__u64)(((x) << (b)) | ((x) >> (64 - (b))))

#define SIPROUND                                                               \
  do {                                                                         \
    v0 += v1;                                                                  \
    v1 = ROTL64(v1, 13);                                                       \
    v1 ^= v0;                                                                  \
    v0 = ROTL64(v0, 32);                                                       \
    v2 += v3;                                                                  \
    v3 = ROTL64(v3, 16);                                                       \
    v3 ^= v2;                                                                  \
    v0 += v3;                                                                  \
    v3 = ROTL64(v3, 21);                                                       \
    v3 ^= v0;                                                                  \
    v2 += v1;                                                                  \
    v1 = ROTL64(v1, 17);                                                       \
    v1 ^= v2;                                                                  \
    v2 = ROTL64(v2, 32);                                                       \
  } while (0)

static inline __attribute__((always_inline)) unsigned long long
siphash_24b(const void *src, const volatile __u8 *keys) {
  __u64 k0 = *(__u64 *)(keys);
  __u64 k1 = *(__u64 *)(keys + 8);
  bpf_printk("DEBUG C: Key0: %llx, Key1: %llx", k0, k1);
  __u64 v0 = 0x736f6d6570736575ULL ^ k0;
  __u64 v1 = 0x646f72616e646f6dULL ^ k1;
  __u64 v2 = 0x6c7967656e657261ULL ^ k0;
  __u64 v3 = 0x7465646279746573ULL ^ k1;
  __u64 m[3];
  __builtin_memcpy(m, src, 24);
  bpf_printk("DEBUG C: m0: %llx, m1: %llx, m2: %llx", m[0], m[1], m[2]);
  bpf_printk("DEBUG C: v0: %llx, v1: %llx, v2: %llx, v3: %llx", v0, v1, v2, v3);

  v3 ^= m[0];
  SIPROUND;
  SIPROUND;
  v0 ^= m[0];

  v3 ^= m[1];
  SIPROUND;
  SIPROUND;
  v0 ^= m[1];

  v3 ^= m[2];
  SIPROUND;
  SIPROUND;
  v0 ^= m[2];

  __u64 b = 24ULL << 56;
  v3 ^= b;
  SIPROUND;
  SIPROUND;
  v0 ^= b;

  v2 ^= 0xff;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  SIPROUND;

  return v0 ^ v1 ^ v2 ^ v3;
}