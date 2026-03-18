// +build ignore

#ifndef __LOGIC_H
#define __LOGIC_H

#include "maps.h"
#include "siphash.h"

static __always_inline int is_replay(__u8 nonce[24]) {
  __u8 *exists = bpf_map_lookup_elem(&seen_nonces, &nonce);
  if (exists)
    return 1;
  __u8 val = 1;
  bpf_map_update_elem(&seen_nonces, &nonce, &val, BPF_ANY);
  return 0;
}

static __always_inline int is_whitelisted(__u32 src_ip) {
  __u64 *expiry = bpf_map_lookup_elem(&whitelist_lru, &src_ip);
  if (expiry) {
    if (bpf_ktime_get_ns() < *expiry)
      return 1;
    bpf_map_delete_elem(&whitelist_lru, &src_ip);
  }
  return 0;
}

static __always_inline int check_conntrack(struct xdp_md *ctx,
                                           struct iphdr *iph, __u16 sport,
                                           __u16 dport) {
  struct bpf_sock_tuple tuple = {};
  tuple.ipv4.saddr = iph->saddr;
  tuple.ipv4.daddr = iph->daddr;
  tuple.ipv4.sport = sport;
  tuple.ipv4.dport = dport;

  struct bpf_ct_opts opts = {
      .l4proto = iph->protocol,
      .netns_id = BPF_F_CURRENT_NETNS,
  };

  struct nf_conn *ct =
      bpf_xdp_ct_lookup(ctx, &tuple, sizeof(tuple.ipv4), &opts, sizeof(opts));
  if (ct) {
    bpf_ct_release(ct);
    if (opts.dir == 1)
      return 1;
  }
  return 0;
}

static __always_inline int handle_spa(struct xdp_md *ctx, struct iphdr *iph,
                                      void *data_end) {
  struct udphdr *udph = (void *)(iph + 1);
  if ((void *)(udph + 1) > data_end)
    return XDP_DROP;
  if (udph->dest != bpf_htons(SPA_PORT))
    return XDP_DROP;

  struct spa_packet *spa = (void *)(udph + 1);
  if ((void *)(spa + 1) > data_end)
    return XDP_DROP;

  if (is_replay(spa->nonce))
    return XDP_DROP;

  __u64 calculated_mac = siphash_24b(&spa->nonce, SIPHASH_KEYS);
  if (spa->siphash_mac != calculated_mac)
    return XDP_DROP;

  struct spa_packet *ring_data =
      bpf_ringbuf_reserve(&spa_ringbuf, sizeof(struct spa_packet), 0);
  if (!ring_data)
    return XDP_DROP;

  __builtin_memcpy(ring_data, spa, sizeof(struct spa_packet));
  bpf_ringbuf_submit(ring_data, 0);

  return XDP_DROP;
}

#endif